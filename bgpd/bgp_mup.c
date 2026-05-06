// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */

#include "linklist.h"
#include "prefix.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_attr_srv6.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_mup.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_zebra.h"
#include "lib/srv6.h"
#include "lib/zclient.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_ISD, "BGP MUP ISD entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_DSD, "BGP MUP DSD entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_ORIGIN, "BGP MUP origin");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_PENDING, "BGP MUP pending originate");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_LIST, "BGP MUP list head");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_STR, "BGP MUP string");

/* Initialise a struct prefix_rd from the 8-octet RD wire bytes
 * embedded in the MUP NLRI / mup_prefix.  RD is opaque to BGP-MUP
 * (kept inside mup_prefix), so the on-the-wire representation is the
 * raw 8 bytes.
 */
static inline void bgp_mup_prd_from_bytes(struct prefix_rd *prd, const uint8_t *bytes)
{
	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;
	memcpy(prd->val, bytes, 8);
}

/*
 * Compute the on-wire size of a single BGP-MUP NLRI for a given prefix
 * (used by bgp_packet_mpattr_prefix_size when building MP_REACH).
 */
size_t bgp_mup_prefix_size(const struct prefix *p)
{
	const struct prefix_mup *mp = (const struct prefix_mup *)p;

	/* Architecture Type(1) + Route Type(2) + Length(1) + Length octets. */
	return 4 + mp->prefix.length;
}

/*
 * Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream
 * (draft-ietf-bess-mup-safi section 3.1 onwards).
 */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	const struct prefix_mup *pm = (const struct prefix_mup *)p;
	const struct mup_prefix *mp = &pm->prefix;
	uint8_t prefix_octets;
	uint8_t addr_octets;
	uint8_t total_len = 0;
	size_t len_pos;

	/* prd is unused: SAFI_MUP keeps a flat RIB and stores the Route
	 * Distinguisher inside struct mup_prefix (the wire format embeds
	 * RD in each route type's payload).  Only the dest's own prefix
	 * is consulted here.
	 */
	(void)prd;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	/* Architecture Type (1) + Route Type (2) + Length (1). */
	stream_putc(s, mp->arch_type);
	stream_putw(s, mp->route_type);

	/* Reserve a byte for Length and remember its position so we can
	 * patch it after the route-type-specific data is serialized.
	 */
	len_pos = stream_get_endp(s);
	stream_putc(s, 0);

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		/* RD(8) + Prefix Length(1) + Prefix(variable). */
		prefix_octets = PSIZE(mp->isd_route.ip_prefix_length);
		stream_put(s, mp->rd, 8);
		stream_putc(s, mp->isd_route.ip_prefix_length);
		stream_put(s, &mp->isd_route.ip.ip.addr, prefix_octets);
		total_len = 8 + 1 + prefix_octets;
		break;

	case BGP_MUP_DSD_ROUTE:
		/* RD(8) + Address(4 or 16). */
		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		stream_put(s, mp->rd, 8);
		stream_put(s, &mp->dsd_route.ip.ip.addr, addr_octets);
		total_len = 8 + addr_octets;
		break;

	case BGP_MUP_T1ST_ROUTE: {
		/* RD(8) + PrefixLength(1) + Prefix(var) + TEID(4) + QFI(1)
		 * + EndpointAddrLen(1) + EndpointAddr(var)
		 * + SourceAddrLen(1) [+ SourceAddr(var)].
		 */
		const struct mup_t1st_3gpp_5g *e = &mp->t1st_route.t1st_3gpp_5g;
		uint8_t ep_octets;
		uint8_t src_octets;

		prefix_octets = PSIZE(mp->t1st_route.ip_prefix_length);
		ep_octets = e->endpoint_address_length / 8;
		src_octets = e->source_address_length / 8;

		stream_put(s, mp->rd, 8);
		stream_putc(s, mp->t1st_route.ip_prefix_length);
		stream_put(s, &mp->t1st_route.ip.ip.addr, prefix_octets);
		stream_putl(s, e->teid);
		stream_putc(s, e->qfi);
		stream_putc(s, e->endpoint_address_length);
		stream_put(s, &e->endpoint_address.ip.addr, ep_octets);
		stream_putc(s, e->source_address_length);
		if (src_octets)
			stream_put(s, &e->source_address.ip.addr, src_octets);

		total_len = 8 + 1 + prefix_octets + 4 + 1 + 1 + ep_octets + 1 + src_octets;
		break;
	}

	case BGP_MUP_T2ST_ROUTE: {
		/* RD(8) + EndpointAddrLen(1) + EndpointAddr(4 or 16)
		 * + TEID(0..4 packed in trailing bits).
		 */
		uint8_t teid_bits;
		uint8_t teid_octets;
		uint32_t teid_be;

		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		teid_bits = mp->t2st_route.endpoint_address_length - (addr_octets * 8);
		teid_octets = (teid_bits + 7) / 8;
		teid_be = htonl(mp->t2st_route.teid);

		stream_put(s, mp->rd, 8);
		stream_putc(s, mp->t2st_route.endpoint_address_length);
		stream_put(s, &mp->t2st_route.endpoint_address.ip.addr, addr_octets);
		if (teid_octets)
			stream_put(s, &teid_be, teid_octets);

		total_len = 8 + 1 + addr_octets + teid_octets;
		break;
	}

	default:
		break;
	}

	/* Patch Length field. */
	stream_putc_at(s, len_pos, total_len);
}

/* ----------------------------------------------------------------------
 * NLRI parsing (draft-ietf-bess-mup-safi section 3.1.x).
 *
 * On parse error we emit EC_BGP_MUP_ROUTE_INVALID and treat the route as
 * withdraw per RFC 7606.
 * ---------------------------------------------------------------------- */

static int bgp_mup_process_isd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				     uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t prefix_len;
	uint8_t prefix_octets;

	if (psize < 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP ISD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	bgp_mup_prd_from_bytes(&prd, pfx);

	prefix_len = pfx[8];
	if ((afi == AFI_IP && prefix_len > 32) || (afi == AFI_IP6 && prefix_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI bad prefix length %u", peer->bgp->vrf_id,
			 peer->host, prefix_len);
		return -1;
	}

	prefix_octets = PSIZE(prefix_len);
	if (psize - 9 != prefix_octets) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI prefix length mismatch", peer->bgp->vrf_id,
			 peer->host);
		return -1;
	}

	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_ISD_ROUTE;
	p.prefix.length = psize;
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.isd_route.ip_prefix_length = prefix_len;
	p.prefix.isd_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.isd_route.ip.ip.addr, pfx + 9, prefix_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_dsd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				     uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;

	if ((afi == AFI_IP && psize != 12) || (afi == AFI_IP6 && psize != 24)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP DSD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	bgp_mup_prd_from_bytes(&prd, pfx);

	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_DSD_ROUTE;
	p.prefix.length = psize;
	memcpy(p.prefix.rd, prd.val, 8);

	if (afi == AFI_IP) {
		addr_octets = IPV4_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V4;
	} else {
		addr_octets = IPV6_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V6;
	}
	memcpy(&p.prefix.dsd_route.ip.ip.addr, pfx + 8, addr_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t1st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	struct mup_t1st_3gpp_5g *ext;
	uint8_t prefix_len;
	uint8_t prefix_octets;
	uint8_t ep_len, src_len;
	uint8_t ep_octets, src_octets;
	int off;

	/* Minimum: RD(8) + PrefixLen(1) + TEID(4) + QFI(1) + EALen(1)
	 * + SALen(1) = 16, plus prefix and endpoint addr bytes.
	 */
	if (psize < 16) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP T1ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	bgp_mup_prd_from_bytes(&prd, pfx);
	off = 8;

	prefix_len = pfx[off++];
	if ((afi == AFI_IP && prefix_len > 32) || (afi == AFI_IP6 && prefix_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI bad prefix length %u", peer->bgp->vrf_id,
			 peer->host, prefix_len);
		return -1;
	}
	prefix_octets = PSIZE(prefix_len);

	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T1ST_ROUTE;
	p.prefix.length = psize;
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.t1st_route.ip_prefix_length = prefix_len;
	p.prefix.t1st_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;

	if (off + prefix_octets + 4 + 1 + 1 > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP T1ST NLRI truncated",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	memcpy(&p.prefix.t1st_route.ip.ip.addr, pfx + off, prefix_octets);
	off += prefix_octets;

	ext = &p.prefix.t1st_route.t1st_3gpp_5g;
	memcpy(&ext->teid, pfx + off, 4);
	ext->teid = ntohl(ext->teid);
	off += 4;
	ext->qfi = pfx[off++];
	ep_len = pfx[off++];
	if (ep_len != 32 && ep_len != 128) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI bad endpoint length %u", peer->bgp->vrf_id,
			 peer->host, ep_len);
		return -1;
	}
	ext->endpoint_address_length = ep_len;
	ep_octets = ep_len / 8;
	if (off + ep_octets + 1 > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI truncated endpoint", peer->bgp->vrf_id,
			 peer->host);
		return -1;
	}
	ext->endpoint_address.ipa_type = (ep_len == 32) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ext->endpoint_address.ip.addr, pfx + off, ep_octets);
	off += ep_octets;

	src_len = pfx[off++];
	if (src_len != 0 && src_len != 32 && src_len != 128) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI bad source length %u", peer->bgp->vrf_id,
			 peer->host, src_len);
		return -1;
	}
	ext->source_address_length = src_len;
	if (src_len) {
		src_octets = src_len / 8;
		if (off + src_octets > psize) {
			flog_err(EC_BGP_MUP_ROUTE_INVALID,
				 "%u:%s - Rx BGP-MUP T1ST NLRI truncated source",
				 peer->bgp->vrf_id, peer->host);
			return -1;
		}
		ext->source_address.ipa_type = (src_len == 32) ? IPADDR_V4 : IPADDR_V6;
		memcpy(&ext->source_address.ip.addr, pfx + off, src_octets);
	}

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t2st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;
	uint8_t teid_bits;
	uint8_t teid_octets;
	uint32_t teid_be = 0;
	uint8_t ea_len;

	if (psize < 13) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP T2ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	bgp_mup_prd_from_bytes(&prd, pfx);

	ea_len = pfx[8];
	if ((afi == AFI_IP && ea_len > 64) || (afi == AFI_IP6 && ea_len > 160)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI bad endpoint length %u", peer->bgp->vrf_id,
			 peer->host, ea_len);
		return -1;
	}

	addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	if (9 + addr_octets > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI truncated endpoint", peer->bgp->vrf_id,
			 peer->host);
		return -1;
	}

	teid_bits = (ea_len > addr_octets * 8) ? ea_len - addr_octets * 8 : 0;
	teid_octets = (teid_bits + 7) / 8;
	if (9 + addr_octets + teid_octets > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID, "%u:%s - Rx BGP-MUP T2ST NLRI truncated TEID",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;
	p.prefix.length = psize;
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.t2st_route.endpoint_address_length = ea_len;
	p.prefix.t2st_route.endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.t2st_route.endpoint_address.ip.addr, pfx + 9, addr_octets);
	if (teid_octets) {
		memcpy(&teid_be, pfx + 9 + addr_octets, teid_octets);
		p.prefix.t2st_route.teid = ntohl(teid_be);
	}

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

/* ----------------------------------------------------------------------
 * ISD / DSD discovery cache (draft-ietf-bess-mup-safi Section 3.3.3 / Section 3.3.6).
 *
 * Both ISD and DSD routes carry a Prefix-SID L3 Service TLV whose SID +
 * SID-Structure is consumed by Type 1/2 ST processing on the receiver
 * side.  Per the draft:
 *
 *   - T1ST processing (Section 3.3.9) looks up an ISD whose IP prefix covers
 *     the T1ST's Tunnel Endpoint Address, extracts locator+function
 *     from the ISD's Prefix-SID, and synthesizes the End.M.GTP*.E
 *     forwarding SID per RFC 9433 Section 6.6.
 *   - T2ST processing (Section 3.3.12) reads the MUP Extended Community's
 *     Direct-Type Segment Identifier from the T2ST attributes, looks
 *     up a DSD with a matching Segment Identifier, and uses the DSD's
 *     Prefix-SID as the SRv6 next-hop for H.M.GTP4.D.
 *
 * To keep these resolutions O(N_ISD) / O(N_DSD) and decoupled from
 * arrival order, we cache each accepted ISD/DSD in per-bgp lists.
 * ---------------------------------------------------------------------- */

struct bgp_mup_isd_entry {
	struct bgp_mup_isd_list_item item;
	afi_t afi;
	struct prefix_rd prd;
	struct prefix prefix; /* Endpoint prefix from ISD NLRI */
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint16_t behavior; /* End.M.GTP4.E or End.M.GTP6.E */
};
DECLARE_LIST(bgp_mup_isd_list, struct bgp_mup_isd_entry, item);

struct bgp_mup_dsd_entry {
	struct bgp_mup_dsd_list_item item;
	afi_t afi;
	struct prefix_rd prd;
	struct ipaddr endpoint; /* Originating PE address (DSD NLRI) */
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint16_t behavior;	    /* End.DT4 / End.DT6 */
	bool has_segment_id;
	uint64_t segment_id; /* MUP-EC Direct-Type Segment Identifier (48 bits) */
};
DECLARE_LIST(bgp_mup_dsd_list, struct bgp_mup_dsd_entry, item);

/* Persistent record of one operator-configured `segment` line.  Lives on
 * the per-vrf bgp instance under whose `address-family ipv[46] mup`
 * block the `segment ...` was typed.  Survives SID alloc/release so
 * `show running-config` can re-emit, and powers the RT-match install
 * filter (bgp_mup_match_install_vrf).
 */
struct bgp_mup_origin {
	struct bgp_mup_origin_list_item item;
	uint16_t route_type; /* BGP_MUP_ISD_ROUTE or BGP_MUP_DSD_ROUTE */
	afi_t afi;
	struct prefix_rd prd;
	struct prefix isd_prefix;   /* ISD only */
	struct ipaddr dsd_endpoint; /* DSD only */
	uint16_t dsd_behavior;	    /* DSD only */
	bool has_explicit_sid;
	struct in6_addr explicit_sid; /* iff has_explicit_sid */
	char *rt_str;
	char *mup_str; /* DSD only */
	/* In-memory marker: this origin already has its SID assigned by
	 * zebra (or via `sid explicit`) and the local install has been
	 * issued.  Reset on bgpd restart, so the locator-arrival hook
	 * (bgp_mup_replay_origins) re-runs `segment` lines that landed
	 * before chunks were ready.  Same posture as L3VPN's
	 * vpn_leak_zebra_vrf_sid_update_per_vrf re-running on every
	 * locator postchange.
	 */
	bool sid_ready;
};
DECLARE_LIST(bgp_mup_origin_list, struct bgp_mup_origin, item);

static struct bgp_mup_isd_list_head *bgp_mup_get_isd_cache(struct bgp *bgp)
{
	if (!bgp->mup_isd_cache) {
		bgp->mup_isd_cache = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_isd_cache));
		bgp_mup_isd_list_init(bgp->mup_isd_cache);
	}
	return bgp->mup_isd_cache;
}

static struct bgp_mup_dsd_list_head *bgp_mup_get_dsd_cache(struct bgp *bgp)
{
	if (!bgp->mup_dsd_cache) {
		bgp->mup_dsd_cache = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_dsd_cache));
		bgp_mup_dsd_list_init(bgp->mup_dsd_cache);
	}
	return bgp->mup_dsd_cache;
}

/* Build a MUP Extended Community of subtype Direct-Type Segment
 * Identifier (draft-ietf-bess-mup-safi §3.2) from an "ASN:NN"
 * operator string.  Returns the ecommunity (caller frees) on success
 * or NULL on parse failure.
 */
static struct ecommunity *bgp_mup_build_mup_ec(const char *mup_str)
{
	uint32_t mup_as = 0, mup_val = 0;
	struct ecommunity_val ev = { 0 };
	struct ecommunity *ec;

	if (sscanf(mup_str, "%u:%u", &mup_as, &mup_val) != 2)
		return NULL;
	ev.val[0] = ECOMMUNITY_ENCODE_MUP;
	ev.val[1] = ECOMMUNITY_MUP_SUBTYPE_DIRECT_SEG_ID;
	ev.val[2] = (mup_as >> 8) & 0xff;
	ev.val[3] = mup_as & 0xff;
	ev.val[4] = (mup_val >> 24) & 0xff;
	ev.val[5] = (mup_val >> 16) & 0xff;
	ev.val[6] = (mup_val >> 8) & 0xff;
	ev.val[7] = mup_val & 0xff;
	ec = ecommunity_new();
	ecommunity_add_val(ec, &ev, false, false);
	return ec;
}

/* Extract the MUP-EC Direct-Type Segment Identifier (sub-type 0x00).
 * Returns true and writes a 48-bit value packed into the low bits of
 * @out (high uint16 << 32 | low uint32) when found.
 */
static bool bgp_mup_get_direct_seg_id(const struct attr *attr, uint64_t *out)
{
	struct ecommunity *ecom;
	uint32_t i;

	if (!attr)
		return false;
	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom)
		return false;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *p = ecom->val + i * ecom->unit_size;
		uint16_t hi;
		uint32_t lo;

		if (p[0] != ECOMMUNITY_ENCODE_MUP)
			continue;
		if (p[1] != ECOMMUNITY_MUP_SUBTYPE_DIRECT_SEG_ID)
			continue;
		memcpy(&hi, p + 2, 2);
		memcpy(&lo, p + 4, 4);
		*out = ((uint64_t)ntohs(hi) << 32) | (uint64_t)ntohl(lo);
		return true;
	}
	return false;
}

static bool bgp_mup_get_sid_structure(const struct attr *attr, struct in6_addr *sid_out,
				      uint8_t *block_out, uint8_t *node_out, uint8_t *func_out,
				      uint8_t *arg_out, uint16_t *behavior_out)
{
	const struct bgp_attr_srv6_l3service *l3 = attr ? attr->srv6_l3service : NULL;

	if (!l3 || sid_zero_ipv6(&l3->sid))
		return false;
	*sid_out = l3->sid;
	*block_out = l3->loc_block_len;
	*node_out = l3->loc_node_len;
	*func_out = l3->func_len;
	*arg_out = l3->arg_len;
	*behavior_out = l3->endpoint_behavior;
	return true;
}

static bool bgp_mup_isd_match_key(const struct bgp_mup_isd_entry *e, afi_t afi,
				  const struct prefix_rd *prd, const struct prefix *prefix)
{
	if (e->afi != afi)
		return false;
	if (memcmp(e->prd.val, prd->val, sizeof(e->prd.val)) != 0)
		return false;
	return prefix_same(&e->prefix, prefix);
}

static struct bgp_mup_isd_entry *bgp_mup_isd_find(struct bgp *bgp, afi_t afi,
						  const struct prefix_rd *prd,
						  const struct prefix *prefix)
{
	struct bgp_mup_isd_entry *e;

	if (!bgp->mup_isd_cache)
		return NULL;
	frr_each (bgp_mup_isd_list, bgp->mup_isd_cache, e) {
		if (bgp_mup_isd_match_key(e, afi, prd, prefix))
			return e;
	}
	return NULL;
}

/* Longest-prefix-match an ISD covering the given endpoint address.
 * Returns the most specific match across all RDs; per the draft the
 * receiving PE has already imported routes by RT, so all entries in the
 * cache are eligible.
 */
static struct bgp_mup_isd_entry *bgp_mup_isd_lookup(struct bgp *bgp, afi_t afi,
						    const struct ipaddr *endpoint)
{
	struct bgp_mup_isd_entry *e, *best = NULL;
	struct prefix needle = {};

	if (!bgp->mup_isd_cache)
		return NULL;

	if (afi == AFI_IP) {
		needle.family = AF_INET;
		needle.prefixlen = IPV4_MAX_BITLEN;
		needle.u.prefix4 = endpoint->ipaddr_v4;
	} else {
		needle.family = AF_INET6;
		needle.prefixlen = IPV6_MAX_BITLEN;
		needle.u.prefix6 = endpoint->ipaddr_v6;
	}

	frr_each (bgp_mup_isd_list, bgp->mup_isd_cache, e) {
		if (e->afi != afi)
			continue;
		if (!prefix_match(&e->prefix, &needle))
			continue;
		if (!best || e->prefix.prefixlen > best->prefix.prefixlen)
			best = e;
	}
	return best;
}

static struct bgp_mup_dsd_entry *bgp_mup_dsd_find_key(struct bgp *bgp, afi_t afi,
						      const struct prefix_rd *prd,
						      const struct ipaddr *endpoint)
{
	struct bgp_mup_dsd_entry *e;

	if (!bgp->mup_dsd_cache)
		return NULL;
	frr_each (bgp_mup_dsd_list, bgp->mup_dsd_cache, e) {
		if (e->afi != afi)
			continue;
		if (memcmp(e->prd.val, prd->val, sizeof(e->prd.val)) != 0)
			continue;
		if (!ipaddr_is_same(&e->endpoint, endpoint))
			continue;
		return e;
	}
	return NULL;
}

/* Lookup a DSD by MUP-EC Direct-Type Segment Identifier. */
static struct bgp_mup_dsd_entry *bgp_mup_dsd_lookup(struct bgp *bgp, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry *e;

	if (!bgp->mup_dsd_cache)
		return NULL;
	frr_each (bgp_mup_dsd_list, bgp->mup_dsd_cache, e) {
		if (e->has_segment_id && e->segment_id == segment_id)
			return e;
	}
	return NULL;
}

/* Walk the per-AFI MUP RIB and re-trigger zebra announce / withdraw for
 * selected T1ST/T2ST paths.  Used after an ISD/DSD cache mutation so
 * deferred resolutions complete (or invalidate) without another
 * BGP UPDATE.
 */
static void bgp_mup_reannounce_st_routes(struct bgp *bgp, afi_t afi);

static void bgp_mup_isd_cache_upsert(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct prefix *prefix, const struct in6_addr *sid,
				     uint8_t block, uint8_t node, uint8_t func, uint8_t arg,
				     uint16_t behavior)
{
	struct bgp_mup_isd_entry *e = bgp_mup_isd_find(bgp, afi, prd, prefix);

	if (!e) {
		e = XCALLOC(MTYPE_BGP_MUP_ISD, sizeof(*e));
		e->afi = afi;
		e->prd = *prd;
		e->prefix = *prefix;
		bgp_mup_isd_list_add_tail(bgp_mup_get_isd_cache(bgp), e);
	}
	e->sid = *sid;
	e->loc_block_len = block;
	e->loc_node_len = node;
	e->func_len = func;
	e->arg_len = arg;
	e->behavior = behavior;
	bgp_mup_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_isd_cache_remove(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct prefix *prefix)
{
	struct bgp_mup_isd_entry *e = bgp_mup_isd_find(bgp, afi, prd, prefix);

	if (!e)
		return;
	bgp_mup_isd_list_del(bgp->mup_isd_cache, e);
	XFREE(MTYPE_BGP_MUP_ISD, e);
	bgp_mup_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_dsd_cache_upsert(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct ipaddr *endpoint, const struct in6_addr *sid,
				     uint8_t block, uint8_t node, uint8_t func, uint8_t arg,
				     uint16_t behavior, bool has_segment_id, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry *e = bgp_mup_dsd_find_key(bgp, afi, prd, endpoint);

	if (!e) {
		e = XCALLOC(MTYPE_BGP_MUP_DSD, sizeof(*e));
		e->afi = afi;
		e->prd = *prd;
		e->endpoint = *endpoint;
		bgp_mup_dsd_list_add_tail(bgp_mup_get_dsd_cache(bgp), e);
	}
	e->sid = *sid;
	e->loc_block_len = block;
	e->loc_node_len = node;
	e->func_len = func;
	e->arg_len = arg;
	e->behavior = behavior;
	e->has_segment_id = has_segment_id;
	e->segment_id = segment_id;
	bgp_mup_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_dsd_cache_remove(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct ipaddr *endpoint)
{
	struct bgp_mup_dsd_entry *e = bgp_mup_dsd_find_key(bgp, afi, prd, endpoint);

	if (!e)
		return;
	bgp_mup_dsd_list_del(bgp->mup_dsd_cache, e);
	XFREE(MTYPE_BGP_MUP_DSD, e);
	bgp_mup_reannounce_st_routes(bgp, afi);
}

void bgp_mup_caches_free(struct bgp *bgp)
{
	struct bgp_mup_isd_entry *isd;
	struct bgp_mup_dsd_entry *dsd;

	if (bgp->mup_isd_cache) {
		while ((isd = bgp_mup_isd_list_pop(bgp->mup_isd_cache)))
			XFREE(MTYPE_BGP_MUP_ISD, isd);
		bgp_mup_isd_list_fini(bgp->mup_isd_cache);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_isd_cache);
	}
	if (bgp->mup_dsd_cache) {
		while ((dsd = bgp_mup_dsd_list_pop(bgp->mup_dsd_cache)))
			XFREE(MTYPE_BGP_MUP_DSD, dsd);
		bgp_mup_dsd_list_fini(bgp->mup_dsd_cache);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_dsd_cache);
	}
}

/*
 * Translate a learned BGP-MUP route into a zapi route programming the
 * appropriate SRv6 Mobile User Plane state in the kernel.
 *
 *   - T1ST (DL ingress at MUP-PE per draft Section 3.3.9): install an IP route
 *           to the UE prefix whose nexthop is an SRv6 ENCAP
 *           (LWTUNNEL_ENCAP_SEG6) targeting an End.M.GTP*.E SID
 *           synthesized per RFC 9433 Section 6.6 from the matching ISD's
 *           locator + function + the T1ST's TEID/QFI/source.
 *   - T2ST (UL ingress at MUP-GW per draft Section 3.3.12): install an IP
 *           route to the GTP-U endpoint whose nexthop is a SEG6_LOCAL
 *           H.M.GTP4.D action with nh6 = the matching DSD's prefix-SID.
 *   - ISD / DSD discovery routes: cached locally to satisfy T1ST/T2ST
 *           lookups; no kernel state programmed directly.
 */

/* Find the local interface that owns a /N prefix covering the SID.  This
 * is the "SR locator interface" — typically a dummy device the operator
 * sets up to advertise the locator and to anchor seg6local installs (lo
 * doesn't work because the kernel rejects lo-OIF routes that overlap an
 * existing local route, which the locator's own /N entry is).
 *
 * Two cases:
 *
 *   - Local SID (this MUP-PE/GW originates the SID): an interface in the
 *     given vrf has a connected prefix that covers the SID.  Return it.
 *   - Remote SID (received via T1ST/T2ST resolution; the locator lives on
 *     a peer): no local interface covers the SID, but we still need an
 *     anchor for the seg6local route.  Fall back to any default-vrf
 *     interface that carries a non-link-local IPv6 connected — typically
 *     the SR underlay's egress veth.  Skipping `lo` matters because the
 *     post-action packet's vrf binding follows the route's `dev`, and
 *     using `lo` traps the new SRv6 packet in the input vrf.
 */
static struct interface *bgp_mup_locator_oif(vrf_id_t vrf_id, const struct in6_addr *sid)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;
	struct interface *fallback = NULL;
	struct connected *connected;

	if (!vrf)
		return NULL;
	FOR_ALL_INTERFACES (vrf, ifp) {
		bool has_global_v6 = false;

		if (ifp->ifindex == IFINDEX_INTERNAL)
			continue;
		frr_each (if_connected, ifp->connected, connected) {
			const struct prefix *p = connected->address;

			if (p->family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
				continue;
			has_global_v6 = true;
			if (p->prefixlen >= IPV6_MAX_BITLEN)
				continue;
			if (prefix_match(p, &(struct prefix){ .family = AF_INET6,
							      .prefixlen = IPV6_MAX_BITLEN,
							      .u.prefix6 = *sid }))
				return ifp;
		}
		/* Prefer the first non-loopback interface that carries any
		 * non-LL IPv6 — that's almost certainly an SR underlay-side
		 * veth, suitable as an anchor for a remote-locator SID's
		 * seg6local install.
		 */
		if (!fallback && has_global_v6 && !if_is_loopback(ifp))
			fallback = ifp;
	}
	return fallback;
}

/* Pick a local IPv6 source address for the new SRv6 outer when the
 * incoming T1ST has no Source Address.  Walk the BGP VRF and return the
 * first non-link-local IPv6 connected address.  If nothing matches the
 * caller must fail the install.
 */
static bool bgp_mup_local_v6_source(vrf_id_t vrf_id, struct in6_addr *out)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;
	struct connected *connected;

	if (!vrf)
		return false;
	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			const struct prefix *p = connected->address;

			if (p->family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
				continue;
			*out = p->u.prefix6;
			return true;
		}
	}
	return false;
}

/* Set @len bits of the IPv6 address starting at bit @offset to the high
 * @len bits of @value.  Used for SID synthesis (RFC 9433 Section 6.6) where v4
 * addresses and Args.Mob.Session are written into a locator+function
 * prefix at well-defined bit offsets.  Bit 0 is the MSB of byte 0.
 */
static void bgp_mup_sid_set_bits(struct in6_addr *sid, unsigned int offset, unsigned int len,
				 uint64_t value)
{
	unsigned int i;

	if (len == 0 || len > 64 || offset + len > IPV6_MAX_BITLEN)
		return;
	value <<= (64 - len);
	for (i = 0; i < len; i++) {
		unsigned int bit = offset + i;
		uint8_t mask = 0x80 >> (bit & 7);

		if (value & ((uint64_t)1 << 63))
			sid->s6_addr[bit >> 3] |= mask;
		else
			sid->s6_addr[bit >> 3] &= (uint8_t)~mask;
		value <<= 1;
	}
}

/* Compose Args.Mob.Session per RFC 9433 Section 6.1 Figure 8 layout:
 *   bits 0..5  : QFI (6 bits, MSB)
 *   bits 6..7  : R, U (1 bit each, both 0)
 *   bits 8..39 : TEID (32 bits, LSB)
 *
 * Returned value places the 40-bit field in the LOW 40 bits of the
 * uint64 (so that bgp_mup_sid_set_bits' final `value <<= 24` puts it
 * MSB-first in the SID's last 5 bytes), matching the kernel decoder
 * in net/ipv6/seg6_local.c::seg6_mobile_teid_from_args() (TEID at
 * SEG6_MOBILE_ARGS_TEID_SHIFT=24, QFI at SHIFT=58 of the
 * left-justified u64).
 */
static uint64_t bgp_mup_args_mob_session(uint32_t teid, uint8_t qfi)
{
	return ((uint64_t)(qfi & 0x3f) << 34) | (uint64_t)teid;
}

/* Synthesize the End.M.GTP*.E forwarding SID per RFC 9433 Section 6.6 from the
 * matched ISD's locator+function and the T1ST's TEID/QFI/endpoint.
 *
 * Layout (per RFC 9433 Figure 11 / Figure 13):
 *   End.M.GTP4.E SID = locator+function | IPv4 DA (32) | pad | Args.Mob (40)
 *   End.M.GTP6.E SID = locator+function | pad | Args.Mob (40)
 *
 * The IPv4 DA bits encode the GTP-U outer destination that End.M.GTP4.E
 * will use when re-encapping toward the gNB; per draft Section 3.3.7 this is
 * the Tunnel Endpoint Address from the T1ST NLRI when the endpoint is
 * IPv4.  Args.Mob.Session is fixed at offset 88 (= 128 - 40).
 */
static bool bgp_mup_synthesize_t1st_sid(const struct bgp_mup_isd_entry *isd,
					const struct mup_t1st_route *t1, struct in6_addr *out)
{
	unsigned int loc_func = isd->loc_block_len + isd->loc_node_len + isd->func_len;
	bool isd_is_v4 = (isd->behavior == SRV6_ENDPOINT_BEHAVIOR_END_M_GTP4_E);
	uint64_t args_mob;

	if (loc_func == 0 || loc_func > IPV6_MAX_BITLEN)
		return false;

	*out = isd->sid;

	if (isd_is_v4) {
		uint32_t v4;

		/* Endpoint must be IPv4 for End.M.GTP4.E SID synthesis. */
		if (t1->t1st_3gpp_5g.endpoint_address.ipa_type != IPADDR_V4)
			return false;
		if (loc_func + 32 + 40 > IPV6_MAX_BITLEN)
			return false;
		v4 = ntohl(t1->t1st_3gpp_5g.endpoint_address.ipaddr_v4.s_addr);
		bgp_mup_sid_set_bits(out, loc_func, 32, (uint64_t)v4);
	} else {
		if (loc_func + 40 > IPV6_MAX_BITLEN)
			return false;
	}

	args_mob = bgp_mup_args_mob_session(t1->t1st_3gpp_5g.teid, t1->t1st_3gpp_5g.qfi);
	bgp_mup_sid_set_bits(out, IPV6_MAX_BITLEN - 40, 40, args_mob);
	return true;
}

/* T1ST resolution result.  Synthesized End.M.GTP*.E SID + outer IPv6
 * source for the new SRv6 packet (T1ST.source_address if present, else
 * a locally configured fallback).
 */
struct bgp_mup_t1st_resolved {
	struct in6_addr sid;
	struct in6_addr outer_sa;
	bool have_outer_sa;
};

static bool bgp_mup_resolve_t1st(struct bgp *bgp, const struct mup_prefix *mp,
				 struct bgp_mup_t1st_resolved *out)
{
	const struct mup_t1st_3gpp_5g *ext = &mp->t1st_route.t1st_3gpp_5g;
	struct bgp_mup_isd_entry *isd;
	afi_t afi;

	afi = (ext->endpoint_address.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	isd = bgp_mup_isd_lookup(bgp, afi, &ext->endpoint_address);
	if (!isd) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: T1ST endpoint has no matching ISD; skip install");
		return false;
	}
	if (!bgp_mup_synthesize_t1st_sid(isd, &mp->t1st_route, &out->sid)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: T1ST SID synthesis failed (loc_func=%u behavior=%u)",
				   isd->loc_block_len + isd->loc_node_len + isd->func_len,
				   isd->behavior);
		return false;
	}

	out->have_outer_sa = false;
	if (ext->source_address_length == 128) {
		out->outer_sa = ext->source_address.ipaddr_v6;
		out->have_outer_sa = true;
	} else if (ext->source_address_length == 32) {
		/* IPv4 source: embed at IPv6 bytes 8..11 (RFC 9433 Section 6.7
		 * default v6_src_prefix_len of 64).  Higher bytes left
		 * zero — operator configures a richer source via local
		 * config when needed (handled by the fallback path).
		 */
		memset(&out->outer_sa, 0, sizeof(out->outer_sa));
		memcpy(&out->outer_sa.s6_addr[8], &ext->source_address.ipaddr_v4,
		       sizeof(struct in_addr));
		out->have_outer_sa = true;
	}
	if (!out->have_outer_sa) {
		/* Pick the outer source from the default vrf (where the SR
		 * underlay lives), regardless of which per-vrf table the
		 * H.Encaps route lands in.
		 */
		if (bgp_mup_local_v6_source(VRF_DEFAULT, &out->outer_sa))
			out->have_outer_sa = true;
	}
	return out->have_outer_sa;
}

static void bgp_mup_build_t1st_route(const struct mup_prefix *mp,
				     const struct bgp_mup_t1st_resolved *r, struct zapi_route *api)
{
	const struct mup_t1st_route *t1 = &mp->t1st_route;
	struct zapi_nexthop *api_nh;

	api->prefix.family = (t1->ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
	api->prefix.prefixlen = t1->ip_prefix_length;
	if (api->prefix.family == AF_INET)
		memcpy(&api->prefix.u.prefix4, &t1->ip.ipaddr_v4, sizeof(struct in_addr));
	else
		memcpy(&api->prefix.u.prefix6, &t1->ip.ipaddr_v6, sizeof(struct in6_addr));

	api_nh = &api->nexthops[0];
	api_nh->type = NEXTHOP_TYPE_IPV6;
	api_nh->gate.ipv6 = r->sid;
	api_nh->seg6_segs[0] = r->sid;
	api_nh->seg_num = 1;
	SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
	/* H.Encaps so the kernel prepends a fresh outer IPv6 (+ optional
	 * SRH) instead of inserting an SRH into an existing IPv6 packet
	 * (H.Insert; only legal for IPv6 destinations).  T1ST is DL
	 * ingress at the MUP-PE so the inner is whatever traffic was
	 * destined to the UE prefix.
	 */
	api_nh->srv6_encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
	/* SID nexthop resolves in the SR underlay (default vrf), even
	 * when the route prefix sits in a per-vrf table.
	 */
	api_nh->vrf_id = VRF_DEFAULT;
	api->nexthop_num = 1;
}

static void bgp_mup_build_t2st_route(const struct mup_prefix *mp,
				     const struct bgp_mup_dsd_entry *dsd,
				     struct zapi_route *api)
{
	const struct mup_t2st_route *t2 = &mp->t2st_route;
	bool ep_v4 = IS_IPADDR_V4(&t2->endpoint_address);
	uint8_t loc_func = dsd->loc_block_len + dsd->loc_node_len + dsd->func_len;
	struct interface *ifp;
	struct zapi_nexthop *api_nh;

	api->prefix.family = ep_v4 ? AF_INET : AF_INET6;
	if (ep_v4) {
		api->prefix.prefixlen = IPV4_MAX_BITLEN;
		api->prefix.u.prefix4 = t2->endpoint_address.ipaddr_v4;
	} else {
		api->prefix.prefixlen = IPV6_MAX_BITLEN;
		api->prefix.u.prefix6 = t2->endpoint_address.ipaddr_v6;
	}

	api_nh = &api->nexthops[0];
	/* H.M.GTP4.D is a local action: anchor the route on an interface
	 * in the SR underlay (default vrf), regardless of which per-vrf
	 * table the route prefix lands in.  The kernel uses this dev to
	 * decide which vrf table to look the post-action SRv6 packet's
	 * destination up in; using a default-vrf interface keeps the
	 * lookup in the SR underlay even for cross-vrf installs (route
	 * in slice X, transport in default).
	 */
	ifp = bgp_mup_locator_oif(VRF_DEFAULT, &dsd->sid);
	api_nh->type = NEXTHOP_TYPE_IFINDEX;
	api_nh->ifindex = ifp ? ifp->ifindex : 0;
	api_nh->vrf_id = VRF_DEFAULT;
	api_nh->seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_H_M_GTP4_D;
	api_nh->seg6local_ctx.nh6 = dsd->sid;
	api_nh->seg6local_ctx.mobile.valid = true;
	/* The kernel's H.M.GTP4.D action constructs the outer SRv6
	 * destination from nh6 (locator+function from DSD's SID) + IPv4
	 * SA bits (v4_mask_len, MSB-aligned at sr_prefix_len) +
	 * Args.Mob.Session (40 bits, last).  v4_mask_len must be 1..32 and
	 * leave room for the 40-bit Args.Mob.Session inside the SID.  Use
	 * the endpoint's mask length (32 for IPv4 endpoints) so the inner
	 * gNB IPv4 SA is fully encoded; the End.DT* endpoint at the
	 * remote PE ignores those bits during decap.
	 */
	api_nh->seg6local_ctx.mobile.sr_prefix_len = loc_func;
	api_nh->seg6local_ctx.mobile.v4_mask_len = ep_v4 ? 32 : 0;
	/* Outer IPv6 source for the new SRv6 packet: pick from the
	 * default vrf (the SR underlay's address space), same scope as
	 * the locator interface above.
	 */
	if (bgp_mup_local_v6_source(VRF_DEFAULT, &api_nh->seg6local_ctx.mobile.src_addr) == false)
		memset(&api_nh->seg6local_ctx.mobile.src_addr, 0,
		       sizeof(api_nh->seg6local_ctx.mobile.src_addr));
	SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL);
	api->nexthop_num = 1;
}

/* Build the prefix-only zapi_route used for ROUTE_DELETE.  Prefix
 * matches what an install would have used so zebra can find/remove the
 * prior add.  No nexthops needed for delete.
 */
static bool bgp_mup_build_st_delete(const struct mup_prefix *mp, struct zapi_route *api)
{
	if (mp->route_type == BGP_MUP_T1ST_ROUTE) {
		const struct mup_t1st_route *t1 = &mp->t1st_route;

		api->prefix.family = (t1->ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
		api->prefix.prefixlen = t1->ip_prefix_length;
		if (api->prefix.family == AF_INET)
			api->prefix.u.prefix4 = t1->ip.ipaddr_v4;
		else
			api->prefix.u.prefix6 = t1->ip.ipaddr_v6;
		return true;
	}
	if (mp->route_type == BGP_MUP_T2ST_ROUTE) {
		const struct mup_t2st_route *t2 = &mp->t2st_route;
		bool ep_v4 = IS_IPADDR_V4(&t2->endpoint_address);

		api->prefix.family = ep_v4 ? AF_INET : AF_INET6;
		if (ep_v4) {
			api->prefix.prefixlen = IPV4_MAX_BITLEN;
			api->prefix.u.prefix4 = t2->endpoint_address.ipaddr_v4;
		} else {
			api->prefix.prefixlen = IPV6_MAX_BITLEN;
			api->prefix.u.prefix6 = t2->endpoint_address.ipaddr_v6;
		}
		return true;
	}
	return false;
}

/* Cache an ISD route into the discovery table.  Treat-as-withdraw on
 * any structural error (no Prefix-SID, malformed SID-Structure, etc).
 */
static void bgp_mup_isd_announce(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp,
				 const struct attr *attr)
{
	struct prefix_rd prd = {};
	struct prefix prefix = {};
	struct in6_addr sid;
	uint8_t block, node, func, arg;
	uint16_t behavior;

	if (!bgp_mup_get_sid_structure(attr, &sid, &block, &node, &func, &arg, &behavior)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: ISD without Prefix-SID; ignoring");
		return;
	}
	bgp_mup_prd_from_bytes(&prd, mp->rd);
	prefix.family = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
	prefix.prefixlen = mp->isd_route.ip_prefix_length;
	if (prefix.family == AF_INET)
		prefix.u.prefix4 = mp->isd_route.ip.ipaddr_v4;
	else
		prefix.u.prefix6 = mp->isd_route.ip.ipaddr_v6;
	bgp_mup_isd_cache_upsert(bgp, afi, &prd, &prefix, &sid, block, node, func, arg, behavior);
}

static void bgp_mup_isd_withdraw(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp)
{
	struct prefix_rd prd = {};
	struct prefix prefix = {};

	bgp_mup_prd_from_bytes(&prd, mp->rd);
	prefix.family = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
	prefix.prefixlen = mp->isd_route.ip_prefix_length;
	if (prefix.family == AF_INET)
		prefix.u.prefix4 = mp->isd_route.ip.ipaddr_v4;
	else
		prefix.u.prefix6 = mp->isd_route.ip.ipaddr_v6;
	bgp_mup_isd_cache_remove(bgp, afi, &prd, &prefix);
}

static void bgp_mup_dsd_announce(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp,
				 const struct attr *attr)
{
	struct prefix_rd prd = {};
	struct in6_addr sid;
	uint8_t block, node, func, arg;
	uint16_t behavior;
	uint64_t segment_id = 0;
	bool has_seg = false;

	if (!bgp_mup_get_sid_structure(attr, &sid, &block, &node, &func, &arg, &behavior)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: DSD without Prefix-SID; ignoring");
		return;
	}
	has_seg = bgp_mup_get_direct_seg_id(attr, &segment_id);
	bgp_mup_prd_from_bytes(&prd, mp->rd);
	bgp_mup_dsd_cache_upsert(bgp, afi, &prd, &mp->dsd_route.ip, &sid, block, node, func, arg,
				 behavior, has_seg, segment_id);
}

static void bgp_mup_dsd_withdraw(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp)
{
	struct prefix_rd prd = {};

	bgp_mup_prd_from_bytes(&prd, mp->rd);
	bgp_mup_dsd_cache_remove(bgp, afi, &prd, &mp->dsd_route.ip);
}

/* Common header for an SRv6 Mobile User Plane install/uninstall sent
 * from BGP-MUP into zebra.
 */
static void bgp_mup_zapi_init(struct zapi_route *api, struct bgp *bgp, struct bgp_path_info *info,
			      bool installing)
{
	api->vrf_id = bgp->vrf_id;
	api->type = ZEBRA_ROUTE_BGP;
	api->safi = SAFI_UNICAST;
	if (installing) {
		SET_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP);
		if (info && info->peer && info->peer->sort == BGP_PEER_IBGP)
			SET_FLAG(api->flags, ZEBRA_FLAG_IBGP);
		/*
		 * The T1ST install carries an IPv6 nexthop = synthesized
		 * End.M.GTP*.E SID inside the remote MUP-GW's locator
		 * prefix.  zebra needs ALLOW_RECURSION to walk the local
		 * RIB (e.g. an IGP/static route to that locator) when the
		 * nh isn't on a directly connected subnet.  Mirrors how
		 * zclient_send_localsid() flags its installs.
		 */
		SET_FLAG(api->flags, ZEBRA_FLAG_ALLOW_RECURSION);
	}
}

/* Decode a persisted `segment direct` origin's MUP-EC Direct-Type
 * Segment Identifier (48 bits, packed mup_as<<32 | mup_val) — same
 * encoding the segment direct DEFPY uses to build the on-wire MUP
 * extended community and that bgp_mup_get_direct_seg_id() pulls back
 * out.
 */
static bool bgp_mup_origin_segment_id(const struct bgp_mup_origin *o, uint64_t *out)
{
	uint32_t mup_as = 0, mup_val = 0;

	if (!o->mup_str)
		return false;
	if (sscanf(o->mup_str, "%u:%u", &mup_as, &mup_val) != 2)
		return false;
	*out = ((uint64_t)mup_as << 32) | (uint64_t)mup_val;
	return true;
}

/* Loop guard for self-origin: returns true iff the (afi, RD, ISD prefix)
 * matches a `segment interwork` line configured on any per-vrf bgp
 * instance on this PE.  Mirrors bgp_mplsvpn.c's vpn_leak_to_vrf_update
 * loop check (`bgp_orig != bgp`): without it, a T1ST received over the
 * BGP-MUP session whose RT also imports into our own per-vrf instance
 * would resolve against our self-originated ISD and produce a
 * non-functional install (synth SID lands in our own locator; packet
 * would loop or get dropped).
 */
static bool bgp_mup_isd_is_self(afi_t afi, const struct prefix_rd *prd,
				const struct prefix *isd_prefix)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_mup_origin *o;

		if (!bgp->mup_origins)
			continue;
		frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
			if (o->route_type != BGP_MUP_ISD_ROUTE)
				continue;
			if (o->afi != afi)
				continue;
			if (memcmp(o->prd.val, prd->val, sizeof(o->prd.val)) != 0)
				continue;
			if (prefix_same(&o->isd_prefix, isd_prefix))
				return true;
		}
	}
	return false;
}

/* DSD analogue of bgp_mup_isd_is_self: T2ST resolution looks up its
 * DSD by the MUP-EC Direct-Type Segment Identifier; a matching
 * `segment direct` line on any per-vrf bgp instance means the DSD
 * is self-originated.
 */
static bool bgp_mup_dsd_is_self(uint64_t segment_id)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_mup_origin *o;

		if (!bgp->mup_origins)
			continue;
		frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
			uint64_t sid;

			if (o->route_type != BGP_MUP_DSD_ROUTE)
				continue;
			if (!bgp_mup_origin_segment_id(o, &sid))
				continue;
			if (sid == segment_id)
				return true;
		}
	}
	return false;
}

/* RT-based per-vrf install selection (mirrors L3VPN's `import vrf` /
 * RT-import filter): walk every per-vrf bgp instance's mup_origins and
 * return the first one whose `segment` was originated with an RT that
 * matches one of the route's RT extended communities.  Returns
 * VRF_UNKNOWN when no per-vrf instance imports this RT — the caller
 * skips the kernel install in that case.
 */
static vrf_id_t bgp_mup_match_install_vrf(const struct attr *attr)
{
	struct ecommunity *route_rt;
	struct listnode *node;
	struct bgp *bgp;
	vrf_id_t found = VRF_UNKNOWN;

	if (!attr)
		return VRF_UNKNOWN;
	route_rt = bgp_attr_get_ecommunity(attr);
	if (!route_rt)
		return VRF_UNKNOWN;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_mup_origin *o;

		if (bgp->vrf_id == VRF_DEFAULT || bgp->vrf_id == VRF_UNKNOWN)
			continue;
		if (!bgp->mup_origins)
			continue;
		frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
			struct ecommunity *o_rt;

			if (!o->rt_str)
				continue;
			o_rt = ecommunity_str2com(o->rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
			if (!o_rt)
				continue;
			if (ecommunity_match(route_rt, o_rt)) {
				ecommunity_free(&o_rt);
				return bgp->vrf_id;
			}
			ecommunity_free(&o_rt);
		}
	}
	return found;
}

static int bgp_mup_st_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct prefix_mup *pm, const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	vrf_id_t install_vrf_id = bgp_mup_match_install_vrf(info->attr);

	(void)dest;

	/* No per-vrf instance imports this RT — there is no local table
	 * the H.Encaps install should land in.
	 */
	if (install_vrf_id == VRF_UNKNOWN) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: route_type %u has no per-vrf RT match; skip install",
				   pm->prefix.route_type);
		return 0;
	}

	if (mp->route_type == BGP_MUP_T1ST_ROUTE) {
		struct bgp_mup_t1st_resolved r;
		struct bgp_mup_isd_entry *isd;
		afi_t isd_afi;

		isd_afi = (mp->t1st_route.t1st_3gpp_5g.endpoint_address.ipa_type == IPADDR_V4)
				  ? AFI_IP
				  : AFI_IP6;
		isd = bgp_mup_isd_lookup(bgp, isd_afi,
					 &mp->t1st_route.t1st_3gpp_5g.endpoint_address);
		if (isd && bgp_mup_isd_is_self(isd_afi, &isd->prd, &isd->prefix)) {
			/* This PE itself originated the ISD that resolves the
			 * T1ST.  Skip install (same loop guard as
			 * bgp_mplsvpn.c::vpn_leak_to_vrf_update).  Withdraw
			 * anything we previously installed in case the
			 * route's origin status flipped.
			 */
			struct zapi_route delapi = {};

			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T1ST endpoint matches self-originated ISD; skip install (no loop)");
			bgp_mup_zapi_init(&delapi, bgp, info, false);
			if (bgp_mup_build_st_delete(mp, &delapi))
				zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &delapi);
			return 0;
		}
		if (!bgp_mup_resolve_t1st(bgp, mp, &r)) {
			/* Withdraw any prior install for this T1ST: an ISD
			 * may have been removed or the source-address
			 * resolution failed.  Idempotent if nothing was
			 * installed.
			 */
			struct zapi_route delapi = {};

			bgp_mup_zapi_init(&delapi, bgp, info, false);
			if (bgp_mup_build_st_delete(mp, &delapi))
				zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &delapi);
			return 0;
		}
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t1st_route(mp, &r, &api);
	} else {
		uint64_t segment_id;
		struct bgp_mup_dsd_entry *dsd;

		if (!bgp_mup_get_direct_seg_id(info->attr, &segment_id)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST without MUP-EC; treat-as-withdraw");
			return 0;
		}
		if (bgp_mup_dsd_is_self(segment_id)) {
			struct zapi_route delapi = {};

			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST seg-id %" PRIu64
					   " matches self-originated DSD; skip install (no loop)",
					   segment_id);
			bgp_mup_zapi_init(&delapi, bgp, info, false);
			if (bgp_mup_build_st_delete(mp, &delapi))
				zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &delapi);
			return 0;
		}
		dsd = bgp_mup_dsd_lookup(bgp, segment_id);
		if (!dsd) {
			struct zapi_route delapi = {};

			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST seg-id %" PRIu64
					   " has no matching DSD; skip install",
					   segment_id);
			bgp_mup_zapi_init(&delapi, bgp, info, false);
			if (bgp_mup_build_st_delete(mp, &delapi))
				zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &delapi);
			return 0;
		}
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t2st_route(mp, dsd, &api);
	}
	/* Route prefix lands in the per-vrf RIB; nexthop vrf stays in
	 * default (the SR underlay) — bgp_mup_build_t{1,2}st_route set
	 * api->nexthops[0].vrf_id = VRF_DEFAULT so the seg6/seg6local
	 * dev resolves against the default-vrf locator interface even
	 * for cross-vrf installs.
	 */
	api.vrf_id = install_vrf_id;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: announcing route_type %u install vrf %u to zebra",
			   pm->prefix.route_type, install_vrf_id);

	return zclient_route_send(ZEBRA_ROUTE_ADD, bgp_zclient, &api);
}

static int bgp_mup_st_withdraw(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct mup_prefix *mp)
{
	struct zapi_route api = {};

	(void)dest;

	if (!bgp_mup_build_st_delete(mp, &api))
		return 0;
	bgp_mup_zapi_init(&api, bgp, info, false);
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: withdrawing route_type %u (vrf %u) from zebra", mp->route_type,
			   bgp->vrf_id);
	return zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &api);
}

int bgp_mup_zebra_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);
	const struct prefix_mup *pm;
	const struct mup_prefix *mp;
	afi_t afi;

	if (p->family != AF_MUP)
		return 0;
	pm = (const struct prefix_mup *)p;
	mp = &pm->prefix;

	afi = AFI_IP;
	if (mp->route_type == BGP_MUP_ISD_ROUTE || mp->route_type == BGP_MUP_T1ST_ROUTE) {
		afi = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	} else if (mp->route_type == BGP_MUP_DSD_ROUTE) {
		afi = (mp->dsd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	} else if (mp->route_type == BGP_MUP_T2ST_ROUTE) {
		afi = IS_IPADDR_V4(&mp->t2st_route.endpoint_address) ? AFI_IP : AFI_IP6;
	}

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		bgp_mup_isd_announce(bgp, afi, mp, info->attr);
		return 0;
	case BGP_MUP_DSD_ROUTE:
		bgp_mup_dsd_announce(bgp, afi, mp, info->attr);
		return 0;
	case BGP_MUP_T1ST_ROUTE:
	case BGP_MUP_T2ST_ROUTE:
		return bgp_mup_st_announce(dest, info, bgp, pm, mp);
	default:
		return 0;
	}
}

int bgp_mup_zebra_withdraw(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);
	const struct prefix_mup *pm;
	const struct mup_prefix *mp;
	afi_t afi;

	if (p->family != AF_MUP)
		return 0;
	pm = (const struct prefix_mup *)p;
	mp = &pm->prefix;

	afi = AFI_IP;
	if (mp->route_type == BGP_MUP_ISD_ROUTE || mp->route_type == BGP_MUP_T1ST_ROUTE) {
		afi = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	} else if (mp->route_type == BGP_MUP_DSD_ROUTE) {
		afi = (mp->dsd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	} else if (mp->route_type == BGP_MUP_T2ST_ROUTE) {
		afi = IS_IPADDR_V4(&mp->t2st_route.endpoint_address) ? AFI_IP : AFI_IP6;
	}

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		bgp_mup_isd_withdraw(bgp, afi, mp);
		return 0;
	case BGP_MUP_DSD_ROUTE:
		bgp_mup_dsd_withdraw(bgp, afi, mp);
		return 0;
	case BGP_MUP_T1ST_ROUTE:
	case BGP_MUP_T2ST_ROUTE:
		return bgp_mup_st_withdraw(dest, info, bgp, mp);
	default:
		return 0;
	}
}

/* Walk the per-AFI MUP RIB and re-trigger zebra install/withdraw for
 * each selected T1ST/T2ST.  Called from bgp_mup_*_cache_upsert/remove
 * so deferred resolutions complete (or invalidate) without another
 * BGP UPDATE arriving.
 */
static void bgp_mup_reannounce_st_routes(struct bgp *bgp, afi_t afi)
{
	struct bgp_table *table;
	struct bgp_dest *dest;

	if (!bgp->rib[afi][SAFI_MUP])
		return;
	table = bgp->rib[afi][SAFI_MUP];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *p = bgp_dest_get_prefix(dest);
		const struct prefix_mup *pm;
		struct bgp_path_info *pi;

		if (p->family != AF_MUP)
			continue;
		pm = (const struct prefix_mup *)p;
		if (pm->prefix.route_type != BGP_MUP_T1ST_ROUTE &&
		    pm->prefix.route_type != BGP_MUP_T2ST_ROUTE)
			continue;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				continue;
			(void)bgp_mup_st_announce(dest, pi, bgp, pm, &pm->prefix);
			break;
		}
	}
}

int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	int psize = 0;
	uint8_t arch_type;
	uint16_t route_type;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		if (addpath_capable) {
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Architecture Type(1) + Route Type(2) + Length(1). */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE;

		arch_type = pnt[0];
		memcpy(&route_type, pnt + 1, 2);
		route_type = ntohs(route_type);
		psize = pnt[3];
		pnt += 4;

		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		/* draft-ietf-bess-mup-safi only defines 3gpp-5g (1).  Silently
		 * skip routes for unknown architectures.
		 */
		if (arch_type != BGP_MUP_ARCH_3GPP_5G)
			continue;

		switch (route_type) {
		case BGP_MUP_ISD_ROUTE:
			if (bgp_mup_process_isd_route(peer, afi, safi, withdraw ? NULL : attr, pnt,
						      psize, addpath_id)) {
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Error processing BGP-MUP ISD NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_ISD_SIZE;
			}
			break;

		case BGP_MUP_DSD_ROUTE:
			if (bgp_mup_process_dsd_route(peer, afi, safi, withdraw ? NULL : attr, pnt,
						      psize, addpath_id)) {
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Error processing BGP-MUP DSD NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_DSD_SIZE;
			}
			break;

		case BGP_MUP_T1ST_ROUTE:
			if (bgp_mup_process_t1st_route(peer, afi, safi, withdraw ? NULL : attr,
						       pnt, psize, addpath_id)) {
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Error processing BGP-MUP T1ST NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_T1ST_SIZE;
			}
			break;

		case BGP_MUP_T2ST_ROUTE:
			if (bgp_mup_process_t2st_route(peer, afi, safi, withdraw ? NULL : attr,
						       pnt, psize, addpath_id)) {
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Error processing BGP-MUP T2ST NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_T2ST_SIZE;
			}
			break;

		default:
			/* Unknown route type for the negotiated arch:
			 * silently ignore (draft section 3.1).
			 */
			break;
		}
	}

	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}

/* ---------------------------------------------------------------------- */
/* Local origination of ISD / DSD routes (draft-ietf-bess-mup-safi 3.3.1, */
/* 3.3.4).  T1ST/T2ST origination is intentionally not provided: those    */
/* routes are derived from per-session 5G control state and synthesised   */
/* by an external MUP Controller (MUP-C) which then advertises them via   */
/* BGP-MUP.  FRR's role is the MUP-PE / MUP-GW that originates ISD/DSD    */
/* for its own SR locator and accepts T1ST/T2ST from the controller.      */
/*                                                                        */
/* Per draft Section 3.3.1: the ISD prefix-SID MUST be `locator + function`,     */
/* and the function MUST be GTP4.E (IPv4 AFI) or GTP6.E (IPv6 AFI).       */
/* Per draft Section 3.3.4: the DSD prefix-SID MUST be `locator + function`,     */
/* and the function is End.DT4 / End.DT6.                                 */
/* The function bit value is locally allocated under the locator so the   */
/* SID is unique within this PE.                                          */
/* ---------------------------------------------------------------------- */

#include "bgpd/bgp_rd.h"

/* Build the BGP attribute set for a locally-originated ISD/DSD: origin
 * INCOMPLETE, IPv6 next-hop = local router-id-mapped or peer's local
 * address (peer adjusts on egress), Prefix-SID L3 Service TLV with the
 * locator-composed SID + per-route-type-mandated behavior + SID-Structure
 * derived from the locator, and the RT/MUP extended communities.
 */
static struct attr *bgp_mup_local_attr(struct bgp *bgp, const struct in6_addr *sid,
				       uint16_t endpoint_behavior, uint8_t loc_block_len,
				       uint8_t loc_node_len, uint8_t func_len, uint8_t arg_len,
				       struct ecommunity *ecom)
{
	struct attr attr = {};
	struct bgp_attr_srv6_l3service *l3;

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);

	/* IPv6 next-hop is a placeholder; egress encoder rewrites it to the
	 * outgoing peer's local address per RFC 9433 / draft.  We just need
	 * a non-zero value so MP_REACH NH length is set.
	 */
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

	/* Prefix-SID (RFC 9252 Section 3 SRv6 L3 Service TLV). */
	l3 = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE, sizeof(*l3));
	l3->sid = *sid;
	l3->endpoint_behavior = endpoint_behavior;
	l3->loc_block_len = loc_block_len;
	l3->loc_node_len = loc_node_len;
	l3->func_len = func_len;
	l3->arg_len = arg_len;
	attr.srv6_l3service = l3;
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));

	/* Extended Communities (RT, optionally MUP). */
	if (ecom) {
		bgp_attr_set_ecommunity(&attr, ecommunity_dup(ecom));
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));
	}

	return bgp_attr_intern(&attr);
}

/* Per-vrf bgp instances originate `segment interwork|direct`, but the
 * BGP-MUP session lives in the default-vrf bgp (mirroring L3VPN's
 * vpn_leak_from_vrf model: per-vrf unicast originates, default-vrf vpn
 * advertises).  Inject the route directly into the default-vrf RIB via
 * the same static-update pattern bgp_static_update / vpn_leak_to_vrf_
 * update_onevrf use (info_make + bgp_path_info_add + bgp_process), so
 * the path registration bypasses the inbound bgp_update_main checks
 * that don't apply to a self-origin (RFC 8212 default-deny in
 * particular fires on peer_self otherwise).  bgp_mup_zebra_announce()
 * on the default-vrf path also populates the discovery cache there,
 * which is where T1ST/T2ST received over the same session look up
 * matches.
 */
static int bgp_mup_originate_common(struct bgp *bgp, afi_t afi, struct prefix_mup *p,
				    struct attr *attr, bool withdraw)
{
	struct bgp *to_bgp = (bgp->vrf_id == VRF_DEFAULT) ? bgp : bgp_get_default();
	struct prefix_rd prd = {};
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr *attr_new;
	struct bgp_path_info *new;

	if (!to_bgp) {
		zlog_err("BGP-MUP: no default-vrf bgp instance to advertise via");
		return -1;
	}

	bgp_mup_prd_from_bytes(&prd, p->prefix.rd);

	if (withdraw) {
		dest = bgp_safi_node_lookup(to_bgp->rib[afi][SAFI_MUP], SAFI_MUP,
					    (struct prefix *)p, &prd);
		if (!dest)
			return 0;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == to_bgp->peer_self &&
			    pi->type == ZEBRA_ROUTE_BGP &&
			    pi->sub_type == BGP_ROUTE_STATIC)
				break;

		if (pi) {
			bgp_aggregate_decrement(to_bgp, (struct prefix *)p, pi, afi, SAFI_MUP);
			bgp_unlink_nexthop(pi);
			bgp_path_info_mark_for_delete(dest, pi);
			bgp_process(to_bgp, dest, pi, afi, SAFI_MUP);
		}
		bgp_dest_unlock_node(dest);
		return 0;
	}

	dest = bgp_afi_node_get(to_bgp->rib[afi][SAFI_MUP], afi, SAFI_MUP,
				(struct prefix *)p, &prd);
	attr_new = bgp_attr_intern(attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == to_bgp->peer_self &&
		    pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_STATIC)
			break;

	if (pi) {
		if (attrhash_cmp(pi->attr, attr_new) &&
		    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			bgp_attr_unintern(&attr_new);
			bgp_dest_unlock_node(dest);
			return 0;
		}
		/* Refresh: replace attr in place. */
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_unset_flag(dest, pi, BGP_PATH_REMOVED);
		bgp_process(to_bgp, dest, pi, afi, SAFI_MUP);
		bgp_dest_unlock_node(dest);
		return 0;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, to_bgp->peer_self,
			attr_new, dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);
	bgp_path_info_add(dest, new);
	bgp_aggregate_increment(to_bgp, (struct prefix *)p, new, afi, SAFI_MUP);
	bgp_dest_unlock_node(dest);
	bgp_process(to_bgp, dest, new, afi, SAFI_MUP);
	return 0;
}

/* ---- Pending-originate tracking (async SID-manager flow) ----------------
 *
 * When the operator types `segment interwork|direct ...` without a
 * `sid explicit`, we ask zebra's SRv6 SID manager to allocate a function
 * for us and zebra returns the SID asynchronously via ZAPI_SRV6_SID_
 * ALLOCATED.  We park the operator's args on a per-bgp pending list and
 * complete the originate (BGP advertise + kernel install) when the SID
 * arrives.
 *
 * Disambiguation: `srv6_sid_ctx` doesn't have room to tag arbitrary
 * client state, but the (vrf_id, behavior) tuple together with the
 * NLRI key (prefix/RD for ISD; address/RD for DSD) is unique within a
 * given bgpd instance.  We match SID alloc replies by ctx alone (FIFO
 * order within a behavior class), which works because zebra processes
 * get-sid requests serially per locator.  If we ever multi-thread or
 * pipeline, switch to encoding a tag in ctx.ifindex.
 */
struct bgp_mup_pending {
	struct bgp_mup_pending_list_item item;
	uint16_t route_type;		 /* BGP_MUP_ISD_ROUTE or BGP_MUP_DSD_ROUTE */
	struct bgp_mup_origin_args args; /* args->ecom is dup'd & owned */
	struct srv6_sid_ctx ctx;	 /* the ctx we sent to zebra */
};
DECLARE_LIST(bgp_mup_pending_list, struct bgp_mup_pending, item);

static struct bgp_mup_pending_list_head *bgp_mup_get_pending_list(struct bgp *bgp)
{
	if (!bgp->mup_pending) {
		bgp->mup_pending = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_pending));
		bgp_mup_pending_list_init(bgp->mup_pending);
	}
	return bgp->mup_pending;
}

static struct bgp_mup_pending *bgp_mup_pending_pop(struct bgp *bgp, const struct srv6_sid_ctx *ctx)
{
	struct bgp_mup_pending_list_head *head;
	struct bgp_mup_pending *p;

	if (!bgp->mup_pending)
		return NULL;
	head = bgp->mup_pending;
	frr_each_safe (bgp_mup_pending_list, head, p) {
		if (p->ctx.behavior == ctx->behavior && p->ctx.vrf_id == ctx->vrf_id) {
			bgp_mup_pending_list_del(head, p);
			return p;
		}
	}
	return NULL;
}

/* Pop a pending entry that matches the operator's withdraw NLRI key
 * (route_type + afi + RD + prefix-or-endpoint).  Used to cancel a
 * not-yet-allocated SID request when `no segment ...` arrives before
 * zebra has answered.  Returns NULL if no matching pending exists,
 * meaning the SID alloc already completed and the route is in the RIB
 * (regular BGP withdraw path applies).
 */
static struct bgp_mup_pending *
bgp_mup_pending_pop_for_withdraw(struct bgp *bgp, uint16_t route_type,
				 const struct bgp_mup_origin_args *args)
{
	struct bgp_mup_pending_list_head *head;
	struct bgp_mup_pending *p;

	if (!bgp->mup_pending)
		return NULL;
	head = bgp->mup_pending;
	frr_each_safe (bgp_mup_pending_list, head, p) {
		if (p->route_type != route_type || p->args.afi != args->afi)
			continue;
		if (memcmp(p->args.prd.val, args->prd.val, sizeof(p->args.prd.val)) != 0)
			continue;
		if (route_type == BGP_MUP_ISD_ROUTE) {
			if (!prefix_same(&p->args.isd_prefix, &args->isd_prefix))
				continue;
		} else {
			if (!ipaddr_is_same(&p->args.dsd_endpoint, &args->dsd_endpoint))
				continue;
		}
		bgp_mup_pending_list_del(head, p);
		return p;
	}
	return NULL;
}

static void bgp_mup_pending_free(struct bgp_mup_pending *p)
{
	if (p->args.ecom)
		ecommunity_free(&p->args.ecom);
	XFREE(MTYPE_BGP_MUP_PENDING, p);
}

/* Persistent record of an operator-configured `segment` line.  Survives
 * SID alloc cycles so the running config can re-emit the originate.
 * rt_str / mup_str preserve the operator's exact text for verbatim
 * roundtrip across `write memory`.
 */
static struct bgp_mup_origin_list_head *bgp_mup_get_origin_list(struct bgp *bgp)
{
	if (!bgp->mup_origins) {
		bgp->mup_origins = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_origins));
		bgp_mup_origin_list_init(bgp->mup_origins);
	}
	return bgp->mup_origins;
}

static bool bgp_mup_origin_match(const struct bgp_mup_origin *o, uint16_t route_type, afi_t afi,
				 const struct prefix_rd *prd, const struct prefix *isd_prefix,
				 const struct ipaddr *dsd_endpoint)
{
	if (o->route_type != route_type || o->afi != afi)
		return false;
	if (memcmp(o->prd.val, prd->val, sizeof(o->prd.val)) != 0)
		return false;
	if (route_type == BGP_MUP_ISD_ROUTE)
		return prefix_same(&o->isd_prefix, isd_prefix);
	return ipaddr_is_same(&o->dsd_endpoint, dsd_endpoint);
}

static struct bgp_mup_origin *bgp_mup_origin_find(struct bgp *bgp, uint16_t route_type, afi_t afi,
						  const struct prefix_rd *prd,
						  const struct prefix *isd_prefix,
						  const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o;

	if (!bgp->mup_origins)
		return NULL;
	frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
		if (bgp_mup_origin_match(o, route_type, afi, prd, isd_prefix, dsd_endpoint))
			return o;
	}
	return NULL;
}

static void bgp_mup_origin_free(struct bgp_mup_origin *o)
{
	XFREE(MTYPE_BGP_MUP_STR, o->rt_str);
	XFREE(MTYPE_BGP_MUP_STR, o->mup_str);
	XFREE(MTYPE_BGP_MUP_ORIGIN, o);
}

/* Mark a persisted origin as fully installed (BGP RIB + kernel SID).
 * Called from bgp_mup_emit_*'s success path, both for explicit-SID
 * (synchronous) and auto-allocate (after the SID notify arrives).
 * The flag distinguishes "needs replay on locator arrival" from
 * "already alive" so bgp_mup_replay_origins is idempotent.
 */
static void bgp_mup_origin_mark_ready(struct bgp *bgp, uint16_t route_type, afi_t afi,
				      const struct prefix_rd *prd,
				      const struct prefix *isd_prefix,
				      const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, route_type, afi, prd, isd_prefix,
						       dsd_endpoint);

	if (o)
		o->sid_ready = true;
}

/* Insert a new persistent record, replacing any existing entry with the
 * same NLRI key.  Caller is the VTY DEFPY after the originate has been
 * accepted by the SID manager path.
 */
static void bgp_mup_origin_persist_isd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
				       const char *rt_str)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, BGP_MUP_ISD_ROUTE, args->afi,
						       &args->prd, &args->isd_prefix, NULL);

	if (o) {
		bgp_mup_origin_list_del(bgp->mup_origins, o);
		bgp_mup_origin_free(o);
	}
	o = XCALLOC(MTYPE_BGP_MUP_ORIGIN, sizeof(*o));
	o->route_type = BGP_MUP_ISD_ROUTE;
	o->afi = args->afi;
	o->prd = args->prd;
	o->isd_prefix = args->isd_prefix;
	o->has_explicit_sid = args->has_explicit_sid;
	o->explicit_sid = args->explicit_sid;
	o->rt_str = XSTRDUP(MTYPE_BGP_MUP_STR, rt_str);
	bgp_mup_origin_list_add_tail(bgp_mup_get_origin_list(bgp), o);
}

static void bgp_mup_origin_persist_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
				       const char *rt_str, const char *mup_str)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, BGP_MUP_DSD_ROUTE, args->afi,
						       &args->prd, NULL, &args->dsd_endpoint);

	if (o) {
		bgp_mup_origin_list_del(bgp->mup_origins, o);
		bgp_mup_origin_free(o);
	}
	o = XCALLOC(MTYPE_BGP_MUP_ORIGIN, sizeof(*o));
	o->route_type = BGP_MUP_DSD_ROUTE;
	o->afi = args->afi;
	o->prd = args->prd;
	o->dsd_endpoint = args->dsd_endpoint;
	o->dsd_behavior = args->dsd_behavior;
	o->has_explicit_sid = args->has_explicit_sid;
	o->explicit_sid = args->explicit_sid;
	o->rt_str = XSTRDUP(MTYPE_BGP_MUP_STR, rt_str);
	o->mup_str = XSTRDUP(MTYPE_BGP_MUP_STR, mup_str);
	bgp_mup_origin_list_add_tail(bgp_mup_get_origin_list(bgp), o);
}

static void bgp_mup_origin_forget(struct bgp *bgp, uint16_t route_type, afi_t afi,
				  const struct prefix_rd *prd, const struct prefix *isd_prefix,
				  const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, route_type, afi, prd, isd_prefix,
						       dsd_endpoint);

	if (!o)
		return;
	bgp_mup_origin_list_del(bgp->mup_origins, o);
	bgp_mup_origin_free(o);
}

void bgp_mup_origin_list_free(struct bgp *bgp)
{
	struct bgp_mup_origin *o;

	if (!bgp->mup_origins)
		return;
	while ((o = bgp_mup_origin_list_pop(bgp->mup_origins)))
		bgp_mup_origin_free(o);
	bgp_mup_origin_list_fini(bgp->mup_origins);
	XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_origins);
}

/* Drain pending originate entries on bgp instance teardown.  Each
 * entry holds a duplicated args.ecom; bgp_mup_pending_free releases
 * both the ecommunity and the entry struct.
 */
void bgp_mup_pending_list_free(struct bgp *bgp)
{
	struct bgp_mup_pending *p;

	if (!bgp->mup_pending)
		return;
	while ((p = bgp_mup_pending_list_pop(bgp->mup_pending)))
		bgp_mup_pending_free(p);
	bgp_mup_pending_list_fini(bgp->mup_pending);
	XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_pending);
}

/* Synchronous originate path: build the prefix_mup + attr from a known
 * SID and submit to bgpd RIB.  Used both by the explicit-SID flow and
 * by the async completion when zebra returns the auto-allocated SID.
 */
static int bgp_mup_emit_isd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
			    const struct in6_addr *sid, bool withdraw)
{
	struct prefix_mup p = {};
	struct attr *attr = NULL;
	struct srv6_locator *loc;
	uint16_t behavior;
	uint8_t prefix_octets;
	int ret;

	loc = bgp_srv6_locator_lookup(bgp, bgp_get_default());
	if (!loc)
		return -1;
	behavior = (args->afi == AFI_IP) ? SRV6_ENDPOINT_BEHAVIOR_END_M_GTP4_E
					 : SRV6_ENDPOINT_BEHAVIOR_END_M_GTP6_E;

	prefix_octets = PSIZE(args->isd_prefix.prefixlen);
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_ISD_ROUTE;
	p.prefix.length = 8 + 1 + prefix_octets;
	memcpy(p.prefix.rd, args->prd.val, 8);
	p.prefix.isd_route.ip_prefix_length = args->isd_prefix.prefixlen;
	if (args->afi == AFI_IP) {
		p.prefix.isd_route.ip.ipa_type = IPADDR_V4;
		p.prefix.isd_route.ip.ipaddr_v4 = args->isd_prefix.u.prefix4;
	} else {
		p.prefix.isd_route.ip.ipa_type = IPADDR_V6;
		p.prefix.isd_route.ip.ipaddr_v6 = args->isd_prefix.u.prefix6;
	}

	if (!withdraw)
		attr = bgp_mup_local_attr(bgp, sid, behavior, loc->block_bits_length,
					  loc->node_bits_length, loc->function_bits_length,
					  loc->argument_bits_length, args->ecom);
	ret = bgp_mup_originate_common(bgp, args->afi, &p, attr, withdraw);
	/*
	 * Self-originated MUP routes (BGP_ROUTE_STATIC) bypass
	 * bgp_zebra_announce_eligible(), so the receive-side dispatch in
	 * bgp_zebra_announce_actual() never reaches bgp_mup_zebra_announce()
	 * for them.  Mirror the cache update here so that local ISD also
	 * resolves T1ST routes received from MUP-Controllers.  The cache
	 * lives in the default-vrf bgp (single source of truth for lookup);
	 * origin_vrf_id remembers which per-vrf instance configured the
	 * `segment` so T1ST resolutions can install into that VRF's table.
	 */
	{
		struct bgp *cache_bgp = (bgp->vrf_id == VRF_DEFAULT) ? bgp : bgp_get_default();

		if (!cache_bgp)
			cache_bgp = bgp;
		if (!withdraw)
			bgp_mup_isd_cache_upsert(cache_bgp, args->afi, &args->prd,
						 &args->isd_prefix, sid, loc->block_bits_length,
						 loc->node_bits_length, loc->function_bits_length,
						 loc->argument_bits_length, behavior);
		else
			bgp_mup_isd_cache_remove(cache_bgp, args->afi, &args->prd,
						 &args->isd_prefix);
	}

	/*
	 * Install the End.M.GTP{4,6}.E seg6local action in the kernel at
	 * the allocated SID.  The L3VPN per-VRF tovpn_sid path uses the
	 * same zclient_send_localsid() helper to push End.DT4/6 — this is
	 * the BGP-MUP equivalent for ISD origination.  Per RFC 9433 Section 6.6
	 * v4_mask_len (32 for IPv4 endpoints, 0 for IPv6) tells the kernel
	 * how many trailing bits of the SID encode the IPv4 destination
	 * address.
	 */
	{
		struct seg6local_context lctx = {};
		enum seg6local_action_t act;
		struct interface *vrf_lo = if_get_vrf_loopback(bgp->vrf_id);
		ifindex_t oif = vrf_lo ? vrf_lo->ifindex : 0;

		lctx.block_len = loc->block_bits_length;
		lctx.node_len = loc->node_bits_length;
		lctx.function_len = loc->function_bits_length;
		lctx.argument_len = loc->argument_bits_length;
		/*
		 * Stash the per-vrf-loopback ifindex in seg6local_ctx.ifindex
		 * so the rt_netlink encoder emits SEG6_LOCAL_OIF in the
		 * seg6local nest.  The kernel's End.M.GTP*.E handler uses
		 * slwt->oif as flowi4_oif for its post-action route lookup —
		 * without it the rebuilt GTP-U is looked up in the main FIB
		 * and dropped because the gNB-side veth lives in vrf-red's
		 * table.  Same pattern as L3VPN's End.DT4/DT6 install in
		 * bgp_mplsvpn.c:vpn_leak_zebra_vrf_sid_update_per_af.
		 */
		lctx.ifindex = oif;
		lctx.mobile.valid = true;
		lctx.mobile.v4_mask_len = (args->afi == AFI_IP) ? 32 : 0;
		/*
		 * v6_src_prefix_len tells End.M.GTP*.E where the IPv4
		 * source bits live inside the incoming SRv6 source
		 * address (the gNB IPv4 written there by the peer
		 * H.M.GTP4.D).  Default to /64 per RFC 9433 Section 6.7 so
		 * the egress GTP-U gets a real src IP, not 0.0.0.0.
		 */
		if (args->afi == AFI_IP)
			lctx.mobile.v6_src_prefix_len = 64;
		act = (args->afi == AFI_IP) ? ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E
					    : ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP6_E;
		/*
		 * End.M.GTP{4,6}.E consumes the trailing v4_DA(32) +
		 * Args.Mob.Session(40) bits at packet time, so the FIB
		 * route must be at the locator+function prefix, not /128.
		 * The kernel enforces prefix_len + v4_mask_len + 40 <= 128.
		 */
		zclient_send_localsid(bgp_zclient,
				      withdraw ? ZEBRA_ROUTE_DELETE : ZEBRA_ROUTE_ADD, sid,
				      loc->block_bits_length + loc->node_bits_length +
					      loc->function_bits_length,
				      oif, act, &lctx);
	}

	if (attr)
		bgp_attr_unintern(&attr);
	if (!withdraw && ret == 0)
		bgp_mup_origin_mark_ready(bgp, BGP_MUP_ISD_ROUTE, args->afi, &args->prd,
					  &args->isd_prefix, NULL);
	return ret;
}

static enum seg6local_action_t bgp_mup_dsd_zebra_action(uint16_t behavior);

static int bgp_mup_emit_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
			    const struct in6_addr *sid, bool withdraw)
{
	struct prefix_mup p = {};
	struct attr *attr = NULL;
	struct srv6_locator *loc;
	uint8_t addr_octets;
	int ret;

	loc = bgp_srv6_locator_lookup(bgp, bgp_get_default());
	if (!loc)
		return -1;

	addr_octets = (args->afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_DSD_ROUTE;
	p.prefix.length = 8 + addr_octets;
	memcpy(p.prefix.rd, args->prd.val, 8);
	p.prefix.dsd_route.ip = args->dsd_endpoint;

	if (!withdraw)
		attr = bgp_mup_local_attr(bgp, sid, args->dsd_behavior, loc->block_bits_length,
					  loc->node_bits_length, loc->function_bits_length,
					  loc->argument_bits_length, args->ecom);
	ret = bgp_mup_originate_common(bgp, args->afi, &p, attr, withdraw);
	/* See comment in bgp_mup_emit_isd: cache the local DSD here so
	 * subsequent T2STs received from a MUP-Controller can resolve.
	 */
	{
		struct bgp *cache_bgp = (bgp->vrf_id == VRF_DEFAULT) ? bgp : bgp_get_default();

		if (!cache_bgp)
			cache_bgp = bgp;
		if (!withdraw) {
			bool has_seg = false;
			uint64_t seg_id = 0;

			if (attr)
				has_seg = bgp_mup_get_direct_seg_id(attr, &seg_id);
			bgp_mup_dsd_cache_upsert(cache_bgp, args->afi, &args->prd,
						 &args->dsd_endpoint, sid,
						 loc->block_bits_length, loc->node_bits_length,
						 loc->function_bits_length,
						 loc->argument_bits_length, args->dsd_behavior,
						 has_seg, seg_id);
		} else {
			bgp_mup_dsd_cache_remove(cache_bgp, args->afi, &args->prd,
						 &args->dsd_endpoint);
		}
	}

	/*
	 * Install the End.DT{4,6} seg6local action in the kernel at the
	 * allocated SID.  Mirrors bgpd/bgp_mplsvpn.c::vpn_leak_zebra_vrf_
	 * sid_update_per_af() — DSD is a per-VRF VPN segment, so the SID
	 * must terminate by decapsulating SRv6 and looking up the inner
	 * IP packet in the bgp's vrf table.
	 */
	{
		struct seg6local_context lctx = {};
		enum seg6local_action_t act;
		struct vrf *vrf = vrf_lookup_by_id(bgp->vrf_id);

		lctx.block_len = loc->block_bits_length;
		lctx.node_len = loc->node_bits_length;
		lctx.function_len = loc->function_bits_length;
		lctx.argument_len = loc->argument_bits_length;
		lctx.table = vrf ? vrf->data.l.table_id : RT_TABLE_MAIN;
		act = bgp_mup_dsd_zebra_action(args->dsd_behavior);
		if (act != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			/*
			 * Install at /loc_func, NOT /128: H.M.GTP4.D at the
			 * peer MUP-GW rewrites the SRv6 destination to
			 * encode the v4 source + Args.Mob.Session, so the
			 * decap-side End.DT* action must match the locator+
			 * function prefix range (not a single SID address).
			 * RFC 9433 Section 6.4 End.DT4 implementation is permissive
			 * about prefix length here.
			 *
			 * oif = per-vrf loopback so the End.DT* post-action IP
			 * lookup happens in the bgp instance's vrf table — the
			 * same hint L3VPN's vpn_leak_zebra_vrf_sid_update_per_af
			 * passes for its tovpn_sid install.
			 */
			uint16_t plen = loc->block_bits_length + loc->node_bits_length +
					loc->function_bits_length;
			struct interface *vrf_lo = if_get_vrf_loopback(bgp->vrf_id);
			ifindex_t oif = vrf_lo ? vrf_lo->ifindex : 0;

			zclient_send_localsid(bgp_zclient,
					      withdraw ? ZEBRA_ROUTE_DELETE
						       : ZEBRA_ROUTE_ADD,
					      sid, plen, oif, act, &lctx);
		}
	}

	if (attr)
		bgp_attr_unintern(&attr);
	if (!withdraw && ret == 0)
		bgp_mup_origin_mark_ready(bgp, BGP_MUP_DSD_ROUTE, args->afi, &args->prd, NULL,
					  &args->dsd_endpoint);
	return ret;
}

/* Public entry: originate ISD (sync if explicit SID, async otherwise). */
int bgp_mup_originate_isd(struct bgp *bgp, const struct bgp_mup_origin_args *args, bool withdraw)
{
	struct bgp_mup_pending *p;
	struct srv6_sid_ctx ctx = {};
	uint16_t behavior;

	if (args->afi != AFI_IP && args->afi != AFI_IP6)
		return -1;

	/* If the operator hasn't yet configured a locator, or zebra hasn't
	 * shipped chunks yet, accept the `segment` line silently — it gets
	 * persisted by the DEFPY caller and replayed by
	 * bgp_mup_replay_origins() once a locator becomes available.
	 */
	if (!bgp_srv6_locator_is_configured(bgp))
		return 0;
	if (!bgp_srv6_locator_lookup(bgp, bgp_get_default()))
		return 0;

	/* Explicit SID short-circuits the SID manager. */
	if (args->has_explicit_sid)
		return bgp_mup_emit_isd(bgp, args, &args->explicit_sid, withdraw);

	/* Auto-allocate via zebra's SRv6 SID manager.  Behavior per AFI. */
	behavior = (args->afi == AFI_IP) ? ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E
					 : ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP6_E;

	if (withdraw) {
		struct bgp_mup_pending *cancel =
			bgp_mup_pending_pop_for_withdraw(bgp, BGP_MUP_ISD_ROUTE, args);

		ctx.behavior = behavior;
		ctx.vrf_id = bgp->vrf_id;
		srv6_manager_release_sid(bgp_zclient, &ctx, bgp->srv6_locator_name, false);
		if (cancel) {
			/* Allocation never completed; nothing in the BGP RIB
			 * to withdraw.  Just release the request and free
			 * the pending record.
			 */
			bgp_mup_pending_free(cancel);
			return 0;
		}
		return bgp_mup_emit_isd(bgp, args, &in6addr_any, true);
	}

	p = XCALLOC(MTYPE_BGP_MUP_PENDING, sizeof(*p));
	p->route_type = BGP_MUP_ISD_ROUTE;
	p->args = *args;
	if (args->ecom)
		p->args.ecom = ecommunity_dup(args->ecom);
	p->ctx.behavior = behavior;
	p->ctx.vrf_id = bgp->vrf_id;
	bgp_mup_pending_list_add_tail(bgp_mup_get_pending_list(bgp), p);

	/* Dynamic SID alloc: pass a pointer to a zero in6_addr (matches
	 * L3VPN's tovpn_sid pattern in bgp_mplsvpn.c).  Passing NULL
	 * triggers undefined sid_zero_ipv6(NULL) inside zclient.
	 */
	srv6_manager_get_sid(bgp_zclient, &p->ctx, &(struct in6_addr){},
			     bgp->srv6_locator_name, NULL, false);
	return 0;
}

/* Public entry: originate DSD. */
int bgp_mup_originate_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args, bool withdraw)
{
	struct bgp_mup_pending *p;
	struct srv6_sid_ctx ctx = {};

	if (args->afi != AFI_IP && args->afi != AFI_IP6)
		return -1;
	switch (args->dsd_behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
		break;
	default:
		zlog_err("BGP-MUP: DSD behavior %u not supported", args->dsd_behavior);
		return -1;
	}

	/* See bgp_mup_originate_isd: defer silently when no locator is
	 * configured yet or chunks haven't arrived from zebra.
	 */
	if (!bgp_srv6_locator_is_configured(bgp))
		return 0;
	if (!bgp_srv6_locator_lookup(bgp, bgp_get_default()))
		return 0;

	if (args->has_explicit_sid)
		return bgp_mup_emit_dsd(bgp, args, &args->explicit_sid, withdraw);

	if (withdraw) {
		struct bgp_mup_pending *cancel;

		ctx.behavior = bgp_mup_dsd_zebra_action(args->dsd_behavior);
		ctx.vrf_id = bgp->vrf_id;

		cancel = bgp_mup_pending_pop_for_withdraw(bgp, BGP_MUP_DSD_ROUTE, args);
		srv6_manager_release_sid(bgp_zclient, &ctx, bgp->srv6_locator_name, false);
		if (cancel) {
			bgp_mup_pending_free(cancel);
			return 0;
		}
		return bgp_mup_emit_dsd(bgp, args, &in6addr_any, true);
	}

	p = XCALLOC(MTYPE_BGP_MUP_PENDING, sizeof(*p));
	p->route_type = BGP_MUP_DSD_ROUTE;
	p->args = *args;
	if (args->ecom)
		p->args.ecom = ecommunity_dup(args->ecom);
	p->ctx.behavior = bgp_mup_dsd_zebra_action(args->dsd_behavior);
	p->ctx.vrf_id = bgp->vrf_id;
	bgp_mup_pending_list_add_tail(bgp_mup_get_pending_list(bgp), p);

	/* Dynamic SID alloc: pass a pointer to a zero in6_addr (matches
	 * L3VPN's tovpn_sid pattern in bgp_mplsvpn.c).  Passing NULL
	 * triggers undefined sid_zero_ipv6(NULL) inside zclient.
	 */
	srv6_manager_get_sid(bgp_zclient, &p->ctx, &(struct in6_addr){},
			     bgp->srv6_locator_name, NULL, false);
	return 0;
}

/* SID Manager async completion (called from bgp_zebra.c).
 *
 * Returns true when a pending MUP request matched this ctx and was
 * dispatched.  Returns false when no pending exists, allowing the
 * caller (bgp_zebra_srv6_sid_notify) to fall through to other handlers
 * such as the VPN one (DT4/DT6 behaviors are shared with VPN).
 */
bool bgp_mup_handle_sid_alloc(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
			      const struct in6_addr *sid_value)
{
	struct bgp_mup_pending *p = bgp_mup_pending_pop(bgp, ctx);

	if (!p)
		return false;

	if (p->route_type == BGP_MUP_ISD_ROUTE)
		(void)bgp_mup_emit_isd(bgp, &p->args, sid_value, false);
	else
		(void)bgp_mup_emit_dsd(bgp, &p->args, sid_value, false);

	bgp_mup_pending_free(p);
	return true;
}

/* ---------------------------------------------------------------------- */
/* VTY: `mup-route isd|dsd ...` under `address-family ipv4|ipv6 mup`.     */
/* ---------------------------------------------------------------------- */

#include "bgpd/bgp_vty.h"
#include "lib/command.h"

#include "bgpd/bgp_mup_clippy.c"

/* DSD `behavior <kw>` keyword ↔ RFC 8986 SRv6 endpoint behavior code.
 * Always operator-driven per draft-ietf-bess-mup-safi §3.3.4 (function
 * MAY be End.DT4/6 or End.DX4/6, picked by inner PDU lookup AFI which
 * is independent of the DSD's Address AFI).
 */
static const struct {
	const char *kw;
	uint16_t code;
} mup_dsd_behaviors[] = {
	{"dt4",  SRV6_ENDPOINT_BEHAVIOR_END_DT4},
	{"dt6",  SRV6_ENDPOINT_BEHAVIOR_END_DT6},
	{"dt46", SRV6_ENDPOINT_BEHAVIOR_END_DT46},
};

static uint16_t mup_dsd_behavior_keyword2code(const char *keyword)
{
	size_t i;

	if (!keyword)
		return 0;
	for (i = 0; i < array_size(mup_dsd_behaviors); i++)
		if (strcmp(keyword, mup_dsd_behaviors[i].kw) == 0)
			return mup_dsd_behaviors[i].code;
	return 0;
}

static const char *mup_dsd_behavior_code2keyword(uint16_t code)
{
	size_t i;

	for (i = 0; i < array_size(mup_dsd_behaviors); i++)
		if (mup_dsd_behaviors[i].code == code)
			return mup_dsd_behaviors[i].kw;
	return NULL;
}

/* Map an SRv6 endpoint behavior code to its zebra seg6local action.
 * Used both at install time (DSD origination) and at the SID-manager
 * release path; centralises the handful of behaviors BGP-MUP DSD
 * supports (End.DT4 / End.DT6 / End.DT46).
 */
static enum seg6local_action_t bgp_mup_dsd_zebra_action(uint16_t behavior)
{
	switch (behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
	default:
		return ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	}
}

/* Common parse for `rd <rd> rt <rt>`. */
static int mup_route_common_args(struct vty *vty, const char *rd_str, const char *rt_str,
				 struct prefix_rd *prd, struct ecommunity **rt)
{
	if (str2prefix_rd(rd_str, prd) == 0) {
		vty_out(vty, "%% Malformed RD\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	*rt = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!*rt) {
		vty_out(vty, "%% Malformed RT \"%s\"\n", rt_str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* `segment interwork PREFIX rd RD rt RT [sid explicit X:X::X:X]`
 *
 * Per draft Section 3.3.1 the prefix-SID's endpoint behavior is mandated by the
 * AFI (End.M.GTP4.E for IPv4, End.M.GTP6.E for IPv6) so it's not part
 * of the CLI.  By default the function bits are auto-allocated by
 * zebra's SRv6 SID manager under the BGP instance's configured locator
 * (mirrors `sid vpn export auto`).  `sid explicit X:X::X:X` is the
 * escape hatch for inter-AS / migration scenarios where the operator
 * needs to pin a specific SID value.
 */
DEFPY(bgp_mup_segment_interwork,
      bgp_mup_segment_interwork_cmd,
      "[no] segment interwork <A.B.C.D/M$v4_pfx|X:X::X:X/M$v6_pfx>"
      " rd ASN:NN_OR_IP-ADDRESS:NN$rd_str"
      " rt WORD$rt_str"
      " [sid explicit X:X::X:X$sid_explicit]",
      NO_STR
      "BGP-MUP segment to originate (draft-ietf-bess-mup-safi)\n"
      "Interwork Segment Discovery route (matches a prefix of UEs)\n"
      "IPv4 interwork prefix\n"
      "IPv6 interwork prefix\n"
      "Route Distinguisher\n"
      "RD value (ASN:NN or IP:NN)\n"
      "Route Target extended community (e.g. \"65000:1\")\n"
      "RT specification\n"
      "Pin a specific SID instead of auto-allocating from the locator\n"
      "Specify the SID value explicitly\n"
      "IPv6 SID address\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_mup_origin_args args = {};
	struct ecommunity *rt = NULL;
	bool withdraw = (no != NULL);
	int rv, idx;

	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% segment interwork must be configured under a non-default vrf bgp instance (`router bgp ASN vrf NAME`); the default-vrf instance only carries the BGP-MUP session\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (v4_pfx_str) {
		args.afi = AFI_IP;
		(void)str2prefix(v4_pfx_str, &args.isd_prefix);
	} else {
		args.afi = AFI_IP6;
		(void)str2prefix(v6_pfx_str, &args.isd_prefix);
	}
	apply_mask(&args.isd_prefix);

	idx = mup_route_common_args(vty, rd_str, rt_str, &args.prd, &rt);
	if (idx != CMD_SUCCESS)
		return idx;
	args.ecom = rt;

	if (sid_explicit_str) {
		args.has_explicit_sid = true;
		args.explicit_sid = sid_explicit;
	}

	rv = bgp_mup_originate_isd(bgp, &args, withdraw);
	if (rv == 0) {
		if (withdraw)
			bgp_mup_origin_forget(bgp, BGP_MUP_ISD_ROUTE, args.afi, &args.prd,
					      &args.isd_prefix, NULL);
		else
			bgp_mup_origin_persist_isd(bgp, &args, rt_str);
	}

	ecommunity_free(&rt);
	return rv ? CMD_WARNING_CONFIG_FAILED : CMD_SUCCESS;
}

/* `segment direct <ADDR> rd RD rt RT mup MUP
 *  behavior <dt4|dt6|dt46> [sid explicit X:X::X:X]`
 *
 * <ADDR> is the DSD NLRI's Address field per draft-ietf-bess-mup-safi
 * §3.1.2 (the address of the originating BGP speaker; in 3GPP 5G
 * architecture this is typically the UPF host's IP).  `behavior`
 * picks the prefix-SID's End.DT* function — it reflects the inner
 * PDU lookup AFI (PDU session type), which is independent of the
 * Address AFI per draft §3.3.4, so the operator MUST declare it
 * explicitly.  Function bits auto-allocate from the locator by
 * default; `sid explicit` pins a specific value (inter-AS / migration
 * escape hatch).
 */
DEFPY(bgp_mup_segment_direct,
      bgp_mup_segment_direct_cmd,
      "[no] segment direct <A.B.C.D$v4_addr|X:X::X:X$v6_addr>"
      " rd ASN:NN_OR_IP-ADDRESS:NN$rd_str"
      " rt WORD$rt_str"
      " mup ASN:NN$mup_str"
      " behavior <dt4|dt6|dt46>$behavior"
      " [sid explicit X:X::X:X$sid_explicit]",
      NO_STR
      "BGP-MUP segment to originate\n"
      "Direct Segment Discovery route (single Address per draft-ietf-bess-mup-safi §3.1.2)\n"
      "IPv4 originating-speaker address\n"
      "IPv6 originating-speaker address\n"
      "Route Distinguisher\n"
      "RD value\n"
      "Route Target extended community\n"
      "RT (e.g. \"65000:1\")\n"
      "MUP extended community\n"
      "MUP segment identifier (ASN:NN)\n"
      "SRv6 endpoint behavior (selects the inner PDU lookup AFI; independent of the Address AFI)\n"
      "End.DT4 — decap and lookup in the IPv4 table\n"
      "End.DT6 — decap and lookup in the IPv6 table\n"
      "End.DT46 — decap and lookup in either IPv4 or IPv6 table (unified)\n"
      "Pin a specific SID instead of auto-allocating from the locator\n"
      "Specify the SID value explicitly\n"
      "IPv6 SID address\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_mup_origin_args args = {};
	struct ecommunity *rt = NULL, *mup_ec = NULL, *ecom = NULL;
	uint16_t bcode = 0;
	bool withdraw = (no != NULL);
	int rv, idx;

	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% segment direct must be configured under a non-default vrf bgp instance (`router bgp ASN vrf NAME`); End.DT4/DT6 are vrf-mandatory per RFC 8986 §4.7-§4.8\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (v4_addr_str) {
		args.afi = AFI_IP;
		args.dsd_endpoint.ipa_type = IPADDR_V4;
		if (inet_pton(AF_INET, v4_addr_str, &args.dsd_endpoint.ipaddr_v4) != 1) {
			vty_out(vty, "%% Bad IPv4 address\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		args.afi = AFI_IP6;
		args.dsd_endpoint.ipa_type = IPADDR_V6;
		if (inet_pton(AF_INET6, v6_addr_str, &args.dsd_endpoint.ipaddr_v6) != 1) {
			vty_out(vty, "%% Bad IPv6 address\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	idx = mup_route_common_args(vty, rd_str, rt_str, &args.prd, &rt);
	if (idx != CMD_SUCCESS)
		return idx;

	bcode = mup_dsd_behavior_keyword2code(behavior);
	if (bcode == 0) {
		vty_out(vty, "%% Unknown DSD behavior \"%s\"\n", behavior);
		ecommunity_free(&rt);
		return CMD_WARNING_CONFIG_FAILED;
	}
	args.dsd_behavior = bcode;

	mup_ec = bgp_mup_build_mup_ec(mup_str);
	if (!mup_ec) {
		vty_out(vty, "%% Malformed MUP segment identifier \"%s\"\n", mup_str);
		ecommunity_free(&rt);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ecom = ecommunity_dup(rt);
	ecommunity_merge(ecom, mup_ec);
	args.ecom = ecom;

	if (sid_explicit_str) {
		args.has_explicit_sid = true;
		args.explicit_sid = sid_explicit;
	}

	rv = bgp_mup_originate_dsd(bgp, &args, withdraw);
	if (rv == 0) {
		if (withdraw)
			bgp_mup_origin_forget(bgp, BGP_MUP_DSD_ROUTE, args.afi, &args.prd, NULL,
					      &args.dsd_endpoint);
		else
			bgp_mup_origin_persist_dsd(bgp, &args, rt_str, mup_str);
	}

	ecommunity_free(&rt);
	ecommunity_free(&mup_ec);
	ecommunity_free(&ecom);
	return rv ? CMD_WARNING_CONFIG_FAILED : CMD_SUCCESS;
}

/* Emit the persisted `segment ...` lines for a given AFI under
 * `address-family ipv4|ipv6 mup`.  Called from bgp_vty.c.
 */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_origin *o;
	char rd_buf[RD_ADDRSTRLEN];

	if (!bgp->mup_origins)
		return;

	frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
		if (o->afi != afi)
			continue;

		prefix_rd2str(&o->prd, rd_buf, sizeof(rd_buf), bgp->asnotation);

		if (o->route_type == BGP_MUP_ISD_ROUTE) {
			vty_out(vty, "  segment interwork %pFX rd %s rt %s", &o->isd_prefix,
				rd_buf, o->rt_str);
		} else {
			const char *bkw = mup_dsd_behavior_code2keyword(o->dsd_behavior);

			if (!bkw)
				continue; /* defensive: unknown behavior */
			if (o->dsd_endpoint.ipa_type == IPADDR_V4)
				vty_out(vty, "  segment direct %pI4 rd %s rt %s mup %s behavior %s",
					&o->dsd_endpoint.ipaddr_v4, rd_buf, o->rt_str,
					o->mup_str, bkw);
			else
				vty_out(vty, "  segment direct %pI6 rd %s rt %s mup %s behavior %s",
					&o->dsd_endpoint.ipaddr_v6, rd_buf, o->rt_str,
					o->mup_str, bkw);
		}

		if (o->has_explicit_sid)
			vty_out(vty, " sid explicit %pI6", &o->explicit_sid);
		vty_out(vty, "\n");
	}
}

/* Replay one persisted origin against the SID manager.  Used after a
 * locator chunk arrives for origins that were configured before zebra
 * had any SRv6 state (config-file boot order).  Rebuilds the
 * ecommunity from the saved rt_str / mup_str so the persistent record
 * stays the single source of truth.
 */
static void bgp_mup_replay_origin(struct bgp *bgp, struct bgp_mup_origin *o)
{
	struct bgp_mup_origin_args args = {};
	struct ecommunity *rt = NULL, *mup_ec = NULL, *ecom = NULL;

	args.afi = o->afi;
	args.prd = o->prd;
	args.has_explicit_sid = o->has_explicit_sid;
	args.explicit_sid = o->explicit_sid;

	rt = ecommunity_str2com(o->rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!rt)
		return;

	if (o->route_type == BGP_MUP_ISD_ROUTE) {
		args.isd_prefix = o->isd_prefix;
		args.ecom = rt;
		(void)bgp_mup_originate_isd(bgp, &args, false);
		ecommunity_free(&rt);
		return;
	}

	args.dsd_endpoint = o->dsd_endpoint;
	args.dsd_behavior = o->dsd_behavior;
	mup_ec = bgp_mup_build_mup_ec(o->mup_str);
	if (!mup_ec) {
		ecommunity_free(&rt);
		return;
	}
	ecom = ecommunity_dup(rt);
	ecommunity_merge(ecom, mup_ec);
	args.ecom = ecom;
	(void)bgp_mup_originate_dsd(bgp, &args, false);
	ecommunity_free(&rt);
	ecommunity_free(&mup_ec);
	ecommunity_free(&ecom);
}

/* Locator-arrival hook: called from zebra/bgpd after `bgp->srv6_locator`
 * is populated.  Walks every per-vrf bgp instance's origin list and
 * replays anything not yet bound to a SID.  Same role as L3VPN's
 * vpn_leak_postchange_all() running after a chunk arrives.
 */
void bgp_mup_replay_origins_all(void)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_mup_origin *o;

		if (!bgp->mup_origins)
			continue;
		if (!bgp_srv6_locator_lookup(bgp, bgp_get_default()))
			continue;
		frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
			if (o->sid_ready)
				continue;
			bgp_mup_replay_origin(bgp, o);
		}
	}
}

void bgp_mup_vty_init(void)
{
	install_element(BGP_IPV4_MUP_NODE, &bgp_mup_segment_interwork_cmd);
	install_element(BGP_IPV4_MUP_NODE, &bgp_mup_segment_direct_cmd);
	install_element(BGP_IPV6_MUP_NODE, &bgp_mup_segment_interwork_cmd);
	install_element(BGP_IPV6_MUP_NODE, &bgp_mup_segment_direct_cmd);
}
