// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */

#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "typesafe.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_attr_srv6.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_mup.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_zebra.h"
#include "lib/srv6.h"
#include "lib/zclient.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_ISD, "BGP MUP ISD entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_DSD, "BGP MUP DSD entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_LIST, "BGP MUP list head");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_IFACE_CACHE, "BGP MUP iface cache entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_EXPORT, "BGP MUP per-vrf-per-afi export policy");

/* Direction-indexed RT slots on the per-(vrf, afi) MUP export policy.
 * Mirrors bgp_mplsvpn.c's BGP_VPN_POLICY_DIR_FROMVPN / DIR_TOVPN.
 */
enum bgp_mup_policy_dir {
	BGP_MUP_POLICY_DIR_FROMMUP = 0,
	BGP_MUP_POLICY_DIR_TOMUP = 1,
	BGP_MUP_POLICY_DIR_MAX = 2,
};

/* Per-(vrf, afi) MUP policy.  Carries the import/export RT lists and the
 * SR-underlay VRF table id used by both the install path (post-action
 * lookup for End.M.GTP6.D{,Di} / H.M.GTP4.D) and the originate path
 * (post-action lookup for End.M.GTP4.E / End.M.GTP6.E local SIDs).
 * Later commits grow the struct with RD, SID, segment, and scalar-DSD
 * knobs as the originate path lands.  Mirrors L3VPN's vpn_policy[afi]
 * one slot at a time so a vrf doing both L3VPN and MUP can keep the two
 * policies independent.
 */
struct bgp_mup_export_policy {
	struct ecommunity *rtlist[BGP_MUP_POLICY_DIR_MAX];
	/* SEG6_MOBILE_VRFTABLE for both directions of the post-action FIB
	 * lookup.  0 = unset; mandatory before any T1ST/T2ST or local-SID
	 * install can proceed (kernel rejects without strict_mode +
	 * VRF-bound table, so there is no useful default).  Configured via
	 * `segment vrftable TABLEID` under `address-family ipv[46] mup`.
	 */
	uint32_t vrftable;
};

static struct bgp_mup_export_policy *bgp_mup_export_get(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	if (bgp->mup_export[afi])
		return bgp->mup_export[afi];
	bgp->mup_export[afi] = XCALLOC(MTYPE_BGP_MUP_EXPORT, sizeof(*bgp->mup_export[afi]));
	return bgp->mup_export[afi];
}

static struct bgp_mup_export_policy *bgp_mup_export_peek(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	return bgp->mup_export[afi];
}

void bgp_mup_export_clear(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *p;
	enum bgp_mup_policy_dir dir;

	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	p = bgp->mup_export[afi];
	if (!p)
		return;
	for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
		if (p->rtlist[dir])
			ecommunity_free(&p->rtlist[dir]);
	}
	XFREE(MTYPE_BGP_MUP_EXPORT, bgp->mup_export[afi]);
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
		teid_bits = (mp->t2st_route.endpoint_address_length > addr_octets * 8)
				    ? mp->t2st_route.endpoint_address_length - (addr_octets * 8)
				    : 0;
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

/*
 * NLRI parsing (draft-ietf-bess-mup-safi section 3.1.x).
 *
 * On parse error we emit EC_BGP_MUP_ROUTE_INVALID and treat the route as
 * withdraw per RFC 7606.
 */

/* Initialise the BGP-side prefix wrapper for a BGP-MUP NLRI of the
 * given route type.  Used by every NLRI parser and origin emitter to
 * keep the family / arch_type / prefixlen / length boilerplate in one
 * place.
 */
static inline void bgp_mup_prefix_init(struct prefix_mup *p, uint16_t route_type, int psize)
{
	p->family = AF_MUP;
	p->prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p->prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p->prefix.route_type = route_type;
	p->prefix.length = psize;
}

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

	/* Decode RD. */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);

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

	bgp_mup_prefix_init(&p, BGP_MUP_ISD_ROUTE, psize);
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

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);

	bgp_mup_prefix_init(&p, BGP_MUP_DSD_ROUTE, psize);
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

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);
	off = 8;

	prefix_len = pfx[off++];
	if ((afi == AFI_IP && prefix_len > 32) || (afi == AFI_IP6 && prefix_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI bad prefix length %u", peer->bgp->vrf_id,
			 peer->host, prefix_len);
		return -1;
	}
	prefix_octets = PSIZE(prefix_len);

	bgp_mup_prefix_init(&p, BGP_MUP_T1ST_ROUTE, psize);
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
	if (ext->teid == 0) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI TEID=0 (draft Section 3.1.3.1: treat-as-withdraw)",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	ext->qfi = pfx[off++];
	ep_len = pfx[off++];
	if ((afi == AFI_IP && ep_len > 32) || (afi == AFI_IP6 && ep_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI endpoint length %u exceeds AFI %u maximum",
			 peer->bgp->vrf_id, peer->host, ep_len, afi);
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
	ext->endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ext->endpoint_address.ip.addr, pfx + off, ep_octets);
	off += ep_octets;

	src_len = pfx[off++];
	if ((afi == AFI_IP && src_len > 32) || (afi == AFI_IP6 && src_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI source length %u exceeds AFI %u maximum",
			 peer->bgp->vrf_id, peer->host, src_len, afi);
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
		ext->source_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
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

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);

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

	bgp_mup_prefix_init(&p, BGP_MUP_T2ST_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.t2st_route.endpoint_address_length = ea_len;
	p.prefix.t2st_route.endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.t2st_route.endpoint_address.ip.addr, pfx + 9, addr_octets);
	if (teid_octets) {
		memcpy(&teid_be, pfx + 9 + addr_octets, teid_octets);
		p.prefix.t2st_route.teid = ntohl(teid_be);
	}
	if (p.prefix.t2st_route.teid == 0) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI TEID=0 (draft Section 3.1.4.1: treat-as-withdraw)",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

/*
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
 */

PREDECL_DLIST(bgp_mup_isd_lpm_chain);

struct bgp_mup_isd_entry {
	struct bgp_mup_isd_hash_item hash_item;
	struct bgp_mup_isd_lpm_chain_item lpm_item;
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

static int bgp_mup_isd_hash_cmp(const struct bgp_mup_isd_entry *a,
				const struct bgp_mup_isd_entry *b)
{
	int r;

	if (a->afi != b->afi)
		return (a->afi < b->afi) ? -1 : 1;
	r = memcmp(a->prd.val, b->prd.val, sizeof(a->prd.val));
	if (r != 0)
		return r;
	if (prefix_same(&a->prefix, &b->prefix))
		return 0;
	return memcmp(&a->prefix, &b->prefix, sizeof(a->prefix));
}

static uint32_t bgp_mup_isd_hash_hash(const struct bgp_mup_isd_entry *e)
{
	uint32_t h = jhash_1word(e->afi, 0xb6709a6c);

	h = jhash(e->prd.val, sizeof(e->prd.val), h);
	return jhash(&e->prefix, sizeof(e->prefix), h);
}

DECLARE_HASH(bgp_mup_isd_hash, struct bgp_mup_isd_entry, hash_item,
	     bgp_mup_isd_hash_cmp, bgp_mup_isd_hash_hash);
DECLARE_DLIST(bgp_mup_isd_lpm_chain, struct bgp_mup_isd_entry, lpm_item);

struct bgp_mup_dsd_entry {
	struct bgp_mup_dsd_hash_item hash_item;
	struct bgp_mup_dsd_segid_hash_item segid_item;
	bool segid_linked; /* in mup_dsd_segid_hash iff true */
	afi_t afi;
	struct prefix_rd prd;
	struct ipaddr endpoint; /* Originating PE address (DSD NLRI) */
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint16_t behavior; /* End.DT4 / End.DT6 */
	bool has_segment_id;
	uint64_t segment_id; /* MUP-EC Direct-Type Segment Identifier (48 bits) */
};

static int bgp_mup_dsd_hash_cmp(const struct bgp_mup_dsd_entry *a,
				const struct bgp_mup_dsd_entry *b)
{
	int r;

	if (a->afi != b->afi)
		return (a->afi < b->afi) ? -1 : 1;
	r = memcmp(a->prd.val, b->prd.val, sizeof(a->prd.val));
	if (r != 0)
		return r;
	if (ipaddr_is_same(&a->endpoint, &b->endpoint))
		return 0;
	return memcmp(&a->endpoint, &b->endpoint, sizeof(a->endpoint));
}

static uint32_t bgp_mup_dsd_hash_hash(const struct bgp_mup_dsd_entry *e)
{
	uint32_t h = jhash_1word(e->afi, 0xc0a5d5d5);

	h = jhash(e->prd.val, sizeof(e->prd.val), h);
	return jhash(&e->endpoint, sizeof(e->endpoint), h);
}

DECLARE_HASH(bgp_mup_dsd_hash, struct bgp_mup_dsd_entry, hash_item,
	     bgp_mup_dsd_hash_cmp, bgp_mup_dsd_hash_hash);

static int bgp_mup_dsd_segid_hash_cmp(const struct bgp_mup_dsd_entry *a,
				      const struct bgp_mup_dsd_entry *b)
{
	if (a->segment_id == b->segment_id)
		return 0;
	return (a->segment_id < b->segment_id) ? -1 : 1;
}

static uint32_t bgp_mup_dsd_segid_hash_hash(const struct bgp_mup_dsd_entry *e)
{
	return jhash_2words((uint32_t)(e->segment_id >> 32),
			    (uint32_t)e->segment_id, 0xd5d5dead);
}

DECLARE_HASH(bgp_mup_dsd_segid_hash, struct bgp_mup_dsd_entry, segid_item,
	     bgp_mup_dsd_segid_hash_cmp, bgp_mup_dsd_segid_hash_hash);

static struct bgp_mup_isd_hash_head *bgp_mup_get_isd_hash(struct bgp *bgp)
{
	if (!bgp->mup_isd_hash) {
		bgp->mup_isd_hash = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_isd_hash));
		bgp_mup_isd_hash_init(bgp->mup_isd_hash);
	}
	return bgp->mup_isd_hash;
}

static struct route_table *bgp_mup_get_isd_lpm(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	if (!bgp->mup_isd_lpm[afi])
		bgp->mup_isd_lpm[afi] = route_table_init();
	return bgp->mup_isd_lpm[afi];
}

static struct bgp_mup_dsd_hash_head *bgp_mup_get_dsd_hash(struct bgp *bgp)
{
	if (!bgp->mup_dsd_hash) {
		bgp->mup_dsd_hash = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_dsd_hash));
		bgp_mup_dsd_hash_init(bgp->mup_dsd_hash);
	}
	return bgp->mup_dsd_hash;
}

static struct bgp_mup_dsd_segid_hash_head *bgp_mup_get_dsd_segid_hash(struct bgp *bgp)
{
	if (!bgp->mup_dsd_segid_hash) {
		bgp->mup_dsd_segid_hash = XCALLOC(MTYPE_BGP_MUP_LIST,
						  sizeof(*bgp->mup_dsd_segid_hash));
		bgp_mup_dsd_segid_hash_init(bgp->mup_dsd_segid_hash);
	}
	return bgp->mup_dsd_segid_hash;
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

static struct bgp_mup_isd_entry *bgp_mup_isd_find(struct bgp *bgp, afi_t afi,
						  const struct prefix_rd *prd,
						  const struct prefix *prefix)
{
	struct bgp_mup_isd_entry needle = {};

	if (!bgp->mup_isd_hash)
		return NULL;
	needle.afi = afi;
	needle.prd = *prd;
	needle.prefix = *prefix;
	return bgp_mup_isd_hash_find(bgp->mup_isd_hash, &needle);
}

/* Longest-prefix-match an ISD covering the given endpoint address via the
 * per-AFI route_table.  Per the draft the receiving PE has already imported
 * routes by RT, so all entries in the cache are eligible; if multiple ISDs
 * share the same prefix from different RDs, the chain head (insertion order)
 * is returned, matching the prior linked-list behavior.
 */
static struct bgp_mup_isd_entry *bgp_mup_isd_lookup(struct bgp *bgp, afi_t afi,
						    const struct ipaddr *endpoint)
{
	struct route_table *table = (afi == AFI_IP || afi == AFI_IP6)
					    ? bgp->mup_isd_lpm[afi]
					    : NULL;
	struct bgp_mup_isd_lpm_chain_head *chain;
	struct bgp_mup_isd_entry *best = NULL;
	struct route_node *rn;
	struct prefix needle = {};

	if (!table)
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

	rn = route_node_match(table, &needle);
	if (!rn)
		return NULL;
	chain = rn->info;
	if (chain)
		best = bgp_mup_isd_lpm_chain_first(chain);
	route_unlock_node(rn);
	return best;
}

static struct bgp_mup_dsd_entry *bgp_mup_dsd_find_key(struct bgp *bgp, afi_t afi,
						      const struct prefix_rd *prd,
						      const struct ipaddr *endpoint)
{
	struct bgp_mup_dsd_entry needle = {};

	if (!bgp->mup_dsd_hash)
		return NULL;
	needle.afi = afi;
	needle.prd = *prd;
	needle.endpoint = *endpoint;
	return bgp_mup_dsd_hash_find(bgp->mup_dsd_hash, &needle);
}

/* Lookup a DSD by MUP-EC Direct-Type Segment Identifier. */
static struct bgp_mup_dsd_entry *bgp_mup_dsd_lookup(struct bgp *bgp, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry needle = {};

	if (!bgp->mup_dsd_segid_hash)
		return NULL;
	needle.segment_id = segment_id;
	return bgp_mup_dsd_segid_hash_find(bgp->mup_dsd_segid_hash, &needle);
}

/* Coalesce reannounce of T1ST/T2ST paths after an ISD/DSD cache mutation.
 * Scheduling is per (bgp, afi); a flood of cache mutations within a
 * single UPDATE collapses to one RIB walk on the next event_loop pass.
 */
static void bgp_mup_schedule_reannounce_st_routes(struct bgp *bgp, afi_t afi);

/* Insert e into the per-AFI LPM tree.  Multiple ISDs with the same
 * (afi, prefix) but different RDs share a single route_node and chain
 * through e->lpm_item; head-of-chain is returned by route_node_match,
 * preserving "first inserted wins" for equal-length matches.
 */
static void bgp_mup_isd_lpm_link(struct bgp *bgp, struct bgp_mup_isd_entry *e)
{
	struct route_table *table = bgp_mup_get_isd_lpm(bgp, e->afi);
	struct bgp_mup_isd_lpm_chain_head *chain;
	struct route_node *rn;

	if (!table)
		return;
	rn = route_node_get(table, &e->prefix);
	chain = rn->info;
	if (!chain) {
		chain = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*chain));
		bgp_mup_isd_lpm_chain_init(chain);
		route_node_set_info(rn, chain);
	} else {
		/* route_node_get bumped lock; chain already holds one */
		route_unlock_node(rn);
	}
	bgp_mup_isd_lpm_chain_add_tail(chain, e);
}

static void bgp_mup_isd_lpm_unlink(struct bgp *bgp, struct bgp_mup_isd_entry *e)
{
	struct route_table *table = (e->afi == AFI_IP || e->afi == AFI_IP6)
					    ? bgp->mup_isd_lpm[e->afi]
					    : NULL;
	struct bgp_mup_isd_lpm_chain_head *chain;
	struct route_node *rn;

	if (!table)
		return;
	rn = route_node_lookup(table, &e->prefix);
	if (!rn)
		return;
	chain = rn->info;
	if (chain)
		bgp_mup_isd_lpm_chain_del(chain, e);
	if (chain && bgp_mup_isd_lpm_chain_count(chain) == 0) {
		bgp_mup_isd_lpm_chain_fini(chain);
		XFREE(MTYPE_BGP_MUP_LIST, chain);
		route_node_set_info(rn, NULL);
		route_unlock_node(rn); /* drop the lock held while info was set */
	}
	route_unlock_node(rn); /* drop the lock from this lookup */
}

static void bgp_mup_isd_cache_upsert(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct prefix *prefix, const struct in6_addr *sid,
				     uint8_t block, uint8_t node, uint8_t func, uint8_t arg,
				     uint16_t behavior)
{
	struct bgp_mup_isd_entry *e = bgp_mup_isd_find(bgp, afi, prd, prefix);
	bool changed = false;

	if (!e) {
		e = XCALLOC(MTYPE_BGP_MUP_ISD, sizeof(*e));
		e->afi = afi;
		e->prd = *prd;
		e->prefix = *prefix;
		bgp_mup_isd_hash_add(bgp_mup_get_isd_hash(bgp), e);
		bgp_mup_isd_lpm_link(bgp, e);
		changed = true;
	} else if (memcmp(&e->sid, sid, sizeof(*sid)) != 0 || e->loc_block_len != block ||
		   e->loc_node_len != node || e->func_len != func || e->arg_len != arg ||
		   e->behavior != behavior) {
		changed = true;
	}
	e->sid = *sid;
	e->loc_block_len = block;
	e->loc_node_len = node;
	e->func_len = func;
	e->arg_len = arg;
	e->behavior = behavior;
	if (changed)
		bgp_mup_schedule_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_isd_cache_remove(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct prefix *prefix)
{
	struct bgp_mup_isd_entry *e = bgp_mup_isd_find(bgp, afi, prd, prefix);

	if (!e)
		return;
	bgp_mup_isd_lpm_unlink(bgp, e);
	bgp_mup_isd_hash_del(bgp->mup_isd_hash, e);
	XFREE(MTYPE_BGP_MUP_ISD, e);
	bgp_mup_schedule_reannounce_st_routes(bgp, afi);
}

/* Maintain the segment_id index alongside the (prd, endpoint) hash.
 * If two DSDs claim the same segment_id, the second link is refused so
 * lookup keeps "first inserter wins" semantics, matching the prior
 * linear-scan behavior.
 */
static void bgp_mup_dsd_segid_link(struct bgp *bgp, struct bgp_mup_dsd_entry *e)
{
	struct bgp_mup_dsd_entry *prev;

	if (!e->has_segment_id || e->segid_linked)
		return;
	prev = bgp_mup_dsd_segid_hash_add(bgp_mup_get_dsd_segid_hash(bgp), e);
	if (prev) {
		zlog_warn("BGP-MUP: duplicate DSD segment-id %" PRIu64
			  " — keeping first-bound entry",
			  e->segment_id);
		return;
	}
	e->segid_linked = true;
}

static void bgp_mup_dsd_segid_unlink(struct bgp *bgp, struct bgp_mup_dsd_entry *e)
{
	if (!e->segid_linked)
		return;
	bgp_mup_dsd_segid_hash_del(bgp->mup_dsd_segid_hash, e);
	e->segid_linked = false;
}

static void bgp_mup_dsd_cache_upsert(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct ipaddr *endpoint, const struct in6_addr *sid,
				     uint8_t block, uint8_t node, uint8_t func, uint8_t arg,
				     uint16_t behavior, bool has_segment_id, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry *e = bgp_mup_dsd_find_key(bgp, afi, prd, endpoint);
	bool changed = false;

	if (!e) {
		e = XCALLOC(MTYPE_BGP_MUP_DSD, sizeof(*e));
		e->afi = afi;
		e->prd = *prd;
		e->endpoint = *endpoint;
		bgp_mup_dsd_hash_add(bgp_mup_get_dsd_hash(bgp), e);
		changed = true;
	} else if (memcmp(&e->sid, sid, sizeof(*sid)) != 0 || e->loc_block_len != block ||
		   e->loc_node_len != node || e->func_len != func || e->arg_len != arg ||
		   e->behavior != behavior || e->has_segment_id != has_segment_id ||
		   e->segment_id != segment_id) {
		changed = true;
	}
	if (e->segid_linked &&
	    (!has_segment_id || e->segment_id != segment_id))
		bgp_mup_dsd_segid_unlink(bgp, e);
	e->sid = *sid;
	e->loc_block_len = block;
	e->loc_node_len = node;
	e->func_len = func;
	e->arg_len = arg;
	e->behavior = behavior;
	e->has_segment_id = has_segment_id;
	e->segment_id = segment_id;
	if (has_segment_id && !e->segid_linked)
		bgp_mup_dsd_segid_link(bgp, e);
	if (changed)
		bgp_mup_schedule_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_dsd_cache_remove(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct ipaddr *endpoint)
{
	struct bgp_mup_dsd_entry *e = bgp_mup_dsd_find_key(bgp, afi, prd, endpoint);

	if (!e)
		return;
	bgp_mup_dsd_segid_unlink(bgp, e);
	bgp_mup_dsd_hash_del(bgp->mup_dsd_hash, e);
	XFREE(MTYPE_BGP_MUP_DSD, e);
	bgp_mup_schedule_reannounce_st_routes(bgp, afi);
}

void bgp_mup_caches_free(struct bgp *bgp)
{
	struct bgp_mup_isd_entry *isd;
	struct bgp_mup_dsd_entry *dsd;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		event_cancel(&bgp->mup_reannounce_ev[afi]);

	if (bgp->mup_isd_hash) {
		while ((isd = bgp_mup_isd_hash_pop(bgp->mup_isd_hash))) {
			bgp_mup_isd_lpm_unlink(bgp, isd);
			XFREE(MTYPE_BGP_MUP_ISD, isd);
		}
		bgp_mup_isd_hash_fini(bgp->mup_isd_hash);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_isd_hash);
	}
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (bgp->mup_isd_lpm[afi]) {
			route_table_finish(bgp->mup_isd_lpm[afi]);
			bgp->mup_isd_lpm[afi] = NULL;
		}
	}
	if (bgp->mup_dsd_hash) {
		while ((dsd = bgp_mup_dsd_hash_pop(bgp->mup_dsd_hash))) {
			bgp_mup_dsd_segid_unlink(bgp, dsd);
			XFREE(MTYPE_BGP_MUP_DSD, dsd);
		}
		bgp_mup_dsd_hash_fini(bgp->mup_dsd_hash);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_dsd_hash);
	}
	if (bgp->mup_dsd_segid_hash) {
		bgp_mup_dsd_segid_hash_fini(bgp->mup_dsd_segid_hash);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_dsd_segid_hash);
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

static bool bgp_mup_local_v6_source_compute(vrf_id_t vrf_id, struct in6_addr *out)
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

/* Cache for bgp_mup_local_v6_source results.  The helper walks every
 * interface × every connected address per T1ST/T2ST install; the answer
 * almost never changes.  Memoise per vrf, invalidated on every connected-
 * address add/delete via bgp_mup_iface_addr_change() (called from
 * bgp_zebra.c's address handlers).
 */
PREDECL_LIST(bgp_mup_v6src_cache);
struct bgp_mup_v6src_cache_entry {
	struct bgp_mup_v6src_cache_item item;
	vrf_id_t vrf_id;
	bool valid; /* false = remembered "no global v6 in this vrf" */
	struct in6_addr addr;
};
DECLARE_LIST(bgp_mup_v6src_cache, struct bgp_mup_v6src_cache_entry, item);

static struct bgp_mup_v6src_cache_head bgp_mup_v6src_cache;
static bool bgp_mup_iface_cache_inited;

static void bgp_mup_iface_cache_init_once(void)
{
	if (bgp_mup_iface_cache_inited)
		return;
	bgp_mup_v6src_cache_init(&bgp_mup_v6src_cache);
	bgp_mup_iface_cache_inited = true;
}

void bgp_mup_iface_addr_change(vrf_id_t vrf_id)
{
	struct bgp_mup_v6src_cache_entry *v;

	if (!bgp_mup_iface_cache_inited)
		return;
	frr_each_safe (bgp_mup_v6src_cache, &bgp_mup_v6src_cache, v) {
		if (v->vrf_id != vrf_id)
			continue;
		bgp_mup_v6src_cache_del(&bgp_mup_v6src_cache, v);
		XFREE(MTYPE_BGP_MUP_IFACE_CACHE, v);
	}
}

/* Pick a local IPv6 source address for the new SRv6 outer when the
 * incoming T1ST has no Source Address.  Cached per vrf_id; result is
 * the first non-link-local IPv6 connected address found in @vrf_id.
 */
static bool bgp_mup_local_v6_source(vrf_id_t vrf_id, struct in6_addr *out)
{
	struct bgp_mup_v6src_cache_entry *e;

	bgp_mup_iface_cache_init_once();
	frr_each (bgp_mup_v6src_cache, &bgp_mup_v6src_cache, e) {
		if (e->vrf_id != vrf_id)
			continue;
		if (e->valid)
			*out = e->addr;
		return e->valid;
	}
	e = XCALLOC(MTYPE_BGP_MUP_IFACE_CACHE, sizeof(*e));
	e->vrf_id = vrf_id;
	e->valid = bgp_mup_local_v6_source_compute(vrf_id, &e->addr);
	bgp_mup_v6src_cache_add_tail(&bgp_mup_v6src_cache, e);
	if (e->valid)
		*out = e->addr;
	return e->valid;
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

/* Synthesize the End.M.GTP*.E forwarding SID per RFC 9433 from the
 * matched ISD's locator+function and the T1ST's TEID/QFI/endpoint.
 *
 * Layout:
 *   End.M.GTP4.E SID = locator+function | IPv4 DA (32) | Args.Mob (40) | pad
 *     (RFC 9433 Section 6.6 Figure 9)
 *   End.M.GTP6.E SID = locator+function | Args.Mob (40)
 *     (RFC 9433 Section 6.5: "The prefix of End.M.GTP6.E SID MUST be
 *      followed by the Args.Mob.Session argument space")
 *
 * For v6, Args.Mob lives at offset loc_func — NOT at the SID's trailing
 * 40 bits.  The kernel's End.M.GTP6.E decoder
 * (net/ipv6/seg6_local.c::seg6_mobile_extract_args_mob) reads Args.Mob
 * starting at the FIB-matched prefix length, which is loc_func when the
 * route is installed at /(loc_func).  For v4, Args.Mob still lives 32
 * bits past loc_func because the IPv4 DA occupies that intermediate
 * slot (kernel ::seg6_mobile_parse_gtp4_sid).
 *
 * The IPv4 DA bits encode the GTP-U outer destination that End.M.GTP4.E
 * will use when re-encapping toward the gNB; per draft-ietf-bess-mup-safi
 * Section 3.3.7 this is the Tunnel Endpoint Address from the T1ST NLRI
 * when the endpoint is IPv4.
 */
static bool bgp_mup_synthesize_t1st_sid(const struct bgp_mup_isd_entry *isd,
					const struct mup_t1st_route *t1, struct in6_addr *out)
{
	unsigned int loc_func = isd->loc_block_len + isd->loc_node_len + isd->func_len;
	bool isd_is_v4 = (isd->behavior == SRV6_ENDPOINT_BEHAVIOR_END_M_GTP4_E);
	unsigned int args_off;
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
		args_off = loc_func + 32;
	} else {
		if (loc_func + 40 > IPV6_MAX_BITLEN)
			return false;
		args_off = loc_func;
	}

	args_mob = bgp_mup_args_mob_session(t1->t1st_3gpp_5g.teid, t1->t1st_3gpp_5g.qfi);
	bgp_mup_sid_set_bits(out, args_off, 40, args_mob);
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
		if (bgp_mup_local_v6_source(bgp->vrf_id, &out->outer_sa))
			out->have_outer_sa = true;
	}
	return out->have_outer_sa;
}

static void bgp_mup_build_t1st_route(const struct mup_prefix *mp,
				     const struct bgp_mup_t1st_resolved *r, vrf_id_t vrf_id,
				     struct zapi_route *api)
{
	const struct mup_t1st_route *t1 = &mp->t1st_route;
	const struct mup_t1st_3gpp_5g *ext = &t1->t1st_3gpp_5g;
	struct zapi_nexthop *api_nh;

	api->prefix.family = (t1->ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
	api->prefix.prefixlen = t1->ip_prefix_length;
	if (api->prefix.family == AF_INET)
		memcpy(&api->prefix.u.prefix4, &t1->ip.ipaddr_v4, sizeof(struct in_addr));
	else
		memcpy(&api->prefix.u.prefix6, &t1->ip.ipaddr_v6, sizeof(struct in6_addr));

	api_nh = &api->nexthops[0];
	api_nh->type = NEXTHOP_TYPE_IPV6;
	/* Resolve the recursive End.M.GTP*.E gate in the same per-vrf table the
	 * route installs into: the seg6_mobile datapath does a single egress
	 * lookup in SEG6_MOBILE_VRFTABLE (the slice table), so the SR-domain
	 * locator is leaked into that table, not the default vrf.  Leaving the
	 * nexthop in the default vrf (vrf_id 0) makes zebra's NHT recurse there,
	 * where the locator is absent, and the install stays inactive.
	 */
	api_nh->vrf_id = vrf_id;
	api_nh->gate.ipv6 = r->sid;
	api_nh->seg6_segs[0] = r->sid;
	api_nh->seg_num = 1;
	/*
	 * RFC 9433 Section 6.5 SRH-S02 requires End.M.GTP6.E to read the
	 * ultimate GTP-U(v6) destination from srh->segments[0] (the kernel
	 * `input_action_end_m_gtp6_e` path enforces segments_left == 1 and
	 * uses srh->segments[0] as next_sid).  IPv4 endpoints encode the
	 * gNB DA inside the End.M.GTP4.E SID itself, so a single SRH
	 * segment suffices; for IPv6 the gNB address must be carried as a
	 * second SRH segment.
	 *
	 * FRR's seg6_segs[] is in transit order (first hop first), and
	 * zebra reverses it into the on-wire SRH such that segments[0] is
	 * the last/ultimate SID.  Append the gNB v6 endpoint as seg6_segs[1]
	 * so the wire SRH ends up { gNB, SID } with segments_left = 1.
	 */
	if (ext->endpoint_address.ipa_type == IPADDR_V6) {
		api_nh->seg6_segs[1] = ext->endpoint_address.ipaddr_v6;
		api_nh->seg_num = 2;
	}
	SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
	/* H.Encaps so the kernel prepends a fresh outer IPv6 (+ optional
	 * SRH) instead of inserting an SRH into an existing IPv6 packet
	 * (H.Insert; only legal for IPv6 destinations).  T1ST is DL
	 * ingress at the MUP-PE so the inner is whatever traffic was
	 * destined to the UE prefix.
	 */
	api_nh->srv6_encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
	api->nexthop_num = 1;
}

static void bgp_mup_build_t2st_route(struct bgp *bgp, const struct mup_prefix *mp,
				     const struct bgp_mup_dsd_entry *dsd, vrf_id_t vrf_id,
				     uint32_t vrftable, struct zapi_route *api)
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
	/* Anchor the route entry on the importing vrf's loopback so the kernel
	 * has a valid dev for the lwtunnel install (mirrors L3VPN's
	 * vpn_leak_zebra_vrf_sid_update_per_af).  The post-action FIB lookup
	 * for the rebuilt SRv6 packet is driven by SEG6_MOBILE_VRFTABLE, not
	 * by this anchor.
	 */
	ifp = if_get_vrf_loopback(vrf_id);
	api_nh->type = NEXTHOP_TYPE_IFINDEX;
	api_nh->ifindex = ifp ? ifp->ifindex : 0;
	api_nh->vrf_id = vrf_id;
	api_nh->seg6_mobile_action = ep_v4 ? ZEBRA_SEG6_MOBILE_ACTION_H_M_GTP4_D
					   : ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP6_D;
	/* Both H.M.GTP4.D (v4) and End.M.GTP6.D (v6) carry the SR Policy as a
	 * single-segment SRH = [DSD SID]; the kernel reads segments[0] as the
	 * outer DA base.  H.M.GTP4.D overlays the 32-bit inner IPv4 DA right
	 * after sr_prefix_len (Args.Mob.Session last); End.M.GTP6.D augments the
	 * SRH with one leading slot and stamps the original outer DA into
	 * segments[0].  The End.DT* endpoint at the remote PE decaps on that SID.
	 */
	api_nh->seg_num = 1;
	api_nh->seg6_segs[0] = dsd->sid;
	SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
	api_nh->seg6_mobile_ctx.sr_prefix_len = loc_func;
	/* The kernel requires SEG6_MOBILE_VRFTABLE to name a VRF-bound table
	 * (seg6_mobile_check_vrftable); the rebuilt SRv6 packet's egress lookup
	 * crosses into it.  Use the slice VRF table — the SR-domain locator
	 * route for B must be reachable there (leaked / advertised into the
	 * slice), per RFC 9433 Section 6.7 S07 "forward along the shortest path
	 * to B".
	 */
	api_nh->seg6_mobile_ctx.vrftable = vrftable;
	/* Outer SRv6 source = MUP-GW's SR-domain address, drawn from the BGP
	 * instance's (SR-domain) vrf, not the access-facing install vrf.
	 */
	if (bgp_mup_local_v6_source(bgp->vrf_id, &api_nh->seg6_mobile_ctx.src_addr) == false)
		memset(&api_nh->seg6_mobile_ctx.src_addr, 0,
		       sizeof(api_nh->seg6_mobile_ctx.src_addr));
	SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6_MOBILE);
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

/* Forward decl: bgp_mup_afi_from_prefix is defined below near
 * bgp_mup_zebra_install but used by bgp_mup_st_announce above it.
 */
static afi_t bgp_mup_afi_from_prefix(const struct mup_prefix *mp);

/* True iff any RT carried on `attr` appears in `bgp`'s per-afi
 * MUP import RT list.  Mirrors L3VPN's vpn_leak_to_vrf_update_onevrf
 * (bgp_mplsvpn.c) `ecommunity_include` test against
 * vpn_policy[afi].rtlist[FROMVPN].
 *
 * The `import mup` master toggle (BGP_CONFIG_MUP_TO_VRF_IMPORT) gates
 * every caller centrally — a vrf with rtlist set but the toggle clear
 * does not participate in install / no-retain / any-vrf-imports
 * decisions, mirroring L3VPN's `import vpn`.
 */
static bool bgp_mup_route_rt_in_import(struct bgp *bgp, afi_t afi,
				       struct ecommunity *route_rt)
{
	struct bgp_mup_export_policy *ep;

	if (!CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			BGP_CONFIG_MUP_TO_VRF_IMPORT))
		return false;
	ep = bgp_mup_export_peek(bgp, afi);
	if (!ep || !ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP])
		return false;
	return ecommunity_include(ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP], route_rt);
}

/* True iff at least one per-vrf bgp instance imports the RT carried on
 * `attr`.  Used to gate ISD/DSD cache upsert: a transit PE shouldn't
 * cache discovery state for slices it has no policy to serve, since a
 * stale ISD could otherwise wrongly cover a T1ST for a slice the local
 * PE has no business resolving.  Mirrors L3VPN's
 * vpn_leak_to_vrf_update_onevrf: import is gated on
 * vpn_policy[afi].rtlist[FROMVPN] only.
 */
static bool bgp_mup_any_vrf_imports(afi_t afi, const struct attr *attr)
{
	struct ecommunity *route_rt;
	struct listnode *node;
	struct bgp *bgp;

	if (!attr)
		return false;
	route_rt = bgp_attr_get_ecommunity(attr);
	if (!route_rt)
		return false;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		if (bgp->vrf_id == VRF_DEFAULT || bgp->vrf_id == VRF_UNKNOWN)
			continue;
		if (bgp_mup_route_rt_in_import(bgp, afi, route_rt))
			return true;
	}
	return false;
}

/* RT-based per-vrf install selection: walk every per-vrf bgp instance
 * and return the first one whose configured `route-target import` list
 * contains an RT that matches one of the route's RT extended
 * communities.  Returns VRF_UNKNOWN when no per-vrf instance imports
 * this RT — the caller skips the kernel install in that case.
 *
 * Mirrors L3VPN's vpn_leak_to_vrf_update_onevrf, which tests only
 * vpn_policy[afi].rtlist[FROMVPN] (the import side).  An instance with
 * no `route-target import` line never imports — operators use it just
 * like an L3VPN receive-only vrf.
 */
static vrf_id_t bgp_mup_match_install_vrf(afi_t afi, const struct attr *attr)
{
	struct ecommunity *route_rt;
	struct listnode *node;
	struct bgp *bgp;

	if (!attr)
		return VRF_UNKNOWN;
	route_rt = bgp_attr_get_ecommunity(attr);
	if (!route_rt)
		return VRF_UNKNOWN;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		if (bgp->vrf_id == VRF_DEFAULT || bgp->vrf_id == VRF_UNKNOWN)
			continue;
		if (bgp_mup_route_rt_in_import(bgp, afi, route_rt))
			return bgp->vrf_id;
	}
	return VRF_UNKNOWN;
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
	if (!bgp_mup_any_vrf_imports(afi, attr)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: ISD RT not imported by any vrf; skip cache upsert");
		return;
	}
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, mp->rd, 8);
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

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, mp->rd, 8);
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
	if (!bgp_mup_any_vrf_imports(afi, attr)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: DSD RT not imported by any vrf; skip cache upsert");
		return;
	}
	has_seg = bgp_mup_get_direct_seg_id(attr, &segment_id);
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, mp->rd, 8);
	bgp_mup_dsd_cache_upsert(bgp, afi, &prd, &mp->dsd_route.ip, &sid, block, node, func, arg,
				 behavior, has_seg, segment_id);
}

static void bgp_mup_dsd_withdraw(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp)
{
	struct prefix_rd prd = {};

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, mp->rd, 8);
	bgp_mup_dsd_cache_remove(bgp, afi, &prd, &mp->dsd_route.ip);
}

/* Common header for an SRv6 Mobile User Plane install/uninstall sent
 * from BGP-MUP into zebra.
 */
/* Send a withdraw to zebra for the given mup_prefix.  Used by every
 * "skip install for this T1ST/T2ST" path in bgp_mup_st_announce that
 * wants any earlier install for the same prefix to be torn down.
 */
static void bgp_mup_st_delete_send(struct bgp *bgp, struct bgp_path_info *info,
				   const struct mup_prefix *mp);

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

static int bgp_mup_st_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct prefix_mup *pm, const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	afi_t afi = bgp_mup_afi_from_prefix(mp);
	vrf_id_t install_vrf_id = bgp_mup_match_install_vrf(afi, info->attr);
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

	(void)dest;

	/* No per-vrf instance imports this RT — there is no local table
	 * the install should land in.
	 */
	if (install_vrf_id == VRF_UNKNOWN) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: route_type %u has no per-vrf RT match; skip install",
				   pm->prefix.route_type);
		return 0;
	}

	if (mp->route_type == BGP_MUP_T1ST_ROUTE) {
		struct bgp_mup_t1st_resolved r;

		if (!bgp_mup_resolve_t1st(bgp, mp, &r)) {
			/* Withdraw any prior install for this T1ST: an ISD
			 * may have been removed or the source-address
			 * resolution failed.  Idempotent if nothing was
			 * installed.
			 */
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		}
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t1st_route(mp, &r, install_vrf_id, &api);
	} else {
		uint64_t segment_id;
		struct bgp_mup_dsd_entry *dsd;

		if (!bgp_mup_get_direct_seg_id(info->attr, &segment_id)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST without MUP-EC; treat-as-withdraw");
			return 0;
		}
		dsd = bgp_mup_dsd_lookup(bgp, segment_id);
		if (!dsd) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST seg-id %" PRIu64
					   " has no matching DSD; skip install",
					   segment_id);
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		}
		/* T2ST install is symmetric across v4/v6 — both place the
		 * GTP-U-decap+SRv6-encap action at the MUP-GW ingress (RFC 9433
		 * Section 6.6 H.M.GTP4.D for v4; Section 6.3 End.M.GTP6.D for
		 * v6).  bgp_mup_build_t2st_route picks the right kernel action
		 * (and the corresponding SR policy carrier — nh6 vs SRH segs)
		 * from endpoint_address's family.  For v6, the configured SR
		 * Policy is pushed verbatim per RFC 9433 Section 6.3 S04 ("SRH
		 * containing B"); a single-segment policy [End.DT6@MUP-PE]
		 * therefore lands at MUP-PE with segments_left == 0 so End.DT6
		 * decaps cleanly.
		 */
		if (!ep || ep->vrftable == 0) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST install skipped — `segment vrftable` unset under address-family ipv%u mup",
					   afi == AFI_IP ? 4 : 6);
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		}
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t2st_route(bgp, mp, dsd, install_vrf_id, ep->vrftable, &api);
	}
	/* Route prefix lands in the per-vrf RIB. */
	api.vrf_id = install_vrf_id;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: announcing route_type %u install vrf %u to zebra",
			   pm->prefix.route_type, install_vrf_id);

	return zclient_route_send(ZEBRA_ROUTE_ADD, bgp_zclient, &api);
}

static void bgp_mup_st_delete_send(struct bgp *bgp, struct bgp_path_info *info,
				   const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	vrf_id_t install_vrf_id;
	afi_t afi = bgp_mup_afi_from_prefix(mp);

	bgp_mup_zapi_init(&api, bgp, info, false);
	if (!bgp_mup_build_st_delete(mp, &api))
		return;
	/* The install was sent to the per-vrf table that imports the
	 * route's RT — the withdraw must target the same table.  Falling
	 * back to bgp->vrf_id (== default) here would leave a stale
	 * install in the per-vrf table when the matching ISD/DSD is
	 * removed.  Mirrors L3VPN's vpn_leak_to_vrf_withdraw which
	 * walks each import-matching vrf to issue the withdraw.
	 */
	install_vrf_id = bgp_mup_match_install_vrf(afi, info ? info->attr : NULL);
	if (install_vrf_id != VRF_UNKNOWN)
		api.vrf_id = install_vrf_id;
	zclient_route_send(ZEBRA_ROUTE_DELETE, bgp_zclient, &api);
}

static int bgp_mup_st_withdraw(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct mup_prefix *mp)
{
	(void)dest;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: withdrawing route_type %u (vrf %u) from zebra",
			   mp->route_type, bgp->vrf_id);
	bgp_mup_st_delete_send(bgp, info, mp);
	return 0;
}

/* Derive AFI from the address embedded in a BGP-MUP NLRI (each route
 * type stores it in a different sub-struct).  Used by both
 * bgp_mup_zebra_announce and bgp_mup_zebra_withdraw.
 */
static afi_t bgp_mup_afi_from_prefix(const struct mup_prefix *mp)
{
	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
	case BGP_MUP_T1ST_ROUTE:
		return (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	case BGP_MUP_DSD_ROUTE:
		return (mp->dsd_route.ip.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	case BGP_MUP_T2ST_ROUTE:
		return IS_IPADDR_V4(&mp->t2st_route.endpoint_address) ? AFI_IP : AFI_IP6;
	}
	return AFI_IP;
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

	afi = bgp_mup_afi_from_prefix(mp);

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

	afi = bgp_mup_afi_from_prefix(mp);

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

static void bgp_mup_reannounce_st_routes_cb(struct event *t)
{
	struct bgp *bgp = EVENT_ARG(t);
	afi_t afi = EVENT_VAL(t);

	bgp_mup_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_schedule_reannounce_st_routes(struct bgp *bgp, afi_t afi)
{
	if (afi >= AFI_MAX)
		return;
	if (bgp->mup_reannounce_ev[afi])
		return;
	event_add_event(bm->master, bgp_mup_reannounce_st_routes_cb, bgp, afi,
			&bgp->mup_reannounce_ev[afi]);
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

		/*
		 * draft-ietf-bess-mup-safi Section 3.1.x: a malformed MUP NLRI
		 * MUST be treated as 'Treat-as-withdraw' per RFC 7606 — the
		 * speaker MUST skip such NLRIs and continue processing the
		 * remainder of the UPDATE.  The outer length checks above
		 * already validated pnt+psize <= lim, so it is safe to
		 * advance to the next NLRI on a per-route processor failure.
		 */
		switch (route_type) {
		case BGP_MUP_ISD_ROUTE:
			if (bgp_mup_process_isd_route(peer, afi, safi,
						      withdraw ? NULL : attr,
						      pnt, psize, addpath_id))
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Skipping malformed BGP-MUP ISD NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
			break;

		case BGP_MUP_DSD_ROUTE:
			if (bgp_mup_process_dsd_route(peer, afi, safi,
						      withdraw ? NULL : attr,
						      pnt, psize, addpath_id))
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Skipping malformed BGP-MUP DSD NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
			break;

		case BGP_MUP_T1ST_ROUTE:
			if (bgp_mup_process_t1st_route(peer, afi, safi,
						       withdraw ? NULL : attr,
						       pnt, psize, addpath_id))
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Skipping malformed BGP-MUP T1ST NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
			break;

		case BGP_MUP_T2ST_ROUTE:
			if (bgp_mup_process_t2st_route(peer, afi, safi,
						       withdraw ? NULL : attr,
						       pnt, psize, addpath_id))
				flog_err(EC_BGP_MUP_FAIL,
					 "%u:%s - Skipping malformed BGP-MUP T2ST NLRI size %d",
					 peer->bgp->vrf_id, peer->host, psize);
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

#include "bgpd/bgp_vty.h"
#include "lib/command.h"

#include "bgpd/bgp_mup_clippy.c"

static afi_t bgp_mup_export_node2afi(struct vty *vty)
{
	if (vty->node == BGP_IPV4_NODE)
		return AFI_IP;
	if (vty->node == BGP_IPV6_NODE)
		return AFI_IP6;
	return AFI_MAX;
}

static int bgp_mup_export_check_ctx(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	if (afi == AFI_MAX) {
		vty_out(vty,
			"%% rt mup only valid under address-family ipv4|ipv6 unicast\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% rt mup must be configured under a non-default vrf bgp instance (`router bgp ASN vrf NAME`); the default-vrf instance only carries the BGP-MUP session\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

static int mup_policy_getdirs(struct vty *vty, const char *dstr, int *dodir)
{
	if (!strcmp(dstr, "import")) {
		dodir[BGP_MUP_POLICY_DIR_FROMMUP] = 1;
	} else if (!strcmp(dstr, "export")) {
		dodir[BGP_MUP_POLICY_DIR_TOMUP] = 1;
	} else if (!strcmp(dstr, "both")) {
		dodir[BGP_MUP_POLICY_DIR_FROMMUP] = 1;
		dodir[BGP_MUP_POLICY_DIR_TOMUP] = 1;
	} else {
		vty_out(vty, "%% direction parse error\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* True iff the per-(vrf, afi) MUP import policy currently has any
 * matching state (rtlist[FROMMUP] non-NULL).  Used by the auto-set
 * of BGP_CONFIG_MUP_TO_VRF_IMPORT on the first `rt mup import` line:
 * existing seg6-mobile configs with `rt mup import` but no explicit
 * `import mup` toggle continue to install received MUP NLRIs.
 */
static bool bgp_mup_import_predicted_active(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

	if (!ep)
		return false;
	return ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP] != NULL;
}

/* Auto-set BGP_CONFIG_MUP_TO_VRF_IMPORT when the operator first enters
 * a matching policy line.  Skipped once the operator has explicitly
 * typed `[no] import mup`: the EXPLICIT bit latches and disables
 * auto-set permanently on this (bgp, afi) so subsequent edits don't
 * override the operator's intent.
 */
static void bgp_mup_import_autoset(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (bgp->vrf_id == VRF_DEFAULT)
		return;
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		       BGP_CONFIG_MUP_TO_VRF_IMPORT_EXPLICIT))
		return;
	if (!bgp_mup_import_predicted_active(bgp, afi))
		return;
	SET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_MUP_TO_VRF_IMPORT);
}

/* `rt mup <import|export|both> RTLIST` under
 * `address-family ipv[46] unicast` — BGP-MUP analogue of L3VPN's
 * `rt vpn <import|export|both>` (af_rt_vpn_imexport_cmd in bgp_vty.c).
 * Stored on the per-vrf bgp instance and consulted by
 * bgp_mup_match_install_vrf and the ISD/DSD cache upsert paths via
 * the FROMMUP slot.  TOMUP feeds the originate path landed in a later
 * commit.
 */
DEFPY (af_rt_mup,
       af_rt_mup_cmd,
       "[no] rt mup <import|export|both>$direction_str RTLIST...",
       NO_STR
       "Specify route target list\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from BGP-MUP into current unicast address-family: match any\n"
       "For routes leaked from current unicast address-family to BGP-MUP: set\n"
       "both import: match any and export: set\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct ecommunity *ecom = NULL;
	struct bgp_mup_export_policy *ep;
	int dodir[BGP_MUP_POLICY_DIR_MAX] = {};
	enum bgp_mup_policy_dir dir;
	int idx = 0;
	bool yes = true;
	int ret;
	int i;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	ret = mup_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!argv_find(argv, argc, "RTLIST", &idx)) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		for (i = idx; i < argc; ++i) {
			struct ecommunity *e =
				ecommunity_str2com(argv[i]->arg, ECOMMUNITY_ROUTE_TARGET, 0);

			if (!e) {
				vty_out(vty, "%% Malformed RT '%s'\n", argv[i]->arg);
				if (ecom)
					ecommunity_free(&ecom);
				return CMD_WARNING_CONFIG_FAILED;
			}
			if (ecom) {
				ecommunity_merge(ecom, e);
				ecommunity_free(&e);
			} else {
				ecom = e;
			}
		}
	}

	for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;
		ep = bgp_mup_export_get(bgp, afi);
		if (ep->rtlist[dir])
			ecommunity_free(&ep->rtlist[dir]);
		ep->rtlist[dir] = ecom ? ecommunity_dup(ecom) : NULL;

		/* Import side: T1ST/T2ST already in the default-vrf MUP RIB
		 * may now resolve to (or away from) this vrf.  Schedule a
		 * coalesced reannounce on every bgp instance that holds an
		 * MUP RIB so post-config resolution catches up without
		 * bouncing the session.  Export side has no consumer yet
		 * (originate path follows in a later commit).
		 */
		if (dir == BGP_MUP_POLICY_DIR_FROMMUP) {
			struct listnode *node;
			struct bgp *b;

			bgp_mup_import_autoset(bgp, afi);
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, b))
				bgp_mup_schedule_reannounce_st_routes(b, afi);
		}
	}

	if (ecom)
		ecommunity_free(&ecom);
	return CMD_SUCCESS;
}

ALIAS (af_rt_mup,
       af_no_rt_mup_cmd,
       "no rt mup <import|export|both>$direction_str",
       NO_STR
       "Specify route target list\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from BGP-MUP into current unicast address-family\n"
       "For routes leaked from current unicast address-family to BGP-MUP\n"
       "both import and export\n")

/* `segment vrftable TABLEID` under `address-family ipv[46] mup` —
 * SR-underlay VRF table id for both T1ST/T2ST install and (in a later
 * commit) local-SID origination.  Configured on the default-vrf BGP
 * instance, where the BGP-MUP session itself lives.  Kernel rejects
 * the install without strict_mode + a VRF-bound table, so there is no
 * useful default; the knob must be set before any install can land.
 */
DEFPY (af_mup_segment_vrftable,
       af_mup_segment_vrftable_cmd,
       "[no] segment vrftable (1-4294967295)$tableid",
       NO_STR
       "Segment routing underlay configuration for this MUP address-family\n"
       "SR-underlay VRF table id (SEG6_MOBILE_VRFTABLE)\n"
       "Linux VRF table id; must be bound to a VRF device with net.vrf.strict_mode=1\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	struct bgp_mup_export_policy *ep;
	struct listnode *node;
	struct bgp *b;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);

	if (vty->node == BGP_IPV4_MUP_NODE)
		afi = AFI_IP;
	else if (vty->node == BGP_IPV6_MUP_NODE)
		afi = AFI_IP6;
	else {
		vty_out(vty,
			"%% segment vrftable only valid under address-family ipv4|ipv6 mup\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"%% segment vrftable must be configured under the default-vrf BGP instance (where the BGP-MUP session lives)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ep = bgp_mup_export_get(bgp, afi);
	ep->vrftable = yes ? (uint32_t)tableid : 0;

	/* T2ST routes already in the MUP RIB may now resolve (or de-resolve)
	 * against the new value; schedule a coalesced reannounce.
	 */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, b))
		bgp_mup_schedule_reannounce_st_routes(b, afi);
	return CMD_SUCCESS;
}

ALIAS (af_mup_segment_vrftable,
       af_no_mup_segment_vrftable_cmd,
       "no segment vrftable",
       NO_STR
       "Segment routing underlay configuration for this MUP address-family\n"
       "SR-underlay VRF table id (SEG6_MOBILE_VRFTABLE)\n")

void bgp_mup_vty_init(void)
{
	install_element(BGP_IPV4_NODE, &af_rt_mup_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rt_mup_cmd);
	install_element(BGP_IPV6_NODE, &af_rt_mup_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rt_mup_cmd);

	install_element(BGP_IPV4_MUP_NODE, &af_mup_segment_vrftable_cmd);
	install_element(BGP_IPV4_MUP_NODE, &af_no_mup_segment_vrftable_cmd);
	install_element(BGP_IPV6_MUP_NODE, &af_mup_segment_vrftable_cmd);
	install_element(BGP_IPV6_MUP_NODE, &af_no_mup_segment_vrftable_cmd);
}

/* Emit MUP-AF-scoped knobs under `address-family ipv[46] mup`. */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

	if (ep && ep->vrftable)
		vty_out(vty, "  segment vrftable %u\n", ep->vrftable);
}

/* Emit the per-(vrf, afi) MUP-policy lines under
 * `address-family ipv[46] unicast`.  Sibling of L3VPN's
 * `rt vpn <import|export|both>` writeback in
 * bgp_vpn_policy_config_write_afi.
 */
void bgp_mup_export_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, int indent)
{
	struct bgp_mup_export_policy *ep;
	struct ecommunity *rt_in, *rt_out;

	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	ep = bgp_mup_export_peek(bgp, afi);
	if (!ep)
		return;

	rt_in = ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP];
	rt_out = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
	if (rt_in && rt_out && ecommunity_cmp(rt_in, rt_out)) {
		char *b = ecommunity_ecom2str(rt_in, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "%*srt mup both %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
		return;
	}
	if (rt_in) {
		char *b = ecommunity_ecom2str(rt_in, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "%*srt mup import %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	}
	if (rt_out) {
		char *b = ecommunity_ecom2str(rt_out, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "%*srt mup export %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	}
}
