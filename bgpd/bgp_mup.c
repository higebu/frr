// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */

#include "prefix.h"
#include "stream.h"

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

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);

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

static struct bgp_mup_isd_list_head *bgp_mup_get_isd_cache(struct bgp *bgp)
{
	if (!bgp->mup_isd_cache) {
		bgp->mup_isd_cache = XCALLOC(MTYPE_TMP, sizeof(*bgp->mup_isd_cache));
		bgp_mup_isd_list_init(bgp->mup_isd_cache);
	}
	return bgp->mup_isd_cache;
}

static struct bgp_mup_dsd_list_head *bgp_mup_get_dsd_cache(struct bgp *bgp)
{
	if (!bgp->mup_dsd_cache) {
		bgp->mup_dsd_cache = XCALLOC(MTYPE_TMP, sizeof(*bgp->mup_dsd_cache));
		bgp_mup_dsd_list_init(bgp->mup_dsd_cache);
	}
	return bgp->mup_dsd_cache;
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
		if (e->endpoint.ipa_type != endpoint->ipa_type)
			continue;
		if (endpoint->ipa_type == IPADDR_V4) {
			if (e->endpoint.ipaddr_v4.s_addr != endpoint->ipaddr_v4.s_addr)
				continue;
		} else if (memcmp(&e->endpoint.ipaddr_v6, &endpoint->ipaddr_v6,
				  sizeof(struct in6_addr)) != 0) {
			continue;
		}
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
		e = XCALLOC(MTYPE_TMP, sizeof(*e));
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
	XFREE(MTYPE_TMP, e);
	bgp_mup_reannounce_st_routes(bgp, afi);
}

static void bgp_mup_dsd_cache_upsert(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				     const struct ipaddr *endpoint, const struct in6_addr *sid,
				     uint8_t block, uint8_t node, uint8_t func, uint8_t arg,
				     uint16_t behavior, bool has_segment_id, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry *e = bgp_mup_dsd_find_key(bgp, afi, prd, endpoint);

	if (!e) {
		e = XCALLOC(MTYPE_TMP, sizeof(*e));
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
	XFREE(MTYPE_TMP, e);
	bgp_mup_reannounce_st_routes(bgp, afi);
}

void bgp_mup_caches_free(struct bgp *bgp)
{
	struct bgp_mup_isd_entry *isd;
	struct bgp_mup_dsd_entry *dsd;

	if (bgp->mup_isd_cache) {
		while ((isd = bgp_mup_isd_list_pop(bgp->mup_isd_cache)))
			XFREE(MTYPE_TMP, isd);
		bgp_mup_isd_list_fini(bgp->mup_isd_cache);
		XFREE(MTYPE_TMP, bgp->mup_isd_cache);
	}
	if (bgp->mup_dsd_cache) {
		while ((dsd = bgp_mup_dsd_list_pop(bgp->mup_dsd_cache)))
			XFREE(MTYPE_TMP, dsd);
		bgp_mup_dsd_list_fini(bgp->mup_dsd_cache);
		XFREE(MTYPE_TMP, bgp->mup_dsd_cache);
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
 */
static struct interface *bgp_mup_locator_oif(vrf_id_t vrf_id, const struct in6_addr *sid)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;
	struct connected *connected;

	if (!vrf)
		return NULL;
	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			const struct prefix *p = connected->address;

			if (p->family != AF_INET6 || p->prefixlen >= IPV6_MAX_BITLEN)
				continue;
			if (prefix_match(p, &(struct prefix){ .family = AF_INET6,
							      .prefixlen = IPV6_MAX_BITLEN,
							      .u.prefix6 = *sid }))
				return ifp;
		}
	}
	return NULL;
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
		if (bgp_mup_local_v6_source(bgp->vrf_id, &out->outer_sa))
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
	api->nexthop_num = 1;
}

static void bgp_mup_build_t2st_route(const struct mup_prefix *mp,
				     const struct bgp_mup_dsd_entry *dsd, vrf_id_t vrf_id,
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
	/* H.M.GTP4.D is a local action: anchor the route on the SR
	 * locator interface so zebra emits RTA_OIF + encap seg6local
	 * without a separate gateway.  Fall back to lo if no covering
	 * interface is found.
	 */
	ifp = bgp_mup_locator_oif(vrf_id, &dsd->sid);
	if (!ifp)
		ifp = if_lookup_by_name("lo", vrf_id);
	api_nh->type = NEXTHOP_TYPE_IFINDEX;
	api_nh->ifindex = ifp ? ifp->ifindex : 0;
	api_nh->vrf_id = vrf_id;
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
	if (bgp_mup_local_v6_source(vrf_id, &api_nh->seg6local_ctx.mobile.src_addr) == false)
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

	(void)dest;

	if (mp->route_type == BGP_MUP_T1ST_ROUTE) {
		struct bgp_mup_t1st_resolved r;

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
		bgp_mup_build_t2st_route(mp, dsd, bgp->vrf_id, &api);
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: announcing route_type %u (vrf %u) to zebra",
			   pm->prefix.route_type, bgp->vrf_id);

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

