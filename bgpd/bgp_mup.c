// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>

#include "prefix.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_mup.h"
#include "bgpd/bgp_route.h"

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
		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN
					      : IPV6_MAX_BYTELEN;
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

		total_len = 8 + 1 + prefix_octets + 4 + 1 + 1 + ep_octets + 1
			    + src_octets;
		break;
	}

	case BGP_MUP_T2ST_ROUTE: {
		/* RD(8) + EndpointAddrLen(1) + EndpointAddr(4 or 16)
		 * + TEID(0..4 packed in trailing bits).
		 */
		uint8_t teid_bits;
		uint8_t teid_octets;
		uint32_t teid_be;

		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN
					      : IPV6_MAX_BYTELEN;
		teid_bits = (mp->t2st_route.endpoint_address_length > addr_octets * 8)
				    ? mp->t2st_route.endpoint_address_length
					      - (addr_octets * 8)
				    : 0;
		teid_octets = (teid_bits + 7) / 8;
		teid_be = htonl(mp->t2st_route.teid);

		stream_put(s, mp->rd, 8);
		stream_putc(s, mp->t2st_route.endpoint_address_length);
		stream_put(s, &mp->t2st_route.endpoint_address.ip.addr,
			   addr_octets);
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

static int bgp_mup_process_isd_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t prefix_len;
	uint8_t prefix_octets;

	if (psize < 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI invalid length %d",
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
			 "%u:%s - Rx BGP-MUP ISD NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}

	prefix_octets = PSIZE(prefix_len);
	if (psize - 9 != prefix_octets) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI prefix length mismatch",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_ISD_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.isd_route.ip_prefix_length = prefix_len;
	p.prefix.isd_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4
							 : IPADDR_V6;
	memcpy(&p.prefix.isd_route.ip.ip.addr, pfx + 9, prefix_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_dsd_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;

	if ((afi == AFI_IP && psize != 12) || (afi == AFI_IP6 && psize != 24)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP DSD NLRI invalid length %d",
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
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t1st_route(struct peer *peer, afi_t afi, safi_t safi,
				      struct attr *attr, uint8_t *pfx, int psize,
				      uint32_t addpath_id)
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
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid length %d",
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
			 "%u:%s - Rx BGP-MUP T1ST NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}
	prefix_octets = PSIZE(prefix_len);

	bgp_mup_prefix_init(&p, BGP_MUP_T1ST_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.t1st_route.ip_prefix_length = prefix_len;
	p.prefix.t1st_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4
							  : IPADDR_V6;

	if (off + prefix_octets + 4 + 1 + 1 > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI truncated",
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
			 "%u:%s - Rx BGP-MUP T1ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
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
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t2st_route(struct peer *peer, afi_t afi, safi_t safi,
				      struct attr *attr, uint8_t *pfx, int psize,
				      uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;
	uint8_t teid_bits;
	uint8_t teid_octets;
	uint32_t teid_be = 0;
	uint8_t ea_len;

	if (psize < 13) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, 8);

	ea_len = pfx[8];
	if ((afi == AFI_IP && ea_len > 64) || (afi == AFI_IP6 && ea_len > 160)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI bad endpoint length %u",
			 peer->bgp->vrf_id, peer->host, ea_len);
		return -1;
	}

	addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	if (9 + addr_octets > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	teid_bits = (ea_len > addr_octets * 8) ? ea_len - addr_octets * 8 : 0;
	teid_octets = (teid_bits + 7) / 8;
	if (9 + addr_octets + teid_octets > psize) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI truncated TEID",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_T2ST_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, 8);
	p.prefix.t2st_route.endpoint_address_length = ea_len;
	p.prefix.t2st_route.endpoint_address.ipa_type = (afi == AFI_IP)
								? IPADDR_V4
								: IPADDR_V6;
	memcpy(&p.prefix.t2st_route.endpoint_address.ip.addr, pfx + 9,
	       addr_octets);
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
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet, int withdraw)
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
