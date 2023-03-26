/*
 * BGP-MUP for packet handling
 * Copyright (C) 2023 Yuya Kusakabe
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"

#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mup.h"

size_t bgp_mup_prefix_size(const struct prefix *p)
{
	int size;
	struct prefix_mup *mp = (struct prefix_mup *)p;

	size = mp->prefix.length + 3;
	return size;
};

/*
 * Encode BGP-MUP prefix in Update (MP_REACH)
 */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	struct prefix_mup *mp = (struct prefix_mup *)p;
	int len, ipa_len = 0;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	/* Architecture type */
	stream_putc(s, mp->prefix.arch_type);

	/* Route type */
	stream_putw(s, mp->prefix.route_type);

	switch (mp->prefix.route_type) {
	case BGP_MUP_ISD_ROUTE: /* Interwork Segment Discovery route */
		ipa_len = PSIZE(mp->prefix.isd_route.ip_prefix_length);
		/* RD, Prefix Length, Prefix */
		len = 8 + 1 + ipa_len;
		stream_putc(s, len);
		stream_put(s, prd->val, 8); /* RD */
		stream_putc(s, mp->prefix.isd_route
				       .ip_prefix_length); /* Prefix Length */
		stream_put(s, &mp->prefix.isd_route.ip.ip.addr, ipa_len);
		break;

	case BGP_MUP_DSD_ROUTE: /* Direct Segment Discovery route */
		if (afi == AFI_IP)
			ipa_len = IPV4_MAX_BYTELEN;
		else
			ipa_len = IPV6_MAX_BYTELEN;
		len = 8 + ipa_len;
		stream_putc(s, len);
		stream_put(s, prd->val, 8); /* RD */
		stream_put_ipaddr(s, &mp->prefix.dsd_route.ip);
		break;

	case BGP_MUP_T1ST_ROUTE: /* Type 1 Session Transformed (ST) route */
		ipa_len = PSIZE(mp->prefix.t1st_route.ip_prefix_length);
		if (IS_IPADDR_V4(&mp->prefix.t1st_route.t1st_3gpp_5g
					  .endpoint_address))
			len = 4;
		else
			len = 16;
		/* RD, Prefix Length, Prefix, TEID, QFI, Endpoint Address Length
		 */
		len += 8 + 1 + ipa_len + 4 + 1 + 1;
		stream_putc(s, len);
		stream_put(s, prd->val, 8); /* RD */
		stream_putc(s, mp->prefix.t1st_route
				       .ip_prefix_length); /* Prefix Length */
		stream_put(s, &p->u.prefix, ipa_len);
		stream_putl(s,
			    mp->prefix.t1st_route.t1st_3gpp_5g.teid); /* TEID */
		stream_putc(s,
			    mp->prefix.t1st_route.t1st_3gpp_5g.qfi); /* QFI */
		stream_putc(
			s,
			mp->prefix.t1st_route.t1st_3gpp_5g
				.endpoint_address_length); /* Endpoint Length */
		stream_put_ipaddr(
			s, &mp->prefix.t1st_route.t1st_3gpp_5g
				    .endpoint_address); /* Endpoint Address
							   Length */
		break;

	case BGP_MUP_T2ST_ROUTE: /* Type 2 Session Transformed (ST) route */
		if (afi == AFI_IP)
			ipa_len = IPV4_MAX_BYTELEN;
		else
			ipa_len = IPV6_MAX_BYTELEN;
		len = 8 + 1 + ipa_len + 4;
		stream_putc(s, len);
		stream_put(s, prd->val, 8); /* RD */
		stream_putc(
			s,
			mp->prefix.t2st_route
				.endpoint_address_length); /* Prefix Length */
		stream_put(s, &mp->prefix.t2st_route.endpoint_address.ip.addr,
			   ipa_len);			    /* Prefix */
		stream_putl(s, mp->prefix.t2st_route.teid); /* TEID */
		break;

	default:
		break;
	}
}

/*
 * Process received BGP-MUP ISD route (advertise or withdraw).
 */
static int bgp_mup_process_isd_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_mup p = {};
	uint8_t prefix_len;
	int ret = 0;

	if (psize < 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *data = stream_new(psize);
	stream_put(data, pfx, psize);

	/* Make prefix_rd. */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	STREAM_GET(&prd.val, data, 8);

	/* Make MUP prefix. */
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_ISD_ROUTE;

	/* Get Prefix Length. */
	STREAM_GETC(data, prefix_len);
	p.prefix.isd_route.ip_prefix_length = prefix_len;
	p.prefix.length = prefix_len;

	/* 
	 * If the AFI is IPv4, then the maximum value of the Prefix Length is 32 bits.
	 * If the AFI is IPv6, then the maximum value of the Prefix length is 128 bits.
	 */
	if ((afi == AFI_IP && prefix_len > 32) || (afi == AFI_IP6 && prefix_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI with invalid prefix length %d",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}

	/* Convert to bytes. */
	prefix_len = PSIZE(prefix_len);
	if (prefix_len != psize - 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP ISD NLRI with invalid prefix",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	if (afi == AFI_IP)
		p.prefix.isd_route.ip.ipa_type = IPADDR_V4;
	else
		p.prefix.isd_route.ip.ipa_type = IPADDR_V6;
	STREAM_GET(&p.prefix.isd_route.ip.ip.addr, data, prefix_len);

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, NULL, 0, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, 0, NULL);
	goto done;

stream_failure:
	flog_err(EC_BGP_MUP_ROUTE_INVALID,
		 "%u:%s - Rx BGP-MUP ISD NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(data);
	return ret;
}

/*
 * Process received BGP-MUP DSD route (advertise or withdraw).
 */
static int bgp_mup_process_dsd_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_mup p = {};
	uint16_t ipa_len;
	int ret = 0;

	if ((afi == AFI_IP && psize != 12) || (afi == AFI_IP6 && psize != 24)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP DSD NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *data = stream_new(psize);
	stream_put(data, pfx, psize);

	/* Make prefix_rd. */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	STREAM_GET(&prd.val, data, 8);

	/* Make MUP prefix. */
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_DSD_ROUTE;

	if (afi == AFI_IP) {
		ipa_len = IPV4_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V4;
	} else {
		ipa_len = IPV6_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V6;
	}
	STREAM_GET(&p.prefix.dsd_route.ip.ip.addr, data, ipa_len);

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, NULL, 0, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, 0, NULL);
	goto done;

stream_failure:
	flog_err(EC_BGP_MUP_ROUTE_INVALID,
		 "%u:%s - Rx BGP-MUP DSD NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(data);
	return ret;
}

/*
 * Process received BGP-MUP Type 1 ST route (advertise or withdraw).
 */
static int bgp_mup_process_t1st_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_mup p = {};
	uint8_t prefix_len, endpoint_address_len;
	int ret = 0;
	uint32_t teid;

	if (psize < 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *data = stream_new(psize);
	stream_put(data, pfx, psize);

	/* Make prefix_rd. */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	STREAM_GET(&prd.val, data, 8);

	/* Make MUP prefix. */
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_T1ST_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T1ST_ROUTE;

	/* Get Prefix Length. */
	STREAM_GETC(data, prefix_len);
	p.prefix.t1st_route.ip_prefix_length = prefix_len;
	p.prefix.length = prefix_len;

	/* 
	 * If the AFI is IPv4, then the maximum value of the Prefix Length is 32 bits.
	 * If the AFI is IPv6, then the maximum value of the Prefix length is 128 bits.
	 */
	if ((afi == AFI_IP && prefix_len > 32) || (afi == AFI_IP6 && prefix_len > 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T1ST NLRI with invalid prefix length %d",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}

	/* Convert to bytes. */
	prefix_len = PSIZE(prefix_len);
	if (afi == AFI_IP)
		p.prefix.t1st_route.ip.ipa_type = IPADDR_V4;
	else
		p.prefix.t1st_route.ip.ipa_type = IPADDR_V6;
	STREAM_GET(&p.prefix.t1st_route.ip.ip.addr, data, prefix_len);

	/* TEID (4 octets) */
	STREAM_GET(&teid, data, 4);
	p.prefix.t1st_route.t1st_3gpp_5g.teid = teid;
	/* QFI (1 octet) */
	STREAM_GETC(data, p.prefix.t1st_route.t1st_3gpp_5g.qfi);
	/* Endpoint Address Length (1 octet) */
	STREAM_GETC(data, endpoint_address_len);
	p.prefix.t1st_route.t1st_3gpp_5g.endpoint_address_length = endpoint_address_len;
	/* Endpoint Address (variable) */
	endpoint_address_len = endpoint_address_len/8;
	STREAM_GET(&p.prefix.t1st_route.t1st_3gpp_5g.endpoint_address, data, endpoint_address_len);

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, NULL, 0, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, 0, NULL);
	goto done;

stream_failure:
	flog_err(EC_BGP_MUP_ROUTE_INVALID,
		 "%u:%s - Rx BGP-MUP T1ST NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(data);
	return ret;
}

/*
 * Process received BGP-MUP Type 2 ST route (advertise or withdraw).
 */
static int bgp_mup_process_t2st_route(struct peer *peer, afi_t afi, safi_t safi,
				     struct attr *attr, uint8_t *pfx, int psize,
				     uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_mup p = {};
	uint8_t endpoint_address_len;
	int ipa_len;
	int ret = 0;
	uint32_t teid;
	uint32_t teid_len;

	if (psize < 9) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *data = stream_new(psize);
	stream_put(data, pfx, psize);

	/* Make prefix_rd. */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	STREAM_GET(&prd.val, data, 8);

	/* Make MUP prefix. */
	p.family = AF_MUP;
	p.prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;

	/* Get Endpoint Address Length. */
	STREAM_GETC(data, endpoint_address_len);
	p.prefix.t2st_route.endpoint_address_length = endpoint_address_len;
	p.prefix.length = endpoint_address_len;

	/* 
	 * If the AFI is IPv4, then the Endpoint Address Length is greater than or equal to 32 bits.
	 * If the AFI is IPv6, then the Endpoint Address Length is greater than or equal to 128 bits.
	 */
	if ((afi == AFI_IP && endpoint_address_len < 32) || (afi == AFI_IP6 && endpoint_address_len < 128)) {
		flog_err(EC_BGP_MUP_ROUTE_INVALID,
			 "%u:%s - Rx BGP-MUP T2ST NLRI with invalid endpoint address length %d",
			 peer->bgp->vrf_id, peer->host, endpoint_address_len);
		return -1;
	}

	if (afi == AFI_IP) {
		p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V4;
		ipa_len = IPV4_MAX_BYTELEN;
		teid_len = endpoint_address_len - IPV4_MAX_BYTELEN * 8;
	} else {
		p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V6;
		ipa_len = IPV6_MAX_BYTELEN;
		teid_len = endpoint_address_len - IPV6_MAX_BYTELEN * 8;
	}
	STREAM_GET(&p.prefix.t2st_route.endpoint_address.ip.addr, data, ipa_len);

	/* TEID (4 octets) */
	STREAM_GET(&teid, data, teid_len/8);
	p.prefix.t2st_route.teid = ntohl(teid);

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, NULL, 0, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, 0, NULL);
	goto done;

stream_failure:
	flog_err(EC_BGP_MUP_ROUTE_INVALID,
		 "%u:%s - Rx BGP-MUP T2ST NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(data);
	return ret;
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
	uint8_t atype;
	uint16_t rtype;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* Deal with path-id if AddPath is supported. */
		if (addpath_capable) {
			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* All BGP-MUP NLRI types start with Architecture type, Route
		 * type and length. */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE;

		atype = *pnt;
		pnt++;
		memcpy(&rtype, pnt, sizeof(uint16_t));
		rtype = ntohs(rtype);
		pnt += 2;
		psize = *pnt;
		pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		switch (rtype) {
		case BGP_MUP_ISD_ROUTE: /* Interwork Segment Discovery route */
			if (bgp_mup_process_isd_route(peer, afi, safi,
						      withdraw ? NULL : attr,
						      pnt, psize, addpath_id)) {
				flog_err(
					EC_BGP_MUP_FAIL,
					"%u:%s - Error in processing BGP-MUP ISD NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_ISD_SIZE;
			}
			break;

		case BGP_MUP_DSD_ROUTE: /* Direct Segment Discovery route */
			if (bgp_mup_process_dsd_route(peer, afi, safi,
						      withdraw ? NULL : attr,
						      pnt, psize, addpath_id)) {
				flog_err(
					EC_BGP_EVPN_FAIL,
					"%u:%s - Error in processing BGP-MUP DSD NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_DSD_SIZE;
			}
			break;

		case BGP_MUP_T1ST_ROUTE: /* Type 1 Session Transformed (ST)
					    route */
			if (bgp_mup_process_t1st_route(
				    peer, afi, safi, withdraw ? NULL : attr,
				    pnt, psize, addpath_id)) {
				flog_err(
					EC_BGP_EVPN_FAIL,
					"%u:%s - Error in processing BGP-MUP T1ST NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_T1ST_SIZE;
			}
			break;

		case BGP_MUP_T2ST_ROUTE: /* Type 2 Session Transformed (ST)
					    route */
			if (bgp_mup_process_t2st_route(
				    peer, afi, safi, withdraw ? NULL : attr,
				    pnt, psize, addpath_id)) {
				flog_err(
					EC_BGP_EVPN_FAIL,
					"%u:%s - Error in processing BGP-MUP T2ST NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MUP_T2ST_SIZE;
			}
			break;

		default:
			break;
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}
