// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#ifndef _FRR_BGP_MUP_H
#define _FRR_BGP_MUP_H

#include "stream.h"

#include "bgpd/bgpd.h"

/* prefix_mup carries the entire MUP route key in struct mup_prefix. */
#define BGP_MUP_ROUTE_PREFIXLEN (sizeof(struct mup_prefix) * 8)

/* Encoded size on the wire of one BGP-MUP NLRI. */
extern size_t bgp_mup_prefix_size(const struct prefix *p);

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
extern void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
				  const struct prefix_rd *prd, bool addpath_capable,
				  uint32_t addpath_tx_id);

/* Parse all BGP-MUP NLRIs in an MP_REACH/MP_UNREACH attribute. */
extern int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      int withdraw);

/* Translate a selected BGP-MUP route into a zapi route programming the
 * appropriate SRv6 Mobile User Plane action in the kernel.  Returns
 * the zclient send status (ZCLIENT_SEND_SUCCESS when no kernel state
 * is required for the route, e.g. ISD/DSD discovery routes that only
 * influence other route types' processing).
 */
extern int bgp_mup_zebra_announce(struct bgp_dest *dest, struct bgp_path_info *info,
				  struct bgp *bgp);
extern int bgp_mup_zebra_withdraw(struct bgp_dest *dest, struct bgp_path_info *info,
				  struct bgp *bgp);

/* Free the per-bgp ISD/DSD discovery caches (called from bgp_free). */
extern void bgp_mup_caches_free(struct bgp *bgp);

#endif /* _FRR_BGP_MUP_H */
