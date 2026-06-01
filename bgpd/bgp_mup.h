// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#ifndef _FRR_BGP_MUP_H
#define _FRR_BGP_MUP_H

#include "stream.h"
#include "lib/srv6.h"

#include "bgpd/bgpd.h"

/* prefix_mup carries the entire MUP route key in struct mup_prefix. */
#define BGP_MUP_ROUTE_PREFIXLEN (sizeof(struct mup_prefix) * 8)

/* Encoded size on the wire of one BGP-MUP NLRI. */
size_t bgp_mup_prefix_size(const struct prefix *p);

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, bool addpath_capable,
			   uint32_t addpath_tx_id);

/* Parse all BGP-MUP NLRIs in an MP_REACH/MP_UNREACH attribute. */
int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, int withdraw);

/* Translate a selected BGP-MUP route into a zapi route programming the
 * appropriate SRv6 Mobile User Plane action in the kernel.  Returns
 * the zclient send status (ZCLIENT_SEND_SUCCESS when no kernel state
 * is required for the route, e.g. ISD/DSD discovery routes that only
 * influence other route types' processing).
 */
int bgp_mup_zebra_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp);
int bgp_mup_zebra_withdraw(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp);

/* Free the per-bgp ISD/DSD discovery caches (called from bgp_free). */
void bgp_mup_caches_free(struct bgp *bgp);

/* Free the per-(vrf, afi) MUP export policy (called from bgp_free). */
void bgp_mup_export_clear(struct bgp *bgp, afi_t afi);

/* Per-prefix ISD origination hooks for the generic redistribute /
 * static-route machinery (bgp_route.c).  Called when a locally-
 * originated route enters or leaves a (vrf, afi, SAFI_MUP) RIB.
 */
void bgp_mup_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi);
void bgp_mup_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi);

/* SRv6 SID notify hook for the BGP-MUP origination path.  Returns
 * true when the notification matches a per-(vrf, afi) MUP policy
 * and has been consumed (the seg6_mobile-family local SID is now
 * installed and the policy is armed for ISD emit).
 */
bool bgp_mup_handle_sid_alloc(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
			      const struct in6_addr *sid, const char *loc_name);

/* Bgp-instance locator arrived (or was rebound): kick SID requests
 * for every (vrf, afi) MUP policy whose ISD origination is set to
 * SID_AUTO and has no SID pinned yet.
 */
void bgp_mup_locator_arrived(struct bgp *bgp);

/* An `sid ... locator NAME` override locator arrived: cache it on the
 * referencing MUP policies and re-kick their SID requests.
 */
void bgp_mup_override_locator_arrived(struct bgp *bgp, struct srv6_locator *locator);

/* Bgp-instance locator was deleted: release every local-SID install
 * that referenced @locator and drop the cached SID + ready latch on
 * the corresponding (vrf, afi) policies.
 */
void bgp_mup_locator_delete_purge(struct bgp *bgp, const struct srv6_locator *locator);

/* Emit BGP-MUP per-AFI commands under `address-family ipv4|ipv6 mup`
 * (placeholder for future SAFI-global knobs).  Called from bgp_vty.c.
 */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi);

/* Register BGP-MUP CLI commands under BGP_IPV4_MUP_NODE / BGP_IPV6_MUP_NODE. */
void bgp_mup_vty_init(void);

/* Invalidate the process-wide iface-state caches used by T1ST/T2ST
 * install (local IPv6 source, locator OIF).  Called from bgp_zebra.c
 * on every connected-address add/delete in @vrf_id.
 */
void bgp_mup_iface_addr_change(vrf_id_t vrf_id);

#endif /* _FRR_BGP_MUP_H */
