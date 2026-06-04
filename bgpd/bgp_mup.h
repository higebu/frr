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

/* On-wire field widths (draft-ietf-bess-mup-safi 3.1). */
#define BGP_MUP_ARCH_TYPE_BYTES	 1
#define BGP_MUP_ROUTE_TYPE_BYTES 2
#define BGP_MUP_LEN_BYTES	 1
#define BGP_MUP_HDR_BYTES  (BGP_MUP_ARCH_TYPE_BYTES + BGP_MUP_ROUTE_TYPE_BYTES + BGP_MUP_LEN_BYTES)
#define BGP_MUP_TEID_BYTES 4
#define BGP_MUP_QFI_BYTES  1
#define BGP_MUP_PREFIX_LEN_BYTES 1
#define BGP_MUP_ADDR_LEN_BYTES	 1

/* Optional TLVs trailing T1ST/T2ST route bodies (draft 3.1.5). */
#define BGP_MUP_TLV_HDR_BYTES	       2 /* Type + Length */
#define BGP_MUP_TLV_SESSION_PARAMS     1 /* 3gpp-5g Session Parameters */
#define BGP_MUP_TLV_INTERWORK_ENDPOINT 2
#define BGP_MUP_TLV_SOURCE_ADDRESS     3

/* Encoded size on the wire of one BGP-MUP NLRI. */
extern size_t bgp_mup_prefix_size(const struct prefix *p);

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
extern void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
				  const struct prefix_rd *prd, const struct attr *attr,
				  bool addpath_capable, uint32_t addpath_tx_id);

/* Parse all BGP-MUP NLRIs in an MP_REACH/MP_UNREACH attribute. */
extern int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);

/* Validate the optional TLV region of a T1ST/T2ST route body. */
extern int bgp_mup_parse_tlvs(uint16_t route_type, const uint8_t *buf, int len);

/* Add the decomposed MUP NLRI fields to a json object for show output. */
extern void bgp_mup_route2json(const struct prefix_mup *pm, struct json_object *json);

/* Render the optional TLVs kept with a T1ST/T2ST route. */
struct bgp_mup_nlri_data;
extern void bgp_mup_nlri_data_show(const struct bgp_mup_nlri_data *tlvs, uint16_t route_type,
				   struct vty *vty, struct json_object *json_path);

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

/* Free the per-(vrf, afi) MUP export policy (called from bgp_free). */
extern void bgp_mup_export_clear(struct bgp *bgp, afi_t afi);

/* Per-prefix ISD origination hooks for the generic redistribute /
 * static-route machinery (bgp_route.c).  Called when a locally-
 * originated route enters or leaves a (vrf, afi, SAFI_MUP) RIB.
 */
void bgp_mup_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi);
void bgp_mup_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi);

/* Re-resolve MUP route-map references and replay affected leak/install
 * paths when a route-map body changes.  Called from the BGP route-map
 * update dispatch (bgp_routemap.c), mirroring vpn_policy_routemap_event.
 */
void mup_policy_routemap_event(const char *rmap_name);

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
extern void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi);

/* Register BGP-MUP CLI commands under BGP_MUPV4_NODE / BGP_MUPV6_NODE. */
extern void bgp_mup_vty_init(void);

/* Invalidate the process-wide iface-state caches used by T1ST/T2ST
 * install (local IPv6 source, locator OIF).  Called from bgp_zebra.c
 * on every connected-address add/delete in @vrf_id.
 */
extern void bgp_mup_iface_addr_change(vrf_id_t vrf_id);

/* Free the process-wide BGP-MUP caches (called from bgp_exit). */
extern void bgp_mup_finish(void);

#endif /* _FRR_BGP_MUP_H */
