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

/* Locally originate ISD/DSD routes (FRR as MUP-PE/MUP-GW per
 * draft-ietf-bess-mup-safi).  T1ST/T2ST origination is intentionally
 * not provided: those routes carry per-session 5G state and are the
 * responsibility of an external MUP Controller (MUP-C).
 *
 * The advertised SID consists of the BGP instance's configured SRv6
 * locator + a function (RFC 8986 SID Structure).  Function allocation:
 *
 *   - Auto (default): bgpd asks zebra's SRv6 SID manager for a function
 *     under the configured locator (mirrors `sid vpn export auto`).
 *     zebra installs the local seg6local kernel state as a side-effect
 *     of allocation.
 *   - Explicit (`sid explicit X:X::X:X`): operator pins a specific SID
 *     (escape hatch for inter-AS / migration scenarios).
 *
 * Behavior:
 *   - ISD: MUST be End.M.GTP4.E (IPv4 AFI) / End.M.GTP6.E (IPv6 AFI)
 *     per draft Section 3.3.1; chosen automatically by AFI.
 *   - DSD: End.DT4 / End.DT6; operator picks via `behavior` keyword.
 */
struct ecommunity;
struct ipaddr;

/* Operator-facing parameters captured from VTY; shared between the two
 * route types so we keep the caller signature small.  See bgp_mup.c
 * for the synchronous (sid explicit) and async (auto-allocate) paths.
 */
struct bgp_mup_origin_args {
	afi_t afi;
	struct prefix_rd prd;
	struct ecommunity *ecom; /* RT (+ MUP for DSD); caller owns */
	bool has_explicit_sid;
	struct in6_addr explicit_sid; /* used iff has_explicit_sid */
	/* Per-route-type extras */
	struct prefix isd_prefix;   /* ISD only */
	struct ipaddr dsd_endpoint; /* DSD only */
	uint16_t dsd_behavior;	    /* DSD only: End.DT4 / End.DT6 */
};

int bgp_mup_originate_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args, bool withdraw);
void bgp_mup_vty_init(void);

/* Process-wide self-origin index init/finish.  Mirrors bgp_mac_init /
 * bgp_mac_finish: bm-scoped hashes that let receive-side T1ST/T2ST
 * resolution detect self-originated ISD/DSD in O(1).
 */
void bgp_mup_master_init(void);
void bgp_mup_master_finish(void);

/* Locator-arrival replay: called after zebra ships SRv6 locator chunks
 * to bgpd, so any `segment` lines that landed before chunks were
 * available finish their SID setup.  Same role as L3VPN's
 * vpn_leak_postchange_all().
 */
void bgp_mup_replay_origins_all(void);

/* Locator-delete hook: symmetric counterpart of
 * bgp_mup_replay_origins_all().  Called from bgp_zebra.c's
 * bgp_zebra_process_srv6_locator_delete_per_bgp() after the L3VPN
 * cleanup so MUP drops any persisted origin's install fingerprint
 * and OIF cache that resolved against the just-deleted locator,
 * and schedules a coalesced T1ST/T2ST reannounce on the affected
 * (bgp, afi).
 */
struct srv6_locator;
void bgp_mup_process_srv6_locator_delete_per_bgp(struct srv6_locator *loc, struct bgp *bgp);

/* Emit the persisted `segment` lines for `address-family ipv4|ipv6 mup`. */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi);

/* Emit the per-(vrf, afi) export-policy lines under
 * `address-family ipv[46] unicast`.  Sibling of L3VPN's
 * `rd vpn export` / `rt vpn export` / `sid vpn export` writeback in
 * bgp_vpn_policy_config_write_afi (bgpd/bgp_vty.c).
 */
void bgp_mup_export_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, int indent);

/* Free the per-bgp MUP state (origin/pending lists, ISD/DSD discovery
 * caches, per-AFI reannounce event).  Called from bgp_free.
 */
void bgp_mup_state_free(struct bgp *bgp);

/* Invalidate the process-wide iface-state caches used by T1ST/T2ST
 * install (local IPv6 source, locator OIF).  Called from bgp_zebra.c
 * on every connected-address add/delete in @vrf_id.
 */
void bgp_mup_iface_addr_change(vrf_id_t vrf_id);

/* SRv6 SID manager async completion: zebra returned a SID for one of
 * our pending originate requests.  Called from bgp_zebra.c's
 * ZAPI_SRV6_SID_ALLOCATED handler when the ctx's behavior is one of
 * the MUP behaviors (End.M.GTP*.E for ISD, End.DT/DX for DSD).
 */
struct srv6_sid_ctx;
bool bgp_mup_handle_sid_alloc(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
			      const struct in6_addr *sid_value);

/* L3VPN-style ISD origination from the VRF unicast RIB.
 *
 * mup_leak_from_vrf_update / _withdraw are sibling hooks placed next to
 * vpn_leak_from_vrf_update / _withdraw at every unicast RIB mutation in
 * bgp_route.c.  When the VRF's mup_export[afi] policy is configured
 * (rd / rt mup export at minimum), each selected, non-default unicast
 * route turns into an ISD NLRI in the default-VRF SAFI_MUP RIB.
 *
 * mup_leak_from_vrf_update_all / _withdraw_all are the bulk variants
 * used by the prechange/postchange dance in the export DEFPYs.
 *
 * mup_leak_prechange / _postchange wrap state mutations: prechange
 * withdraws all currently-leaked ISD NLRIs originated from this VRF/AFI,
 * postchange re-emits them from the current unicast RIB.
 *
 * to_bgp is always the default-VRF instance (bgp_get_default()); the
 * primitives are no-ops if either bgp is NULL or from_bgp is the
 * default-VRF instance.
 */
struct bgp_path_info;
void mup_leak_from_vrf_update(struct bgp *to_bgp, struct bgp *from_bgp,
			      struct bgp_path_info *path_vrf);
void mup_leak_from_vrf_withdraw(struct bgp *to_bgp, struct bgp *from_bgp,
				struct bgp_path_info *path_vrf);
void mup_leak_from_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi);
void mup_leak_from_vrf_withdraw_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi);
void mup_leak_prechange(afi_t afi, struct bgp *bgp);
void mup_leak_postchange(afi_t afi, struct bgp *bgp);

#endif /* _FRR_BGP_MUP_H */
