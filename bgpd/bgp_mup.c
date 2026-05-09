// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */

#include "hash.h"
#include "jhash.h"
#include "linklist.h"
#include "prefix.h"
#include "routemap.h"
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
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_STATE, "BGP MUP per-bgp state");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_STR, "BGP MUP string");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_IFACE_CACHE, "BGP MUP iface cache entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_SELF_KEY, "BGP MUP self-origin key");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_EXPORT, "BGP MUP per-vrf-per-afi export policy");

/* Per-bgp MUP state — pulled out of `struct bgp` so MUP-internal
 * typesafe heads stay private to this translation unit.  Lazily
 * allocated on first need by bgp_mup_state_get(); freed by
 * bgp_mup_state_free() in the bgp teardown path.
 */
PREDECL_LIST(bgp_mup_pending_list);
PREDECL_LIST(bgp_mup_origin_list);
PREDECL_HASH(bgp_mup_isd_hash);
PREDECL_HASH(bgp_mup_dsd_hash);
PREDECL_HASH(bgp_mup_dsd_segid_hash);

struct bgp_mup_state {
	struct bgp_mup_pending_list_head pending;
	struct bgp_mup_origin_list_head origins;
	struct bgp_mup_isd_hash_head isd_hash;
	struct route_table *isd_lpm[AFI_MAX];
	struct bgp_mup_dsd_hash_head dsd_hash;
	struct bgp_mup_dsd_segid_hash_head dsd_segid_hash;
	/* Per-AFI coalescing event for T1ST/T2ST reannounce after a cache
	 * mutation.  One pending event collapses a flood of mutations
	 * within a single UPDATE into a single RIB walk.
	 */
	struct event *reannounce_ev[AFI_MAX];
};

static struct bgp_mup_state *bgp_mup_state_get(struct bgp *bgp);

/* Per-vrf-per-afi MUP policy.  Mirrors L3VPN's vpn_policy[afi]: RD,
 * RT list (both directions), and SID allocation knob configured under
 * `address-family ipv[46] unicast` on a non-default-VRF instance via
 * `rd mup export`, `rt mup <import|export|both>`, and
 * `sid mup export`.
 *
 * The rtlist[] array indexes by direction so a single policy struct
 * holds both the export RT list (attached to leaked ISDs) and the
 * import RT list (gates which received MUP NLRIs install in this vrf).
 * Mirrors bgp_mplsvpn.c's vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_*].
 *
 * Lazily allocated by bgp_mup_export_get() on first CLI mutation;
 * freed by bgp_mup_state_free() on instance teardown.
 */
enum bgp_mup_policy_dir {
	BGP_MUP_POLICY_DIR_FROMMUP = 0,
	BGP_MUP_POLICY_DIR_TOMUP = 1,
	BGP_MUP_POLICY_DIR_MAX = 2,
};

struct bgp_mup_export_policy {
	uint32_t flags;
#define BGP_MUP_EXPORT_RD_SET (1U << 0)
#define BGP_MUP_EXPORT_SID_AUTO (1U << 1)
#define BGP_MUP_EXPORT_SID_EXPLICIT (1U << 2)
#define BGP_MUP_EXPORT_NEXTHOP_SET (1U << 3)
/* Operator explicitly enabled ISD origination for this (vrf, afi)
 * via `segment mup export interwork`.
 */
#define BGP_MUP_EXPORT_SEGMENT_INTERWORK (1U << 4)
/* Operator explicitly enabled DSD origination for this (vrf, afi)
 * via `segment mup export direct [address X]`.
 */
#define BGP_MUP_EXPORT_SEGMENT_DIRECT (1U << 5)
/* DSD address was set explicitly via `segment mup export direct
 * address X` (otherwise default to router-id).
 */
#define BGP_MUP_EXPORT_DSD_ADDRESS_SET (1U << 6)

	char *tovpn_rd_pretty;
	struct prefix_rd tovpn_rd;
	struct ecommunity *rtlist[BGP_MUP_POLICY_DIR_MAX];

	/* Per-direction route-map plumbing.  Mirrors L3VPN's
	 * vpn_policy[afi].rmap_name[] / .rmap[] in bgpd/bgp_mplsvpn.c —
	 * configured via `route-map mup <import|export> RMAP` under
	 * `address-family ipv[46] unicast`.  The TOMUP slot filters
	 * VRF→MUP leaked ISDs (mup_leak_from_vrf_update); the FROMMUP
	 * slot is reserved for receive-side filtering (Phase 2; the
	 * Phase 1 CLI stores the value but does not apply it).
	 */
	char *rmap_name[BGP_MUP_POLICY_DIR_MAX];
	struct route_map *rmap[BGP_MUP_POLICY_DIR_MAX];

	/* Optional per-policy locator override.  NULL => fall back to
	 * bgp->srv6_locator_name.  Deliberate deviation from L3VPN's
	 * single-locator-per-bgp baseline: MUP encodes behavior in the
	 * SID's function (End.M.GTP4.E vs End.M.GTP6.E), so per-AFI/
	 * per-slice locator partitioning is operationally meaningful.
	 */
	char *locator_name;

	/* Per-(vrf, afi) SID, allocated via the SRv6 SID manager with
	 * behavior = ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E for AFI_IP and
	 * END_M_GTP6_E for AFI_IP6.  tovpn_sid is the running value
	 * (auto or explicit copied here for emit); tovpn_sid_explicit
	 * preserves the operator override; tovpn_sid_ready latches once
	 * a SID is usable.
	 */
	struct in6_addr tovpn_sid;
	struct in6_addr tovpn_sid_explicit;
	bool tovpn_sid_ready;

	/* Operator-set IPv6 next-hop carried in originated ISD/DSD
	 * MP_REACH.  When unset, the locally-built attribute leaves
	 * mp_nexthop_global zero (matching prior behavior).  IPv4 input is
	 * stored as IPv4-mapped IPv6 (::ffff:A.B.C.D) so the emit path
	 * stays uniform — MUP NLRIs always carry an IPv6 next-hop per
	 * draft-ietf-bess-mup-safi.  Mirrors L3VPN's
	 * BGP_VPN_POLICY_TOVPN_NEXTHOP_SET / tovpn_nexthop pair in
	 * bgpd/bgp_mplsvpn.c.
	 */
	struct in6_addr tovpn_nexthop;
	bool tovpn_nexthop_was_v4;

	/* Install fingerprint, mirrors bgp_mup_origin's last_installed_*
	 * but lives on the per-(vrf, afi) policy because the new path
	 * shares one SID across every leaked ISD prefix.
	 */
	struct in6_addr last_installed_sid;
	enum seg6local_action_t last_installed_act;

	/* DSD scalar (segment mup export direct) origination metadata.
	 * DSD is a single-NLRI knob per (vrf, afi): the originator-address
	 * defaults to the speaker's router-id and can be overridden via
	 * `segment mup export direct address X`; the End.DT* behavior is
	 * configured via `behavior mup export <dt4|dt6|dt46>`; the MUP
	 * extended community is configured via `ext-community mup export
	 * ASN:NN`.  RD/RT/SID come from the shared `rd mup export` /
	 * `rt mup export` / `sid mup export` knobs already on this policy.
	 */
	struct ipaddr dsd_address;
	uint16_t dsd_behavior; /* End.DT4 / End.DT6 / End.DT46 */
	uint32_t dsd_mup_as;
	uint32_t dsd_mup_val;
	char *dsd_mup_str; /* verbatim for writeback */
};

/* Resolve the locator name an export policy should use.  Returns the
 * per-policy override when set, otherwise the bgp instance's default.
 * NULL or empty means "no locator known yet".
 */
static const char *bgp_mup_export_locname(const struct bgp *bgp,
					  const struct bgp_mup_export_policy *ep)
{
	if (ep && ep->locator_name && ep->locator_name[0] != '\0')
		return ep->locator_name;
	if (bgp && bgp->srv6_locator_name[0] != '\0')
		return bgp->srv6_locator_name;
	return NULL;
}

/* True iff @name matches the bgp's primary locator OR any per-(vrf, afi)
 * MUP export-policy override across the bgp master list.  Used by the
 * SRv6 locator chunk receive path so chunks for MUP-tracked locators are
 * not dropped just because they don't match the per-bgp primary name.
 */
bool bgp_mup_locator_name_is_tracked(const char *name)
{
	struct listnode *node;
	struct bgp *bgp;
	afi_t afi;

	if (!name || name[0] == '\0' || !bm)
		return false;
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			struct bgp_mup_export_policy *ep = bgp->mup_export[afi];

			if (ep && ep->locator_name && ep->locator_name[0] &&
			    strcmp(ep->locator_name, name) == 0)
				return true;
		}
	}
	return false;
}

static struct bgp_mup_export_policy *bgp_mup_export_get(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	if (bgp->mup_export[afi])
		return bgp->mup_export[afi];
	bgp->mup_export[afi] = XCALLOC(MTYPE_BGP_MUP_EXPORT, sizeof(*bgp->mup_export[afi]));
	bgp->mup_export[afi]->last_installed_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	return bgp->mup_export[afi];
}

static struct bgp_mup_export_policy *bgp_mup_export_peek(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	return bgp->mup_export[afi];
}

static void bgp_mup_export_clear(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *p;
	enum bgp_mup_policy_dir dir;

	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	p = bgp->mup_export[afi];
	if (!p)
		return;
	XFREE(MTYPE_BGP_NAME, p->tovpn_rd_pretty);
	for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
		if (p->rtlist[dir])
			ecommunity_free(&p->rtlist[dir]);
		XFREE(MTYPE_ROUTE_MAP_NAME, p->rmap_name[dir]);
		p->rmap[dir] = NULL;
	}
	XFREE(MTYPE_BGP_NAME, p->locator_name);
	XFREE(MTYPE_BGP_MUP_STR, p->dsd_mup_str);
	XFREE(MTYPE_BGP_MUP_EXPORT, bgp->mup_export[afi]);
}

/* Peek accessors: return a pointer to the per-bgp state's sub-head, or
 * NULL when no state has been allocated yet for this bgp.  Used by
 * read-only call sites that want to skip the work entirely on a
 * never-touched instance instead of force-allocating state.
 */
static inline struct bgp_mup_pending_list_head *bgp_mup_state_pending(struct bgp *bgp)
{
	return bgp->mup_state ? &bgp->mup_state->pending : NULL;
}

static inline struct bgp_mup_origin_list_head *bgp_mup_state_origins(struct bgp *bgp)
{
	return bgp->mup_state ? &bgp->mup_state->origins : NULL;
}

static inline struct bgp_mup_isd_hash_head *bgp_mup_state_isd_hash(struct bgp *bgp)
{
	return bgp->mup_state ? &bgp->mup_state->isd_hash : NULL;
}

static inline struct route_table *bgp_mup_state_isd_lpm(struct bgp *bgp, afi_t afi)
{
	if (!bgp->mup_state || (afi != AFI_IP && afi != AFI_IP6))
		return NULL;
	return bgp->mup_state->isd_lpm[afi];
}

static inline struct bgp_mup_dsd_hash_head *bgp_mup_state_dsd_hash(struct bgp *bgp)
{
	return bgp->mup_state ? &bgp->mup_state->dsd_hash : NULL;
}

static inline struct bgp_mup_dsd_segid_hash_head *bgp_mup_state_dsd_segid_hash(struct bgp *bgp)
{
	return bgp->mup_state ? &bgp->mup_state->dsd_segid_hash : NULL;
}

/* Self-origin index entry for DSD: the receive-side bgp_mup_dsd_is_self()
 * lookup key is the 48-bit MUP-EC Direct-Type Segment Identifier from the
 * operator's `segment direct ... mup AS:VAL` line.  One entry per
 * persisted DSD `segment` line.  ISD self-detection is no longer hashed —
 * with ISD origination driven from the per-(vrf, afi) export policy, the
 * receive-side check is a runtime walk over bm->bgp->mup_export[afi].
 */
struct bgp_mup_self_dsd_key {
	uint64_t segment_id;
};

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

	bgp_mup_prd_from_bytes(&prd, pfx);

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

/* Persistent record of one operator-configured `segment` line.  Lives on
 * the per-vrf bgp instance under whose `address-family ipv[46] mup`
 * block the `segment ...` was typed.  Survives SID alloc/release so
 * `show running-config` can re-emit, and powers the RT-match install
 * filter (bgp_mup_match_install_vrf).
 */
struct bgp_mup_origin {
	struct bgp_mup_origin_list_item item;
	afi_t afi;
	struct prefix_rd prd;
	struct ipaddr dsd_endpoint;
	uint16_t dsd_behavior;
	bool has_explicit_sid;
	struct in6_addr explicit_sid; /* iff has_explicit_sid */
	char *rt_str;
	/* Pre-parsed form of rt_str.  Allocated once at persist time so the
	 * RT-match hot path (bgp_mup_any_vrf_imports / bgp_mup_match_install_vrf
	 * legacy fallback) and the locator-arrival replay
	 * (bgp_mup_replay_origin) avoid re-tokenising on every UPDATE.
	 * rt_str is kept as the verbatim source for `show running-config`
	 * and the `no segment ... rt RT` string match.
	 */
	struct ecommunity *rt_ecom;
	char *mup_str;
	/* Pre-parsed 48-bit segment id (mup_as<<32 | mup_val) cached at
	 * persist time so the receive-side self-DSD lookup and the per-
	 * UPDATE bgp_mup_origin_segment_id() avoid re-running sscanf on
	 * every match.
	 */
	uint64_t segment_id;
	bool has_segment_id;
	/* In-memory marker: this origin already has its SID assigned by
	 * zebra (or via `sid explicit`) and the local install has been
	 * issued.  Reset on bgpd restart, so the locator-arrival hook
	 * (bgp_mup_replay_origins) re-runs `segment` lines that landed
	 * before chunks were ready.  Same posture as L3VPN's
	 * vpn_leak_zebra_vrf_sid_update_per_vrf re-running on every
	 * locator postchange.
	 */
	bool sid_ready;
	/* Fingerprint of the last (sid, action) pair pushed to zebra via
	 * zclient_send_localsid().  Used to suppress redundant netlink
	 * installs when a locator postchange replays a `segment` line
	 * whose SID and behavior are unchanged.  Mirrors what
	 * bgp_mup_originate_common() already does on the BGP RIB side via
	 * attrhash_cmp().  Cleared on withdraw and on free.
	 */
	struct in6_addr last_installed_sid;
	enum seg6local_action_t last_installed_act;
};
DECLARE_LIST(bgp_mup_origin_list, struct bgp_mup_origin, item);

static struct bgp_mup_isd_hash_head *bgp_mup_get_isd_hash(struct bgp *bgp)
{
	return &bgp_mup_state_get(bgp)->isd_hash;
}

static struct route_table *bgp_mup_get_isd_lpm(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_state *st;

	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	st = bgp_mup_state_get(bgp);
	if (!st->isd_lpm[afi])
		st->isd_lpm[afi] = route_table_init();
	return st->isd_lpm[afi];
}

static struct bgp_mup_dsd_hash_head *bgp_mup_get_dsd_hash(struct bgp *bgp)
{
	return &bgp_mup_state_get(bgp)->dsd_hash;
}

static struct bgp_mup_dsd_segid_hash_head *bgp_mup_get_dsd_segid_hash(struct bgp *bgp)
{
	return &bgp_mup_state_get(bgp)->dsd_segid_hash;
}

/* Parse a MUP segment identifier "ASN:NN" string into its 16-bit AS
 * and 32-bit value parts.  The on-wire MUP-EC encodes these in a
 * 2-byte and 4-byte field respectively; values exceeding those widths
 * are rejected here so the on-wire encoding never silently truncates.
 */
static bool bgp_mup_parse_seg_id_str(const char *mup_str, uint16_t *mup_as,
				     uint32_t *mup_val)
{
	const char *colon;
	char *endp;
	unsigned long long lhs, rhs;

	if (!mup_str)
		return false;
	colon = strchr(mup_str, ':');
	if (!colon || colon == mup_str || !colon[1])
		return false;
	lhs = strtoull(mup_str, &endp, 10);
	if (endp != colon)
		return false;
	rhs = strtoull(colon + 1, &endp, 10);
	if (*endp != '\0')
		return false;
	if (lhs > UINT16_MAX || rhs > UINT32_MAX)
		return false;
	*mup_as = (uint16_t)lhs;
	*mup_val = (uint32_t)rhs;
	return true;
}

/* Build a MUP Extended Community of subtype Direct-Type Segment
 * Identifier (draft-ietf-bess-mup-safi Section 3.2) from an "ASN:NN"
 * operator string.  Returns the ecommunity (caller frees) on success
 * or NULL on parse failure.
 */
static struct ecommunity *bgp_mup_build_mup_ec(const char *mup_str)
{
	uint16_t mup_as = 0;
	uint32_t mup_val = 0;
	struct ecommunity_val ev = { 0 };
	struct ecommunity *ec;

	if (!bgp_mup_parse_seg_id_str(mup_str, &mup_as, &mup_val))
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

static struct bgp_mup_isd_entry *bgp_mup_isd_find(struct bgp *bgp, afi_t afi,
						  const struct prefix_rd *prd,
						  const struct prefix *prefix)
{
	struct bgp_mup_isd_entry needle = {};

	if (!bgp_mup_state_isd_hash(bgp))
		return NULL;
	needle.afi = afi;
	needle.prd = *prd;
	needle.prefix = *prefix;
	return bgp_mup_isd_hash_find(bgp_mup_state_isd_hash(bgp), &needle);
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
	struct route_table *table = bgp_mup_state_isd_lpm(bgp, afi);
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

	if (!bgp_mup_state_dsd_hash(bgp))
		return NULL;
	needle.afi = afi;
	needle.prd = *prd;
	needle.endpoint = *endpoint;
	return bgp_mup_dsd_hash_find(bgp_mup_state_dsd_hash(bgp), &needle);
}

/* Lookup a DSD by MUP-EC Direct-Type Segment Identifier. */
static struct bgp_mup_dsd_entry *bgp_mup_dsd_lookup(struct bgp *bgp, uint64_t segment_id)
{
	struct bgp_mup_dsd_entry needle = {};

	if (!bgp_mup_state_dsd_segid_hash(bgp))
		return NULL;
	needle.segment_id = segment_id;
	return bgp_mup_dsd_segid_hash_find(bgp_mup_state_dsd_segid_hash(bgp), &needle);
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
	struct route_table *table = bgp_mup_state_isd_lpm(bgp, e->afi);
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
	bgp_mup_isd_hash_del(bgp_mup_state_isd_hash(bgp), e);
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
	bgp_mup_dsd_segid_hash_del(bgp_mup_state_dsd_segid_hash(bgp), e);
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
	bgp_mup_dsd_hash_del(bgp_mup_state_dsd_hash(bgp), e);
	XFREE(MTYPE_BGP_MUP_DSD, e);
	bgp_mup_schedule_reannounce_st_routes(bgp, afi);
}

/* Folded into bgp_mup_state_free near the bottom of this file. */

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
static struct interface *bgp_mup_locator_oif_compute(vrf_id_t vrf_id, const struct in6_addr *sid)
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
			struct prefix sid_p = {
				.family = AF_INET6,
				.prefixlen = IPV6_MAX_BITLEN,
				.u.prefix6 = *sid,
			};

			if (p->family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
				continue;
			has_global_v6 = true;
			if (p->prefixlen >= IPV6_MAX_BITLEN)
				continue;
			if (prefix_match(p, &sid_p))
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

/* Cache for bgp_mup_local_v6_source / bgp_mup_locator_oif results.
 * Both helpers walk every interface × every connected address per
 * T1ST/T2ST install; the answers almost never change.  Memoise per
 * vrf and per (vrf, locator block) respectively, invalidated on every
 * connected-address add/delete via bgp_mup_iface_addr_change()
 * (called from bgp_zebra.c's address handlers).
 *
 * Locator-block keying assumes the SR underlay's connected prefix is
 * at least as wide as the operator's locator block (the typical
 * deployment).  All SIDs under one block then resolve to the same
 * interface and share one cache slot.
 */
PREDECL_LIST(bgp_mup_v6src_cache);
struct bgp_mup_v6src_cache_entry {
	struct bgp_mup_v6src_cache_item item;
	vrf_id_t vrf_id;
	bool valid; /* false = remembered "no global v6 in this vrf" */
	struct in6_addr addr;
};
DECLARE_LIST(bgp_mup_v6src_cache, struct bgp_mup_v6src_cache_entry, item);

PREDECL_LIST(bgp_mup_oif_cache);
struct bgp_mup_oif_cache_entry {
	struct bgp_mup_oif_cache_item item;
	vrf_id_t vrf_id;
	struct prefix_ipv6 block; /* SID truncated to loc_block_len bits */
	ifindex_t ifindex;	  /* IFINDEX_INTERNAL = remembered miss */
};
DECLARE_LIST(bgp_mup_oif_cache, struct bgp_mup_oif_cache_entry, item);

static struct bgp_mup_v6src_cache_head bgp_mup_v6src_cache;
static struct bgp_mup_oif_cache_head bgp_mup_oif_cache;
static bool bgp_mup_iface_cache_inited;

static void bgp_mup_iface_cache_init_once(void)
{
	if (bgp_mup_iface_cache_inited)
		return;
	bgp_mup_v6src_cache_init(&bgp_mup_v6src_cache);
	bgp_mup_oif_cache_init(&bgp_mup_oif_cache);
	bgp_mup_iface_cache_inited = true;
}

void bgp_mup_iface_addr_change(vrf_id_t vrf_id)
{
	struct bgp_mup_v6src_cache_entry *v;
	struct bgp_mup_oif_cache_entry *o;

	if (!bgp_mup_iface_cache_inited)
		return;
	frr_each_safe (bgp_mup_v6src_cache, &bgp_mup_v6src_cache, v) {
		if (v->vrf_id != vrf_id)
			continue;
		bgp_mup_v6src_cache_del(&bgp_mup_v6src_cache, v);
		XFREE(MTYPE_BGP_MUP_IFACE_CACHE, v);
	}
	frr_each_safe (bgp_mup_oif_cache, &bgp_mup_oif_cache, o) {
		if (o->vrf_id != vrf_id)
			continue;
		bgp_mup_oif_cache_del(&bgp_mup_oif_cache, o);
		XFREE(MTYPE_BGP_MUP_IFACE_CACHE, o);
	}
}

/* Return an interface whose connected covers @sid, or a fallback
 * non-loopback interface carrying any non-LL global IPv6 in @vrf_id.
 * Result is cached per (vrf_id, locator block) where the block is
 * the high @block_len bits of @sid.
 */
static struct interface *bgp_mup_locator_oif(vrf_id_t vrf_id, const struct in6_addr *sid,
					     uint8_t block_len)
{
	struct bgp_mup_oif_cache_entry *e;
	struct prefix_ipv6 block = { .family = AF_INET6, .prefixlen = block_len };
	struct interface *ifp;

	block.prefix = *sid;
	apply_mask_ipv6(&block);

	bgp_mup_iface_cache_init_once();
	frr_each (bgp_mup_oif_cache, &bgp_mup_oif_cache, e) {
		if (e->vrf_id != vrf_id)
			continue;
		if (e->block.prefixlen != block.prefixlen)
			continue;
		if (memcmp(&e->block.prefix, &block.prefix, sizeof(struct in6_addr)) != 0)
			continue;
		if (e->ifindex == IFINDEX_INTERNAL)
			return NULL;
		return if_lookup_by_index(e->ifindex, vrf_id);
	}
	ifp = bgp_mup_locator_oif_compute(vrf_id, sid);
	e = XCALLOC(MTYPE_BGP_MUP_IFACE_CACHE, sizeof(*e));
	e->vrf_id = vrf_id;
	e->block = block;
	e->ifindex = ifp ? ifp->ifindex : IFINDEX_INTERNAL;
	bgp_mup_oif_cache_add_tail(&bgp_mup_oif_cache, e);
	return ifp;
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

enum bgp_mup_t1st_status {
	BGP_MUP_T1ST_OK,
	BGP_MUP_T1ST_NO_ISD,
	BGP_MUP_T1ST_SELF,
};

static bool bgp_mup_isd_is_self(afi_t afi, const struct prefix_rd *prd,
				const struct prefix *isd_prefix);

/* Resolve T1ST endpoint via the ISD discovery cache.  Single LPM walk:
 * the caller used to look up the ISD twice (once for the self-origin
 * loop guard, once here for SID synthesis).
 */
static enum bgp_mup_t1st_status bgp_mup_resolve_t1st(struct bgp *bgp, const struct mup_prefix *mp,
						     struct bgp_mup_t1st_resolved *out)
{
	const struct mup_t1st_3gpp_5g *ext = &mp->t1st_route.t1st_3gpp_5g;
	struct bgp_mup_isd_entry *isd;
	afi_t afi;

	afi = (ext->endpoint_address.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	isd = bgp_mup_isd_lookup(bgp, afi, &ext->endpoint_address);
	if (!isd)
		return BGP_MUP_T1ST_NO_ISD;
	if (bgp_mup_isd_is_self(afi, &isd->prd, &isd->prefix))
		return BGP_MUP_T1ST_SELF;
	if (!bgp_mup_synthesize_t1st_sid(isd, &mp->t1st_route, &out->sid)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: T1ST SID synthesis failed (loc_func=%u behavior=%u)",
				   isd->loc_block_len + isd->loc_node_len + isd->func_len,
				   isd->behavior);
		return BGP_MUP_T1ST_NO_ISD;
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
	return out->have_outer_sa ? BGP_MUP_T1ST_OK : BGP_MUP_T1ST_NO_ISD;
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
				     const struct bgp_mup_dsd_entry *dsd, struct zapi_route *api)
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
	ifp = bgp_mup_locator_oif(VRF_DEFAULT, &dsd->sid, dsd->loc_block_len);
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

/* Forward decl: defined below near bgp_mup_match_install_vrf but used
 * by bgp_mup_isd_apply/bgp_mup_dsd_apply above it.
 */
static bool bgp_mup_any_vrf_imports(afi_t afi, const struct attr *attr);

/* Cache an ISD route into the discovery table, or remove it on
 * withdraw (attr == NULL).  Treat-as-withdraw on any structural error
 * (no Prefix-SID, malformed SID-Structure, etc).
 */
static void bgp_mup_isd_apply(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp,
			      const struct attr *attr)
{
	struct prefix_rd prd = {};
	struct prefix prefix = {};
	struct in6_addr sid;
	uint8_t block, node, func, arg;
	uint16_t behavior;

	if (attr) {
		if (!bgp_mup_get_sid_structure(attr, &sid, &block, &node, &func, &arg, &behavior)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: ISD without Prefix-SID; ignoring");
			return;
		}
		if (!bgp_mup_any_vrf_imports(afi, attr)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: ISD RT not imported by any vrf; skip cache");
			return;
		}
	}
	bgp_mup_prd_from_bytes(&prd, mp->rd);
	prefix.family = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
	prefix.prefixlen = mp->isd_route.ip_prefix_length;
	if (prefix.family == AF_INET)
		prefix.u.prefix4 = mp->isd_route.ip.ipaddr_v4;
	else
		prefix.u.prefix6 = mp->isd_route.ip.ipaddr_v6;
	if (attr)
		bgp_mup_isd_cache_upsert(bgp, afi, &prd, &prefix, &sid, block, node, func, arg,
					 behavior);
	else
		bgp_mup_isd_cache_remove(bgp, afi, &prd, &prefix);
}

static void bgp_mup_dsd_apply(struct bgp *bgp, afi_t afi, const struct mup_prefix *mp,
			      const struct attr *attr)
{
	struct prefix_rd prd = {};
	struct in6_addr sid;
	uint8_t block, node, func, arg;
	uint16_t behavior;
	uint64_t segment_id = 0;
	bool has_seg = false;

	if (attr) {
		if (!bgp_mup_get_sid_structure(attr, &sid, &block, &node, &func, &arg, &behavior)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: DSD without Prefix-SID; ignoring");
			return;
		}
		if (!bgp_mup_any_vrf_imports(afi, attr)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: DSD RT not imported by any vrf; skip cache");
			return;
		}
		has_seg = bgp_mup_get_direct_seg_id(attr, &segment_id);
	}
	bgp_mup_prd_from_bytes(&prd, mp->rd);
	if (attr)
		bgp_mup_dsd_cache_upsert(bgp, afi, &prd, &mp->dsd_route.ip, &sid, block, node,
					 func, arg, behavior, has_seg, segment_id);
	else
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

/* Return a persisted `segment direct` origin's pre-parsed Direct-Type
 * Segment Identifier (48 bits, packed mup_as<<32 | mup_val).  The
 * value is cached at persist time by bgp_mup_origin_persist().
 */
static bool bgp_mup_origin_segment_id(const struct bgp_mup_origin *o, uint64_t *out)
{
	if (!o->has_segment_id)
		return false;
	*out = o->segment_id;
	return true;
}

/* DSD self-origin index hash machinery.  bm->mup_self_dsd_hash is
 * populated from bgp_mup_origin_persist (insert) and drained from
 * bgp_mup_origin_forget / bgp_mup_state_free (remove), so the
 * receive-side bgp_mup_dsd_is_self() answers in O(1) instead of
 * walking every per-vrf bgp instance's mup_origins list per UPDATE.
 */
static unsigned int bgp_mup_self_dsd_hash_key(const void *data)
{
	const struct bgp_mup_self_dsd_key *k = data;

	return jhash_2words((uint32_t)(k->segment_id >> 32), (uint32_t)k->segment_id, 0xd5d5dead);
}

static bool bgp_mup_self_dsd_hash_cmp(const void *d1, const void *d2)
{
	const struct bgp_mup_self_dsd_key *a = d1;
	const struct bgp_mup_self_dsd_key *b = d2;

	return a->segment_id == b->segment_id;
}

static void *bgp_mup_self_dsd_alloc(void *data)
{
	void *e = XCALLOC(MTYPE_BGP_MUP_SELF_KEY, sizeof(struct bgp_mup_self_dsd_key));

	memcpy(e, data, sizeof(struct bgp_mup_self_dsd_key));
	return e;
}

static void bgp_mup_self_key_free(void *data)
{
	XFREE(MTYPE_BGP_MUP_SELF_KEY, data);
}

void bgp_mup_master_init(void)
{
	bm->mup_self_dsd_hash = hash_create(bgp_mup_self_dsd_hash_key, bgp_mup_self_dsd_hash_cmp,
					    "BGP MUP self DSD hash");
}

void bgp_mup_master_finish(void)
{
	struct bgp_mup_v6src_cache_entry *v;
	struct bgp_mup_oif_cache_entry *o;

	hash_clean_and_free(&bm->mup_self_dsd_hash, bgp_mup_self_key_free);

	if (bgp_mup_iface_cache_inited) {
		frr_each_safe (bgp_mup_v6src_cache, &bgp_mup_v6src_cache, v) {
			bgp_mup_v6src_cache_del(&bgp_mup_v6src_cache, v);
			XFREE(MTYPE_BGP_MUP_IFACE_CACHE, v);
		}
		frr_each_safe (bgp_mup_oif_cache, &bgp_mup_oif_cache, o) {
			bgp_mup_oif_cache_del(&bgp_mup_oif_cache, o);
			XFREE(MTYPE_BGP_MUP_IFACE_CACHE, o);
		}
		bgp_mup_v6src_cache_fini(&bgp_mup_v6src_cache);
		bgp_mup_oif_cache_fini(&bgp_mup_oif_cache);
		bgp_mup_iface_cache_inited = false;
	}
}

static void bgp_mup_self_dsd_index_add(uint64_t segment_id)
{
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };

	if (!bm->mup_self_dsd_hash)
		return;
	(void)hash_get(bm->mup_self_dsd_hash, &tmp, bgp_mup_self_dsd_alloc);
}

static void bgp_mup_self_dsd_index_del(uint64_t segment_id)
{
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };
	struct bgp_mup_self_dsd_key *e;

	if (!bm->mup_self_dsd_hash)
		return;
	e = hash_release(bm->mup_self_dsd_hash, &tmp);
	if (e)
		bgp_mup_self_key_free(e);
}

/* Loop guard for self-origin: returns true iff the (afi, RD) matches a
 * per-(vrf, afi) ISD export policy on any per-vrf bgp instance on this
 * PE.  Mirrors bgp_mplsvpn.c's vpn_leak_to_vrf_update loop check
 * (`bgp_orig != bgp`): without it, a T1ST received over the BGP-MUP
 * session whose RT also imports into our own per-vrf instance would
 * resolve against our self-originated ISD and produce a non-functional
 * install (synth SID lands in our own locator; packet would loop or
 * get dropped).
 *
 * Walks bm->bgp instead of consulting a hash because ISD origination is
 * now driven from the per-(vrf, afi) export policy rather than per-prefix
 * `segment` lines: the comparison key collapses from (afi, RD, prefix)
 * to (afi, RD) and an O(N_vrf) walk per resolve is cheap.
 */
static bool bgp_mup_isd_is_self(afi_t afi, const struct prefix_rd *prd,
				const struct prefix *isd_prefix)
{
	struct listnode *node;
	struct bgp *bgp;

	(void)isd_prefix;
	if (afi != AFI_IP && afi != AFI_IP6)
		return false;
	if (!bm || !bm->bgp)
		return false;
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_mup_export_policy *ep;

		if (bgp->vrf_id == VRF_DEFAULT)
			continue;
		ep = bgp->mup_export[afi];
		if (!ep || !(ep->flags & BGP_MUP_EXPORT_RD_SET))
			continue;
		if (memcmp(ep->tovpn_rd.val, prd->val, sizeof(prd->val)) == 0)
			return true;
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
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };

	if (!bm->mup_self_dsd_hash)
		return false;
	return hash_lookup(bm->mup_self_dsd_hash, &tmp);
}

/* Forward decl: bgp_mup_afi_from_prefix is defined below near
 * bgp_mup_zebra_install but used by bgp_mup_st_announce above it.
 */
static afi_t bgp_mup_afi_from_prefix(const struct mup_prefix *mp);

/* True iff any RT carried on `attr` appears in `bgp`'s per-(vrf, afi)
 * MUP import RT list (mup_export[afi]->rtlist[FROMMUP]).  Mirrors
 * L3VPN's vpn_leak_to_vrf_update_onevrf (bgp_mplsvpn.c)
 * `ecommunity_include` test against vpn_policy[afi].rtlist[FROMVPN].
 */
static bool bgp_mup_route_rt_in_import(struct bgp *bgp, afi_t afi,
				       struct ecommunity *route_rt)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

	if (!ep || !ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP])
		return false;
	return ecommunity_include(ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP],
				  route_rt);
}

/* True iff at least one per-vrf bgp instance imports the RT carried on
 * `attr`.  Used to gate ISD/DSD cache upsert: a transit PE shouldn't
 * cache discovery state for slices it has no policy to serve, since a
 * stale ISD could otherwise wrongly cover a T1ST for a slice the local
 * PE has no business resolving.  Mirrors L3VPN's
 * vpn_leak_to_vrf_update_onevrf: import is gated on
 * vpn_policy[afi].rtlist[FROMVPN] only — no symmetric origin-RT
 * fallback.
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

/* `bgp retain route-target all` receive-side filter.  Returns true iff
 * the route's RT ecommunity matches no local VRF's MUP import list —
 * i.e. the NLRI should be dropped on receive when the default-instance
 * is configured `no bgp retain route-target all`.  Mirrors L3VPN's
 * vpn_leak_to_vrf_no_retain_filter_check (bgpd/bgp_mplsvpn.c) one-to-one,
 * substituting mup_export[afi]->rtlist[FROMMUP] for
 * vpn_policy[afi].rtlist[FROMVPN].
 */
bool bgp_mup_no_retain_filter_check(struct bgp *bgp, struct attr *attr, afi_t afi)
{
	struct ecommunity *route_rt;
	struct listnode *node;
	struct bgp *to_bgp;

	(void)bgp;
	if (!attr)
		return true;
	route_rt = bgp_attr_get_ecommunity(attr);
	if (!route_rt)
		return true;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, to_bgp)) {
		if (to_bgp->vrf_id == VRF_DEFAULT || to_bgp->vrf_id == VRF_UNKNOWN)
			continue;
		if (bgp_mup_route_rt_in_import(to_bgp, afi, route_rt))
			return false;
	}
	return true;
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

static int bgp_mup_st_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct prefix_mup *pm, const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	afi_t afi = bgp_mup_afi_from_prefix(mp);
	vrf_id_t install_vrf_id = bgp_mup_match_install_vrf(afi, info->attr);

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

		switch (bgp_mup_resolve_t1st(bgp, mp, &r)) {
		case BGP_MUP_T1ST_SELF:
			/* This PE itself originated the ISD that resolves the
			 * T1ST.  Skip install (same loop guard as
			 * bgp_mplsvpn.c::vpn_leak_to_vrf_update).  Withdraw
			 * anything we previously installed in case the
			 * route's origin status flipped.
			 */
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T1ST endpoint matches self-originated ISD; skip install (no loop)");
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		case BGP_MUP_T1ST_NO_ISD:
			/* Withdraw any prior install for this T1ST: an ISD
			 * may have been removed or the source-address
			 * resolution failed.  Idempotent if nothing was
			 * installed.
			 */
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T1ST endpoint has no matching ISD; skip install");
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		case BGP_MUP_T1ST_OK:
			break;
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
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("BGP-MUP: T2ST seg-id %" PRIu64
					   " matches self-originated DSD; skip install (no loop)",
					   segment_id);
			bgp_mup_st_delete_send(bgp, info, mp);
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
	 * install in slice1's table when the matching ISD/DSD is
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
		bgp_mup_isd_apply(bgp, afi, mp, info->attr);
		return 0;
	case BGP_MUP_DSD_ROUTE:
		bgp_mup_dsd_apply(bgp, afi, mp, info->attr);
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
		bgp_mup_isd_apply(bgp, afi, mp, NULL);
		return 0;
	case BGP_MUP_DSD_ROUTE:
		bgp_mup_dsd_apply(bgp, afi, mp, NULL);
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
	struct bgp_mup_state *st;

	if (afi >= AFI_MAX)
		return;
	st = bgp_mup_state_get(bgp);
	if (st->reannounce_ev[afi])
		return;
	event_add_event(bm->master, bgp_mup_reannounce_st_routes_cb, bgp, afi,
			&st->reannounce_ev[afi]);
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

/* Local origination of ISD / DSD routes — see bgp_mup.h for the full
 * MUP-PE / MUP-GW posture and SID-allocation rules.
 */

#include "bgpd/bgp_rd.h"

/* Build the BGP attribute set for a locally-originated ISD/DSD: origin
 * INCOMPLETE, IPv6 next-hop = @nexthop_override when non-NULL, else
 * left unset (peer-side rewrite per RFC 9433 / draft), Prefix-SID L3
 * Service TLV with the locator-composed SID + per-route-type-mandated
 * behavior + SID-Structure derived from the locator, and the RT/MUP
 * extended communities.
 */
static struct attr *bgp_mup_local_attr(struct bgp *bgp, const struct in6_addr *sid,
				       uint16_t endpoint_behavior, uint8_t loc_block_len,
				       uint8_t loc_node_len, uint8_t func_len, uint8_t arg_len,
				       struct ecommunity *ecom,
				       const struct in6_addr *nexthop_override)
{
	struct attr attr = {};
	struct bgp_attr_srv6_l3service *l3;

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);

	/* MUP NLRI carries an IPv6 next-hop on the wire.  Default leaves
	 * mp_nexthop_global zero; with `nexthop mup export A.B.C.D|X:X::X:X`
	 * configured, the per-(vrf, afi) policy supplies an explicit value
	 * (IPv4 stored as IPv4-mapped) — same posture as L3VPN's
	 * BGP_VPN_POLICY_TOVPN_NEXTHOP_SET path.
	 */
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
	if (nexthop_override)
		attr.mp_nexthop_global = *nexthop_override;

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
			if (pi->peer == to_bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
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

	dest = bgp_afi_node_get(to_bgp->rib[afi][SAFI_MUP], afi, SAFI_MUP, (struct prefix *)p,
				&prd);
	attr_new = bgp_attr_intern(attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == to_bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_STATIC)
			break;

	if (pi) {
		if (attrhash_cmp(pi->attr, attr_new) && !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
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

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, to_bgp->peer_self, attr_new, dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);
	bgp_path_info_add(dest, new);
	bgp_aggregate_increment(to_bgp, (struct prefix *)p, new, afi, SAFI_MUP);
	bgp_dest_unlock_node(dest);
	bgp_process(to_bgp, dest, new, afi, SAFI_MUP);
	return 0;
}

/* ---- Pending-originate tracking (async SID-manager flow) ----------------
 *
 * When the operator types `segment direct ...` without a
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
	struct bgp_mup_origin_args args; /* args->ecom is dup'd & owned */
	struct srv6_sid_ctx ctx;	 /* the ctx we sent to zebra */
};
DECLARE_LIST(bgp_mup_pending_list, struct bgp_mup_pending, item);

static struct bgp_mup_pending_list_head *bgp_mup_get_pending_list(struct bgp *bgp)
{
	return &bgp_mup_state_get(bgp)->pending;
}

static struct bgp_mup_pending *bgp_mup_pending_pop(struct bgp *bgp, const struct srv6_sid_ctx *ctx)
{
	struct bgp_mup_pending_list_head *head;
	struct bgp_mup_pending *p;

	if (!bgp_mup_state_pending(bgp))
		return NULL;
	head = bgp_mup_state_pending(bgp);
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
bgp_mup_pending_pop_for_withdraw(struct bgp *bgp,
				 const struct bgp_mup_origin_args *args)
{
	struct bgp_mup_pending_list_head *head;
	struct bgp_mup_pending *p;

	if (!bgp_mup_state_pending(bgp))
		return NULL;
	head = bgp_mup_state_pending(bgp);
	frr_each_safe (bgp_mup_pending_list, head, p) {
		if (p->args.afi != args->afi)
			continue;
		if (memcmp(p->args.prd.val, args->prd.val, sizeof(p->args.prd.val)) != 0)
			continue;
		if (!ipaddr_is_same(&p->args.dsd_endpoint, &args->dsd_endpoint))
			continue;
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
	return &bgp_mup_state_get(bgp)->origins;
}

static bool bgp_mup_origin_match(const struct bgp_mup_origin *o, afi_t afi,
				 const struct prefix_rd *prd,
				 const struct ipaddr *dsd_endpoint)
{
	if (o->afi != afi)
		return false;
	if (memcmp(o->prd.val, prd->val, sizeof(o->prd.val)) != 0)
		return false;
	return ipaddr_is_same(&o->dsd_endpoint, dsd_endpoint);
}

static struct bgp_mup_origin *bgp_mup_origin_find(struct bgp *bgp, afi_t afi,
						  const struct prefix_rd *prd,
						  const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o;

	if (!bgp_mup_state_origins(bgp))
		return NULL;
	frr_each (bgp_mup_origin_list, bgp_mup_state_origins(bgp), o) {
		if (bgp_mup_origin_match(o, afi, prd, dsd_endpoint))
			return o;
	}
	return NULL;
}

static void bgp_mup_origin_free(struct bgp_mup_origin *o)
{
	XFREE(MTYPE_BGP_MUP_STR, o->rt_str);
	if (o->rt_ecom)
		ecommunity_free(&o->rt_ecom);
	XFREE(MTYPE_BGP_MUP_STR, o->mup_str);
	XFREE(MTYPE_BGP_MUP_ORIGIN, o);
}

/* Mark a persisted origin as fully installed (BGP RIB + kernel SID) and
 * record the (sid, action) just pushed to zebra so a later
 * bgp_mup_emit_*() can skip the redundant zclient_send_localsid().
 * Called from bgp_mup_emit_*'s success path, both for explicit-SID
 * (synchronous) and auto-allocate (after the SID notify arrives).
 */
static void bgp_mup_origin_mark_installed(struct bgp *bgp, afi_t afi,
					  const struct prefix_rd *prd,
					  const struct ipaddr *dsd_endpoint,
					  const struct in6_addr *sid, enum seg6local_action_t act)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, afi, prd, dsd_endpoint);

	if (!o)
		return;
	o->sid_ready = true;
	o->last_installed_sid = *sid;
	o->last_installed_act = act;
}

/* Returns true when (sid, act) match the last install for this origin and
 * sid_ready is set — caller can then skip zclient_send_localsid().  Only
 * meaningful on the install path; the withdraw path always sends so zebra
 * removes the kernel state.
 */
static bool bgp_mup_origin_localsid_cached(struct bgp *bgp, afi_t afi,
					   const struct prefix_rd *prd,
					   const struct ipaddr *dsd_endpoint,
					   const struct in6_addr *sid, enum seg6local_action_t act)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, afi, prd, dsd_endpoint);

	if (!o || !o->sid_ready)
		return false;
	if (o->last_installed_act != act)
		return false;
	return IPV6_ADDR_SAME(&o->last_installed_sid, sid);
}

/* Drop the cached (sid, action) fingerprint after a withdraw so a later
 * re-install isn't wrongly suppressed.  Also called from origin teardown
 * paths to keep the cache in sync with the on-the-wire state.
 */
static void bgp_mup_origin_clear_installed(struct bgp *bgp, afi_t afi,
					   const struct prefix_rd *prd,
					   const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, afi, prd, dsd_endpoint);

	if (!o)
		return;
	o->sid_ready = false;
	memset(&o->last_installed_sid, 0, sizeof(o->last_installed_sid));
	o->last_installed_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
}

/* Insert a new persistent record, replacing any existing entry with the
 * same NLRI key.  Caller is the VTY DEFPY after the originate has been
 * accepted by the SID manager path.  mup_str is required for DSD and
 * must be NULL for ISD.
 */
static void bgp_mup_origin_persist(struct bgp *bgp,
				   const struct bgp_mup_origin_args *args, const char *rt_str,
				   const char *mup_str)
{
	struct bgp_mup_origin *o;
	struct ecommunity *rt_ecom;
	uint64_t segment_id;
	bool sid_ready = false;
	struct in6_addr last_sid = {};
	enum seg6local_action_t last_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;

	rt_ecom = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!rt_ecom)
		return;

	o = bgp_mup_origin_find(bgp, args->afi, &args->prd, &args->dsd_endpoint);
	if (o) {
		if (bgp_mup_origin_segment_id(o, &segment_id))
			bgp_mup_self_dsd_index_del(segment_id);
		/* Carry over the install fingerprint so explicit-SID's
		 * synchronous emit (which ran before persist) survives the
		 * record replacement and a later replay can dedup.  rt_ecom
		 * is intentionally not carried over — the operator may have
		 * changed the RT on a re-issued `segment` line, and the old
		 * rt_ecom is freed by bgp_mup_origin_free below.
		 */
		sid_ready = o->sid_ready;
		last_sid = o->last_installed_sid;
		last_act = o->last_installed_act;
		bgp_mup_origin_list_del(bgp_mup_state_origins(bgp), o);
		bgp_mup_origin_free(o);
	}
	o = XCALLOC(MTYPE_BGP_MUP_ORIGIN, sizeof(*o));
	o->afi = args->afi;
	o->prd = args->prd;
	o->has_explicit_sid = args->has_explicit_sid;
	o->explicit_sid = args->explicit_sid;
	o->rt_str = XSTRDUP(MTYPE_BGP_MUP_STR, rt_str);
	o->rt_ecom = rt_ecom;
	o->sid_ready = sid_ready;
	o->last_installed_sid = last_sid;
	o->last_installed_act = last_act;
	o->dsd_endpoint = args->dsd_endpoint;
	o->dsd_behavior = args->dsd_behavior;
	o->mup_str = XSTRDUP(MTYPE_BGP_MUP_STR, mup_str);
	{
		uint16_t mup_as = 0;
		uint32_t mup_val = 0;

		if (bgp_mup_parse_seg_id_str(mup_str, &mup_as, &mup_val)) {
			o->segment_id = ((uint64_t)mup_as << 32) | mup_val;
			o->has_segment_id = true;
		}
	}
	bgp_mup_origin_list_add_tail(bgp_mup_get_origin_list(bgp), o);
	if (bgp_mup_origin_segment_id(o, &segment_id))
		bgp_mup_self_dsd_index_add(segment_id);
}

static void bgp_mup_origin_forget(struct bgp *bgp, afi_t afi,
				  const struct prefix_rd *prd,
				  const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, afi, prd, dsd_endpoint);
	uint64_t segment_id;

	if (!o)
		return;
	if (bgp_mup_origin_segment_id(o, &segment_id))
		bgp_mup_self_dsd_index_del(segment_id);
	bgp_mup_origin_list_del(bgp_mup_state_origins(bgp), o);
	bgp_mup_origin_free(o);
}

/* Drain and free the entire per-bgp MUP state on instance teardown.
 * Replaces three earlier helpers (bgp_mup_origin_list_free,
 * bgp_mup_pending_list_free, bgp_mup_caches_free) with a single entry
 * point that mirrors bgp_mup_state_get's lazy-allocate counterpart.
 *
 * Drain order matters: the pending list owns dup'd ecommunities; the
 * origin list owns rt_str / rt_ecom / mup_str and feeds the bm-scope
 * self-origin indexes; the ISD/DSD caches embed an LPM tree and a
 * per-segid hash.
 */
void bgp_mup_state_free(struct bgp *bgp)
{
	struct bgp_mup_state *st = bgp->mup_state;
	struct bgp_mup_isd_entry *isd;
	struct bgp_mup_dsd_entry *dsd;
	struct bgp_mup_origin *o;
	struct bgp_mup_pending *p;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		bgp_mup_export_clear(bgp, afi);

	if (!st)
		return;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		event_cancel(&st->reannounce_ev[afi]);

	while ((p = bgp_mup_pending_list_pop(&st->pending)))
		bgp_mup_pending_free(p);
	bgp_mup_pending_list_fini(&st->pending);

	while ((o = bgp_mup_origin_list_pop(&st->origins))) {
		uint64_t segment_id;

		if (bgp_mup_origin_segment_id(o, &segment_id))
			bgp_mup_self_dsd_index_del(segment_id);
		bgp_mup_origin_free(o);
	}
	bgp_mup_origin_list_fini(&st->origins);

	while ((isd = bgp_mup_isd_hash_pop(&st->isd_hash))) {
		bgp_mup_isd_lpm_unlink(bgp, isd);
		XFREE(MTYPE_BGP_MUP_ISD, isd);
	}
	bgp_mup_isd_hash_fini(&st->isd_hash);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (st->isd_lpm[afi]) {
			route_table_finish(st->isd_lpm[afi]);
			st->isd_lpm[afi] = NULL;
		}
	}

	while ((dsd = bgp_mup_dsd_hash_pop(&st->dsd_hash))) {
		bgp_mup_dsd_segid_unlink(bgp, dsd);
		XFREE(MTYPE_BGP_MUP_DSD, dsd);
	}
	bgp_mup_dsd_hash_fini(&st->dsd_hash);
	bgp_mup_dsd_segid_hash_fini(&st->dsd_segid_hash);

	XFREE(MTYPE_BGP_MUP_STATE, bgp->mup_state);
}

/* Lazy allocator for per-bgp MUP state.  Mirrors L3VPN's per-vrf
 * vpn_policy initialisation but folded into one struct so MUP-internal
 * typesafe heads stay private to bgp_mup.c.
 */
static struct bgp_mup_state *bgp_mup_state_get(struct bgp *bgp)
{
	struct bgp_mup_state *st = bgp->mup_state;

	if (st)
		return st;
	st = XCALLOC(MTYPE_BGP_MUP_STATE, sizeof(*st));
	bgp_mup_pending_list_init(&st->pending);
	bgp_mup_origin_list_init(&st->origins);
	bgp_mup_isd_hash_init(&st->isd_hash);
	bgp_mup_dsd_hash_init(&st->dsd_hash);
	bgp_mup_dsd_segid_hash_init(&st->dsd_segid_hash);
	bgp->mup_state = st;
	return st;
}

/* Self-originated MUP routes (BGP_ROUTE_STATIC) bypass
 * bgp_zebra_announce_eligible(), so the receive-side dispatch in
 * bgp_zebra_announce_actual() never reaches bgp_mup_zebra_announce()
 * for them.  Mirror the cache update at originate time so local
 * ISD/DSD also resolves T1ST/T2ST routes received from MUP-Controllers.
 * The cache lives in the default-vrf bgp (single source of truth);
 * origin_vrf_id remembers which per-vrf instance configured the
 * `segment` so T1ST resolutions can install into that VRF's table.
 */
static void bgp_mup_emit_isd_cache_update(struct bgp *bgp, const struct bgp_mup_origin_args *args,
					  const struct in6_addr *sid, struct srv6_locator *loc,
					  uint16_t behavior, bool withdraw)
{
	struct bgp *cache_bgp = (bgp->vrf_id == VRF_DEFAULT) ? bgp : bgp_get_default();

	if (!cache_bgp)
		cache_bgp = bgp;
	if (!withdraw)
		bgp_mup_isd_cache_upsert(cache_bgp, args->afi, &args->prd, &args->isd_prefix, sid,
					 loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 behavior);
	else
		bgp_mup_isd_cache_remove(cache_bgp, args->afi, &args->prd, &args->isd_prefix);
}

static void bgp_mup_emit_dsd_cache_update(struct bgp *bgp, const struct bgp_mup_origin_args *args,
					  const struct in6_addr *sid, struct srv6_locator *loc,
					  struct attr *attr, bool withdraw)
{
	struct bgp *cache_bgp = (bgp->vrf_id == VRF_DEFAULT) ? bgp : bgp_get_default();

	if (!cache_bgp)
		cache_bgp = bgp;
	if (!withdraw) {
		bool has_seg = false;
		uint64_t seg_id = 0;

		if (attr)
			has_seg = bgp_mup_get_direct_seg_id(attr, &seg_id);
		bgp_mup_dsd_cache_upsert(cache_bgp, args->afi, &args->prd, &args->dsd_endpoint,
					 sid, loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 args->dsd_behavior, has_seg, seg_id);
	} else {
		bgp_mup_dsd_cache_remove(cache_bgp, args->afi, &args->prd, &args->dsd_endpoint);
	}
}

/* Synchronous originate path: build the prefix_mup + attr from a known
 * SID and submit to bgpd RIB.  Driven by the mup_leak_from_vrf_*
 * primitives that propagate VRF unicast RIB changes into the
 * default-VRF MUP RIB.  @from_bgp is the originating per-VRF instance
 * whose `mup_export[afi]` policy carries the (vrf, afi)-shared SID and
 * install fingerprint; @bgp is the destination (default-VRF) instance
 * the NLRI lands in.
 */
static int bgp_mup_emit_isd(struct bgp *bgp, struct bgp *from_bgp,
			    const struct bgp_mup_origin_args *args,
			    const struct in6_addr *sid, bool withdraw)
{
	struct prefix_mup p = {};
	struct attr *attr = NULL;
	struct srv6_locator *loc;
	uint16_t behavior;
	uint8_t prefix_octets;
	int ret;

	loc = bgp_srv6_locator_lookup(from_bgp ? from_bgp : bgp, bgp_get_default());
	if (!loc)
		return -1;
	behavior = (args->afi == AFI_IP) ? SRV6_ENDPOINT_BEHAVIOR_END_M_GTP4_E
					 : SRV6_ENDPOINT_BEHAVIOR_END_M_GTP6_E;

	prefix_octets = PSIZE(args->isd_prefix.prefixlen);
	bgp_mup_prefix_init(&p, BGP_MUP_ISD_ROUTE, 8 + 1 + prefix_octets);
	memcpy(p.prefix.rd, args->prd.val, 8);
	p.prefix.isd_route.ip_prefix_length = args->isd_prefix.prefixlen;
	if (args->afi == AFI_IP) {
		p.prefix.isd_route.ip.ipa_type = IPADDR_V4;
		p.prefix.isd_route.ip.ipaddr_v4 = args->isd_prefix.u.prefix4;
	} else {
		p.prefix.isd_route.ip.ipa_type = IPADDR_V6;
		p.prefix.isd_route.ip.ipaddr_v6 = args->isd_prefix.u.prefix6;
	}

	if (!withdraw) {
		struct bgp_mup_export_policy *ep =
			from_bgp ? bgp_mup_export_peek(from_bgp, args->afi) : NULL;
		const struct in6_addr *nh = (ep && (ep->flags & BGP_MUP_EXPORT_NEXTHOP_SET))
						    ? &ep->tovpn_nexthop
						    : NULL;

		attr = bgp_mup_local_attr(bgp, sid, behavior, loc->block_bits_length,
					  loc->node_bits_length, loc->function_bits_length,
					  loc->argument_bits_length, args->ecom, nh);
	}
	ret = bgp_mup_originate_common(bgp, args->afi, &p, attr, withdraw);
	bgp_mup_emit_isd_cache_update(bgp, args, sid, loc, behavior, withdraw);

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
		vrf_id_t install_vrf = from_bgp ? from_bgp->vrf_id : bgp->vrf_id;
		struct interface *vrf_lo = if_get_vrf_loopback(install_vrf);
		ifindex_t oif = vrf_lo ? vrf_lo->ifindex : 0;
		struct bgp_mup_export_policy *ep =
			from_bgp ? bgp_mup_export_peek(from_bgp, args->afi) : NULL;
		bool dedup;

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
		 *
		 * Skip the netlink install when zebra already holds an
		 * identical (sid, action) for the (vrf, afi) export policy:
		 * leaking N prefixes from the unicast RIB shares one SID, so
		 * we must dedup at the policy granularity, not per-prefix.
		 */
		dedup = ep && ep->last_installed_act == act &&
			IPV6_ADDR_SAME(&ep->last_installed_sid, sid);
		if (withdraw || !dedup)
			zclient_send_localsid(bgp_zclient,
					      withdraw ? ZEBRA_ROUTE_DELETE : ZEBRA_ROUTE_ADD, sid,
					      loc->block_bits_length + loc->node_bits_length +
						      loc->function_bits_length,
					      oif, act, &lctx);
		if (ep) {
			if (!withdraw && ret == 0) {
				ep->last_installed_sid = *sid;
				ep->last_installed_act = act;
			} else if (withdraw) {
				memset(&ep->last_installed_sid, 0,
				       sizeof(ep->last_installed_sid));
				ep->last_installed_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
			}
		}
	}

	if (attr)
		bgp_attr_unintern(&attr);
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
	bgp_mup_prefix_init(&p, BGP_MUP_DSD_ROUTE, 8 + addr_octets);
	memcpy(p.prefix.rd, args->prd.val, 8);
	p.prefix.dsd_route.ip = args->dsd_endpoint;

	if (!withdraw) {
		struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, args->afi);
		const struct in6_addr *nh = (ep && (ep->flags & BGP_MUP_EXPORT_NEXTHOP_SET))
						    ? &ep->tovpn_nexthop
						    : NULL;

		attr = bgp_mup_local_attr(bgp, sid, args->dsd_behavior, loc->block_bits_length,
					  loc->node_bits_length, loc->function_bits_length,
					  loc->argument_bits_length, args->ecom, nh);
	}
	ret = bgp_mup_originate_common(bgp, args->afi, &p, attr, withdraw);
	bgp_mup_emit_dsd_cache_update(bgp, args, sid, loc, attr, withdraw);

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

			/* Skip if zebra already holds an identical (sid, act)
			 * for this DSD origin; matches the ISD-side dedup.
			 */
			if (withdraw ||
			    !bgp_mup_origin_localsid_cached(bgp, args->afi, &args->prd,
							    &args->dsd_endpoint, sid, act))
				zclient_send_localsid(bgp_zclient,
						      withdraw ? ZEBRA_ROUTE_DELETE
							       : ZEBRA_ROUTE_ADD,
						      sid, plen, oif, act, &lctx);
			if (!withdraw && ret == 0)
				bgp_mup_origin_mark_installed(bgp, args->afi, &args->prd,
							      &args->dsd_endpoint, sid, act);
			else if (withdraw)
				bgp_mup_origin_clear_installed(bgp, args->afi, &args->prd,
							       &args->dsd_endpoint);
		}
	}

	if (attr)
		bgp_attr_unintern(&attr);
	return ret;
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

	/* Defer silently when no locator is configured yet or chunks
	 * haven't arrived from zebra; the persisted origin replays via
	 * bgp_mup_replay_origins_all() after locator arrival.
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

		cancel = bgp_mup_pending_pop_for_withdraw(bgp, args);
		bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_locator_name);
		if (cancel) {
			bgp_mup_pending_free(cancel);
			return 0;
		}
		return bgp_mup_emit_dsd(bgp, args, &in6addr_any, true);
	}

	p = XCALLOC(MTYPE_BGP_MUP_PENDING, sizeof(*p));
	p->args = *args;
	if (args->ecom)
		p->args.ecom = ecommunity_dup(args->ecom);
	p->ctx.behavior = bgp_mup_dsd_zebra_action(args->dsd_behavior);
	p->ctx.vrf_id = bgp->vrf_id;
	bgp_mup_pending_list_add_tail(bgp_mup_get_pending_list(bgp), p);

	/* The real SID arrives async via ZAPI_SRV6_SID_ALLOCATED, handled
	 * by bgp_mup_handle_sid_alloc() which dispatches into emit_dsd().
	 */
	{
		struct in6_addr sid = {};

		bgp_zebra_request_srv6_sid(&p->ctx, &sid, bgp->srv6_locator_name, NULL);
	}
	return 0;
}

/* SID Manager async completion (called from bgp_zebra.c).
 *
 * Returns true when a pending MUP request matched this ctx and was
 * dispatched.  Returns false when no pending exists, allowing the
 * caller (bgp_zebra_srv6_sid_notify) to delegate to other handlers
 * such as the VPN one (DT4/DT6 behaviors are shared with VPN).
 */
bool bgp_mup_handle_sid_alloc(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
			      const struct in6_addr *sid_value, const char *loc_name)
{
	struct bgp_mup_pending *p = bgp_mup_pending_pop(bgp, ctx);
	afi_t afi;

	if (p) {
		(void)bgp_mup_emit_dsd(bgp, &p->args, sid_value, false);
		bgp_mup_pending_free(p);
		return true;
	}

	/* No per-prefix pending matched.  Check whether this allocation
	 * satisfies a per-(vrf, afi) ISD export policy waiting on its
	 * shared End.M.GTP{4,6}.E SID.  These two behaviors are exclusive
	 * to MUP, so we must claim every notification carrying them
	 * (return true) — falling through to the VPN handler would treat
	 * them as unsupported and release the SID we just received.
	 */
	if (ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E)
		afi = AFI_IP;
	else if (ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP6_E)
		afi = AFI_IP6;
	else
		return false;

	{
		struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
		struct bgp *to_bgp = bgp_get_default();
		const char *want_loc;

		if (!ep || (ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT)) {
			/* No auto policy is waiting on this SID — release it
			 * back to zebra so the binding doesn't leak.  Use the
			 * notify's loc_name so zebra finds the same key it
			 * allocated under.
			 */
			if (loc_name && loc_name[0] != '\0')
				bgp_zebra_release_srv6_sid(ctx, loc_name);
			else if (bgp->srv6_locator_name[0] != '\0')
				bgp_zebra_release_srv6_sid(ctx, bgp->srv6_locator_name);
			return true;
		}
		if (ep->tovpn_sid_ready) {
			/* Duplicate notify for an already-latched policy
			 * (idempotent zebra ctx_lookup hits on a re-request).
			 * Sanity-check the value matches; warn otherwise.
			 */
			if (memcmp(&ep->tovpn_sid, sid_value, sizeof(*sid_value)) != 0)
				zlog_warn("BGP-MUP: duplicate SID notify with different value (afi=%s have=%pI6 got=%pI6)",
					  afi2str(afi), &ep->tovpn_sid, sid_value);
			return true;
		}
		/* Per-policy locator validation: zebra delivered a SID from
		 * loc_name; if the policy now wants a different locator (e.g.
		 * operator changed the override mid-flight before zebra
		 * processed the prior request), release the stale binding
		 * back to zebra so it doesn't leak.
		 */
		want_loc = bgp_mup_export_locname(bgp, ep);
		if (loc_name && want_loc && strcmp(loc_name, want_loc) != 0) {
			bgp_zebra_release_srv6_sid(ctx, loc_name);
			return true;
		}
		ep->tovpn_sid = *sid_value;
		ep->tovpn_sid_ready = true;
		if (to_bgp)
			mup_leak_from_vrf_update_all(to_bgp, bgp, afi);
		return true;
	}
}

/* ----------------------------------------------------------------------
 * Leak primitives: drive ISD origination from the VRF unicast RIB.
 *
 * Mirrors bgpd/bgp_mplsvpn.c's vpn_leak_from_vrf_* family.  Trigger
 * sites in bgp_route.c call mup_leak_from_vrf_update / _withdraw next
 * to the L3VPN equivalents; the export-policy DEFPYs use the prechange
 * / postchange wrappers around their state mutations.
 * ----------------------------------------------------------------------
 */

static bool mup_leak_should_skip_prefix(const struct prefix *p)
{
	if (!p)
		return true;
	/* Default route is not an ISD candidate per draft Section 3.3.1; ISD
	 * advertises N3 (gNB-side) reachability prefixes only.
	 */
	if (p->family == AF_INET && p->prefixlen == 0)
		return true;
	if (p->family == AF_INET6 && p->prefixlen == 0)
		return true;
	return false;
}

/* Idempotent SID resolver for the per-(vrf, afi) ISD export policy.
 *
 * Mirrors bgp_mplsvpn.c:ensure_vrf_tovpn_sid_per_af().  Called from
 * config-event sites (mup_leak_postchange and the locator-add replay)
 * — never from the per-prefix leak path.  Multiple calls collapse to
 * one zebra allocation because zebra's zebra_srv6_sid_ctx_lookup()
 * returns the existing SID for an already-bound (behavior, vrf_id)
 * pair, making bgpd-side in-flight bookkeeping unnecessary.
 */
static void mup_ensure_export_sid(struct bgp *from_bgp, afi_t afi, struct bgp_mup_export_policy *ep)
{
	struct srv6_sid_ctx ctx = {};
	struct in6_addr dummy = {};
	const char *locname;

	if (ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT) {
		ep->tovpn_sid = ep->tovpn_sid_explicit;
		ep->tovpn_sid_ready = true;
		return;
	}
	if (!(ep->flags & BGP_MUP_EXPORT_SID_AUTO))
		return;
	if (ep->tovpn_sid_ready)
		return;
	locname = bgp_mup_export_locname(from_bgp, ep);
	if (!locname)
		return;
	if (ep->locator_name && ep->locator_name[0] != '\0') {
		/* Per-policy override: zebra may not have pushed a chunk
		 * for this locator yet.  Fire a get-chunk request lazily;
		 * arrival will trigger bgp_mup_replay_origins_all() which
		 * retries this path.
		 */
		(void)bgp_zebra_srv6_manager_get_locator_chunk(locname);
	} else {
		if (!bgp_srv6_locator_is_configured(from_bgp))
			return;
		if (!bgp_srv6_locator_lookup(from_bgp, bgp_get_default()))
			return;
	}
	ctx.behavior = (afi == AFI_IP) ? ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E
				       : ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP6_E;
	ctx.vrf_id = from_bgp->vrf_id;
	bgp_zebra_request_srv6_sid(&ctx, &dummy, locname, NULL);
}

void mup_leak_from_vrf_update(struct bgp *to_bgp, struct bgp *from_bgp,
			      struct bgp_path_info *path_vrf)
{
	struct bgp_mup_export_policy *ep;
	const struct prefix *p;
	afi_t afi;
	struct bgp_mup_origin_args args = {};

	if (!to_bgp || !from_bgp || !path_vrf || !path_vrf->net)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	p = bgp_dest_get_prefix(path_vrf->net);
	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (mup_leak_should_skip_prefix(p))
		return;

	ep = bgp_mup_export_peek(from_bgp, afi);
	if (!ep || !(ep->flags & BGP_MUP_EXPORT_SEGMENT_INTERWORK) ||
	    !(ep->flags & BGP_MUP_EXPORT_RD_SET) ||
	    !ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP])
		return;

	/* Mirror vpn_leak_from_vrf_update's gate: do NOT require
	 * BGP_PATH_SELECTED here.  The leak hook fires immediately
	 * after path creation in bgp_route.c (e.g. bgp_redistribute_add,
	 * bgp_static_update, bgp_update), at which point VALID is set
	 * but selection is still asynchronous via bgp_process.
	 * Requiring SELECTED would silently drop every initial leak.
	 * Bulk replays from update_all already filter on SELECTED so
	 * dedup of multiple bpis per dest is handled there.
	 */
	if (!CHECK_FLAG(path_vrf->flags, BGP_PATH_VALID) ||
	    CHECK_FLAG(path_vrf->flags, BGP_PATH_REMOVED))
		return;
	if (bgp_path_suppressed(path_vrf))
		return;

	if (!ep->tovpn_sid_ready)
		return; /* defer: SID-arrival callback will replay via update_all */

	/* Phase 1 export-side route-map filter.  Mirrors L3VPN's
	 * filter step in bgpd/bgp_mplsvpn.c:vpn_leak_from_vrf_update.
	 * Filter-only initial cut: any rmap-applied attribute mutation is
	 * dropped — the emitted ISD attr is locally built from the policy
	 * (SID/RT/nexthop), not derived from the unicast attr, so set-clauses
	 * cannot meaningfully ride through to the wire.
	 */
	if (ep->rmap[BGP_MUP_POLICY_DIR_TOMUP]) {
		struct bgp_path_info info;
		struct bgp_path_info_extra path_extra;
		struct attr static_attr = *path_vrf->attr;
		struct peer *peer = path_vrf->peer ? path_vrf->peer : to_bgp->peer_self;
		route_map_result_t rmap_ret;

		prep_for_rmap_apply(&info, &path_extra, path_vrf->net, path_vrf, peer, NULL,
				    &static_attr);
		rmap_ret = route_map_apply(ep->rmap[BGP_MUP_POLICY_DIR_TOMUP], p, &info);
		bgp_attr_flush(&static_attr);
		if (rmap_ret == RMAP_DENYMATCH)
			return;
	}

	args.afi = afi;
	args.prd = ep->tovpn_rd;
	args.ecom = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
	args.isd_prefix = *p;
	(void)bgp_mup_emit_isd(to_bgp, from_bgp, &args, &ep->tovpn_sid, false);
}

void mup_leak_from_vrf_withdraw(struct bgp *to_bgp, struct bgp *from_bgp,
				struct bgp_path_info *path_vrf)
{
	struct bgp_mup_export_policy *ep;
	const struct prefix *p;
	afi_t afi;
	struct bgp_mup_origin_args args = {};
	struct in6_addr dummy = {};

	if (!to_bgp || !from_bgp || !path_vrf || !path_vrf->net)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	p = bgp_dest_get_prefix(path_vrf->net);
	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (mup_leak_should_skip_prefix(p))
		return;

	ep = bgp_mup_export_peek(from_bgp, afi);
	if (!ep || !(ep->flags & BGP_MUP_EXPORT_RD_SET))
		return;

	args.afi = afi;
	args.prd = ep->tovpn_rd;
	args.ecom = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
	args.isd_prefix = *p;
	(void)bgp_mup_emit_isd(to_bgp, from_bgp, &args, &dummy, true);
	/* Per design: do not release the SID — it is shared per (vrf, afi). */
}

void mup_leak_from_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;

	if (!to_bgp || !from_bgp)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (!from_bgp->rib[afi][SAFI_UNICAST])
		return;

	/* Walk every bpi; per-bpi mup_leak_from_vrf_update gates on
	 * VALID && !REMOVED && !suppressed.  Filtering on SELECTED here
	 * would skip paths that haven't been through bgp_process yet —
	 * the very situation we hit on SID arrival, when the unicast
	 * routes that triggered the SID request are still pre-selection.
	 */
	for (bn = bgp_table_top(from_bgp->rib[afi][SAFI_UNICAST]); bn;
	     bn = bgp_route_next(bn)) {
		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next)
			mup_leak_from_vrf_update(to_bgp, from_bgp, bpi);
	}
}

void mup_leak_from_vrf_withdraw_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep;
	struct bgp_dest *pdest;

	if (!to_bgp || !from_bgp)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	ep = bgp_mup_export_peek(from_bgp, afi);
	if (!ep || !(ep->flags & BGP_MUP_EXPORT_RD_SET))
		return;
	if (!to_bgp->rib[afi][SAFI_MUP])
		return;

	/* Walk to_bgp's MUP RIB, withdraw every locally-originated ISD entry
	 * whose RD matches this policy's tovpn_rd.  We can't filter on
	 * bgp_orig like vpn_leak_from_vrf_withdraw_all does because the
	 * MUP path uses BGP_ROUTE_STATIC self-origination — the RD gate is
	 * the unique key for this (vrf, afi) policy.
	 */
	for (pdest = bgp_table_top(to_bgp->rib[afi][SAFI_MUP]); pdest;
	     pdest = bgp_route_next(pdest)) {
		const struct prefix *pp = bgp_dest_get_prefix(pdest);
		const struct prefix_mup *pm;
		struct prefix_rd prd_have = {};
		struct bgp_path_info *bpi, *next;
		struct bgp_mup_origin_args args = {};
		struct in6_addr dummy = {};

		if (!pp || pp->family != AF_MUP)
			continue;
		pm = (const struct prefix_mup *)pp;
		if (pm->prefix.route_type != BGP_MUP_ISD_ROUTE)
			continue;
		bgp_mup_prd_from_bytes(&prd_have, pm->prefix.rd);
		if (memcmp(prd_have.val, ep->tovpn_rd.val, sizeof(prd_have.val)) != 0)
			continue;

		bpi = bgp_dest_get_bgp_path_info(pdest);
		if (!bpi)
			continue;
		for (; bpi && (next = bpi->next, 1); bpi = next) {
			if (bpi->peer != to_bgp->peer_self ||
			    bpi->type != ZEBRA_ROUTE_BGP ||
			    bpi->sub_type != BGP_ROUTE_STATIC)
				continue;
			args.afi = afi;
			args.prd = ep->tovpn_rd;
			args.ecom = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
			if (afi == AFI_IP) {
				args.isd_prefix.family = AF_INET;
				args.isd_prefix.prefixlen = pm->prefix.isd_route.ip_prefix_length;
				args.isd_prefix.u.prefix4 = pm->prefix.isd_route.ip.ipaddr_v4;
			} else {
				args.isd_prefix.family = AF_INET6;
				args.isd_prefix.prefixlen = pm->prefix.isd_route.ip_prefix_length;
				args.isd_prefix.u.prefix6 = pm->prefix.isd_route.ip.ipaddr_v6;
			}
			(void)bgp_mup_emit_isd(to_bgp, from_bgp, &args, &dummy, true);
			break;
		}
	}
}

void mup_leak_prechange(afi_t afi, struct bgp *bgp)
{
	struct bgp *to_bgp = bgp_get_default();

	if (!to_bgp || !bgp)
		return;
	mup_leak_from_vrf_withdraw_all(to_bgp, bgp, afi);
}

void mup_leak_postchange(afi_t afi, struct bgp *bgp)
{
	struct bgp *to_bgp = bgp_get_default();
	struct bgp_mup_export_policy *ep;

	if (!to_bgp || !bgp)
		return;
	ep = bgp_mup_export_peek(bgp, afi);
	if (ep)
		mup_ensure_export_sid(bgp, afi, ep);
	mup_leak_from_vrf_update_all(to_bgp, bgp, afi);
}

/* ---------------------------------------------------------------------- */
/* VTY: `mup-route isd|dsd ...` under `address-family ipv4|ipv6 mup`.     */
/* ---------------------------------------------------------------------- */

#include "bgpd/bgp_vty.h"
#include "lib/command.h"

#include "bgpd/bgp_mup_clippy.c"

/* DSD `behavior <kw>` keyword ↔ RFC 8986 SRv6 endpoint behavior code.
 * Always operator-driven per draft-ietf-bess-mup-safi Section 3.3.4 (function
 * MAY be End.DT4/6 or End.DX4/6, picked by inner PDU lookup AFI which
 * is independent of the DSD's Address AFI).
 */
static const struct {
	const char *kw;
	uint16_t code;
} mup_dsd_behaviors[] = {
	{ "dt4", SRV6_ENDPOINT_BEHAVIOR_END_DT4 },
	{ "dt6", SRV6_ENDPOINT_BEHAVIOR_END_DT6 },
	{ "dt46", SRV6_ENDPOINT_BEHAVIOR_END_DT46 },
};

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

/* DSD scalar singleton emit: build an `args` from the per-(vrf, afi)
 * export policy and call bgp_mup_originate_dsd().  The DSD address
 * defaults to the speaker's bgp router-id and can be overridden via
 * `segment mup export direct address X` on the policy.  The MUP-EC
 * (Direct-Type Segment Identifier) is configured via
 * `ext-community mup export ASN:NN`; the End.DT* behavior via
 * `behavior mup export <dt4|dt6|dt46>`.  RD / RT / SID come from
 * the shared `rd|rt|sid mup export` knobs already on this policy.
 *
 * The previous per-prefix `segment direct ADDR rd ... rt ... mup ...
 * behavior ... [sid explicit ...]` collection is gone; this is a
 * single DSD per (vrf, afi) — see refactor issue 210805 Move (2)
 * option (d).
 */
static bool mup_dsd_policy_ready(const struct bgp_mup_export_policy *ep)
{
	if (!ep)
		return false;
	if (!(ep->flags & BGP_MUP_EXPORT_SEGMENT_DIRECT))
		return false;
	if (!(ep->flags & BGP_MUP_EXPORT_RD_SET))
		return false;
	if (!ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP])
		return false;
	if (!ep->dsd_mup_str || !ep->dsd_behavior)
		return false;
	return true;
}

static void mup_dsd_args_from_policy(struct bgp *bgp, afi_t afi,
				     const struct bgp_mup_export_policy *ep,
				     struct bgp_mup_origin_args *args,
				     struct ecommunity **out_rt,
				     struct ecommunity **out_mup_ec,
				     struct ecommunity **out_ecom)
{
	struct ecommunity *rt = ecommunity_dup(ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP]);
	struct ecommunity *mup_ec = bgp_mup_build_mup_ec(ep->dsd_mup_str);

	args->afi = afi;
	args->prd = ep->tovpn_rd;
	args->dsd_behavior = ep->dsd_behavior;

	if (ep->flags & BGP_MUP_EXPORT_DSD_ADDRESS_SET) {
		args->dsd_endpoint = ep->dsd_address;
	} else {
		/* Default to bgp router-id (IPv4).  When the policy is on
		 * AFI_IP6 we still use the IPv4 router-id encoded as IPADDR_V4
		 * — the DSD NLRI's Address AFI is independent from the
		 * inner-PDU AFI per draft-ietf-bess-mup-safi Section 3.3.4.
		 */
		args->dsd_endpoint.ipa_type = IPADDR_V4;
		args->dsd_endpoint.ipaddr_v4 = bgp->router_id;
	}

	if (ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT) {
		args->has_explicit_sid = true;
		args->explicit_sid = ep->tovpn_sid_explicit;
	}

	*out_rt = rt;
	*out_mup_ec = mup_ec;
	if (rt && mup_ec)
		*out_ecom = ecommunity_merge(ecommunity_dup(rt), mup_ec);
	else
		*out_ecom = NULL;
	args->ecom = *out_ecom;
}

static void mup_dsd_emit_singleton(struct bgp *bgp, afi_t afi, bool withdraw)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
	struct bgp_mup_origin_args args = {};
	struct ecommunity *rt = NULL, *mup_ec = NULL, *ecom = NULL;

	if (!mup_dsd_policy_ready(ep))
		return;
	if (!withdraw && bgp->router_id.s_addr == 0 &&
	    !(ep->flags & BGP_MUP_EXPORT_DSD_ADDRESS_SET)) {
		zlog_warn("BGP-MUP: vrf %s has no router-id and no `segment mup export direct address` override; deferring DSD origination",
			  bgp->name ? bgp->name : "default");
		return;
	}

	mup_dsd_args_from_policy(bgp, afi, ep, &args, &rt, &mup_ec, &ecom);
	if (!ecom)
		goto done;

	(void)bgp_mup_originate_dsd(bgp, &args, withdraw);
	if (!withdraw) {
		char *rt_str = ecommunity_ecom2str(rt, ECOMMUNITY_FORMAT_ROUTE_MAP,
						   ECOMMUNITY_ROUTE_TARGET);

		bgp_mup_origin_persist(bgp, &args, rt_str, ep->dsd_mup_str);
		XFREE(MTYPE_ECOMMUNITY_STR, rt_str);
	} else {
		bgp_mup_origin_forget(bgp, args.afi, &args.prd, &args.dsd_endpoint);
	}

done:
	if (rt)
		ecommunity_free(&rt);
	if (mup_ec)
		ecommunity_free(&mup_ec);
	if (ecom)
		ecommunity_free(&ecom);
}

static void mup_dsd_prechange(afi_t afi, struct bgp *bgp)
{
	mup_dsd_emit_singleton(bgp, afi, true);
}

static void mup_dsd_postchange(afi_t afi, struct bgp *bgp)
{
	mup_dsd_emit_singleton(bgp, afi, false);
}

/* Schedule a coalesced T1ST/T2ST reannounce on every bgp instance that
 * holds an MUP RIB; called when receive-side import RT changes so
 * already-received NLRIs re-evaluate their per-vrf install selection.
 */
static void mup_st_resolve_reannounce_all(afi_t afi)
{
	struct listnode *node;
	struct bgp *b;

	if (!bm || !bm->bgp)
		return;
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, b))
		bgp_mup_schedule_reannounce_st_routes(b, afi);
}

/* L3VPN-style export-policy DEFPYs.  Live under `address-family ipv[46]
 * unicast` on a non-default-VRF instance.  Each command wraps state
 * mutation in mup_leak_prechange / _postchange so leaked ISD NLRIs
 * track the policy edit atomically (mirrors `rd vpn export` etc).
 */

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
			"%% rd|rt|sid mup export only valid under address-family ipv4|ipv6 unicast\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% rd|rt|sid mup export must be configured under a non-default vrf bgp instance (`router bgp ASN vrf NAME`); the default-vrf instance only carries the BGP-MUP session\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFPY (af_rd_mup_export,
       af_rd_mup_export_cmd,
       "[no] rd mup export ASN:NN_OR_IP-ADDRESS:NN$rd_str",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct prefix_rd prd = {};
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes && !str2prefix_rd(rd_str, &prd)) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	mup_leak_prechange(afi, bgp);

	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		if (ep->tovpn_rd_pretty)
			XFREE(MTYPE_BGP_NAME, ep->tovpn_rd_pretty);
		ep->tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME, rd_str);
		ep->tovpn_rd = prd;
		ep->flags |= BGP_MUP_EXPORT_RD_SET;
	} else {
		XFREE(MTYPE_BGP_NAME, ep->tovpn_rd_pretty);
		memset(&ep->tovpn_rd, 0, sizeof(ep->tovpn_rd));
		ep->flags &= ~BGP_MUP_EXPORT_RD_SET;
		/* Keep the (potentially still-valid) tovpn_sid — the operator
		 * may re-add RD with a new value and reuse the SID.  Any
		 * in-flight zebra response is harmless: it latches into
		 * tovpn_sid via the per-(behavior, vrf_id) ctx, which is
		 * independent of RD state.
		 */
	}

	mup_leak_postchange(afi, bgp);
	return CMD_SUCCESS;
}

ALIAS (af_rd_mup_export,
       af_no_rd_mup_export_cmd,
       "no rd mup export",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n")

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

		/* Export side: prechange withdraws leaked ISDs/DSDs so the
		 * postchange re-emits them with the new RT list.  Import side:
		 * trigger a coalesced T1ST/T2ST reannounce since the per-vrf
		 * install-vrf selection key changed.
		 */
		if (dir == BGP_MUP_POLICY_DIR_TOMUP) {
			mup_leak_prechange(afi, bgp);
			mup_dsd_prechange(afi, bgp);
		}

		ep = bgp_mup_export_get(bgp, afi);
		if (ep->rtlist[dir])
			ecommunity_free(&ep->rtlist[dir]);
		ep->rtlist[dir] = ecom ? ecommunity_dup(ecom) : NULL;

		if (dir == BGP_MUP_POLICY_DIR_TOMUP) {
			mup_dsd_postchange(afi, bgp);
			mup_leak_postchange(afi, bgp);
		} else {
			mup_st_resolve_reannounce_all(afi);
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

/* Mirror af_route_map_vpn_imexport_cmd in bgpd/bgp_vty.c.  L3VPN's
 * route-map DEFPY accepts only <import|export> (no `both`), so MUP
 * follows the same shape for parity.  Phase 1 enforces only the
 * export side; the import slot stores state so writeback round-trips,
 * but the apply happens in Phase 2 (receive-side dispatch).
 */
DEFPY (af_route_map_mup_imexport,
       af_route_map_mup_imexport_cmd,
       "[no] route-map mup <import|export>$direction_str RMAP$rmap_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from BGP-MUP into current unicast address-family\n"
       "For routes leaked from current unicast address-family to BGP-MUP\n"
       "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int dodir[BGP_MUP_POLICY_DIR_MAX] = {};
	enum bgp_mup_policy_dir dir;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	ret = mup_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		if (dir == BGP_MUP_POLICY_DIR_TOMUP)
			mup_leak_prechange(afi, bgp);

		ep = bgp_mup_export_get(bgp, afi);
		XFREE(MTYPE_ROUTE_MAP_NAME, ep->rmap_name[dir]);
		ep->rmap[dir] = NULL;
		if (yes) {
			ep->rmap_name[dir] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);
			ep->rmap[dir] = route_map_lookup_warn_noexist(vty, rmap_str);
		}

		if (dir == BGP_MUP_POLICY_DIR_TOMUP)
			mup_leak_postchange(afi, bgp);
		else if (yes)
			vty_out(vty,
				"%% route-map mup import: state stored, not yet applied (Phase 1: export side only)\n");
	}

	return CMD_SUCCESS;
}

ALIAS (af_route_map_mup_imexport,
       af_no_route_map_mup_imexport_cmd,
       "no route-map mup <import|export>$direction_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from BGP-MUP into current unicast address-family\n"
       "For routes leaked from current unicast address-family to BGP-MUP\n")

/* Re-resolve route-map pointers and trigger a leak prechange/postchange
 * pair on every (bgp, afi) whose policy references @rmap_name, so an
 * edit / definition / deletion of a route-map body propagates to the
 * already-leaked ISD set.  Mirrors vpn_policy_routemap_update in
 * bgpd/bgp_mplsvpn.c — only the TOMUP slot triggers a re-leak in
 * Phase 1 (FROMMUP is unenforced, so a refresh would change nothing).
 */
static void mup_policy_routemap_update(struct bgp *bgp, const char *rmap_name)
{
	struct route_map *rmap;
	struct bgp_mup_export_policy *ep;
	afi_t afi;
	enum bgp_mup_policy_dir dir;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT && bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	rmap = route_map_lookup_by_name(rmap_name); /* NULL if deleted */

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		ep = bgp_mup_export_peek(bgp, afi);
		if (!ep)
			continue;

		for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
			if (!ep->rmap_name[dir] || strcmp(rmap_name, ep->rmap_name[dir]) != 0)
				continue;

			if (dir == BGP_MUP_POLICY_DIR_TOMUP)
				mup_leak_prechange(afi, bgp);

			ep->rmap[dir] = rmap;

			if (dir == BGP_MUP_POLICY_DIR_TOMUP)
				mup_leak_postchange(afi, bgp);
		}
	}
}

void mup_policy_routemap_event(const char *rmap_name)
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	if (!bm || !bm->bgp)
		return;
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp))
		mup_policy_routemap_update(bgp, rmap_name);
}

DEFPY (af_sid_mup_export,
       af_sid_mup_export_cmd,
       "[no] sid mup export <auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value> [locator WORD$loc_name]",
       NO_STR
       "SID value for BGP-MUP\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n"
       "Auto-allocate from the configured SRv6 locator\n"
       "Pin a specific SID value\n"
       "SID value\n"
       "Allocate from a named SRv6 locator instead of the bgp-instance default\n"
       "SRv6 locator name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	mup_leak_prechange(afi, bgp);

	ep = bgp_mup_export_get(bgp, afi);

	/* Release any prior auto allocation that was anchored under a
	 * locator name we're about to change away from.  Both the no path
	 * and the yes-with-changed-locator path want this cleanup.
	 */
	if ((!yes || (yes && sid_auto && loc_name &&
		      (!ep->locator_name || strcmp(ep->locator_name, loc_name) != 0))) &&
	    !(ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT) && ep->tovpn_sid_ready) {
		const char *prev_loc = bgp_mup_export_locname(bgp, ep);

		if (prev_loc) {
			struct srv6_sid_ctx ctx = {};

			ctx.behavior = (afi == AFI_IP) ? ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP4_E
						       : ZEBRA_SEG6_LOCAL_ACTION_END_M_GTP6_E;
			ctx.vrf_id = bgp->vrf_id;
			bgp_zebra_release_srv6_sid(&ctx, prev_loc);
		}
		ep->tovpn_sid_ready = false;
		memset(&ep->tovpn_sid, 0, sizeof(ep->tovpn_sid));
	}

	if (yes) {
		/* Update or clear the per-policy locator override. */
		XFREE(MTYPE_BGP_NAME, ep->locator_name);
		if (loc_name)
			ep->locator_name = XSTRDUP(MTYPE_BGP_NAME, loc_name);

		if (sid_auto) {
			ep->flags |= BGP_MUP_EXPORT_SID_AUTO;
			ep->flags &= ~BGP_MUP_EXPORT_SID_EXPLICIT;
			memset(&ep->tovpn_sid_explicit, 0, sizeof(ep->tovpn_sid_explicit));
			/* Drop any previous explicit value's ready latch so the
			 * postchange path re-resolves via SRv6 SID manager.
			 */
			ep->tovpn_sid_ready = false;
		} else if (sid_explicit) {
			ep->flags |= BGP_MUP_EXPORT_SID_EXPLICIT;
			ep->flags &= ~BGP_MUP_EXPORT_SID_AUTO;
			ep->tovpn_sid_explicit = sid_value;
			ep->tovpn_sid = sid_value;
			ep->tovpn_sid_ready = true;
		}
	} else {
		/* Release of the auto-allocated (behavior, vrf_id) binding is
		 * handled by the pre-block above (covers both `no` and
		 * yes-with-changed-locator), with the resolved locname so a
		 * per-policy override is honored.
		 */
		ep->flags &= ~(BGP_MUP_EXPORT_SID_AUTO | BGP_MUP_EXPORT_SID_EXPLICIT);
		memset(&ep->tovpn_sid, 0, sizeof(ep->tovpn_sid));
		memset(&ep->tovpn_sid_explicit, 0, sizeof(ep->tovpn_sid_explicit));
		ep->tovpn_sid_ready = false;
		XFREE(MTYPE_BGP_NAME, ep->locator_name);
	}

	mup_leak_postchange(afi, bgp);
	return CMD_SUCCESS;
}

DEFPY (af_nexthop_mup_export,
       af_nexthop_mup_export_cmd,
       "[no] nexthop mup export [<A.B.C.D|X:X::X:X>$nexthop_su]",
       NO_STR
       "Specify next hop to use for VRF advertised prefixes\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n"
       "IPv4 address (stored as IPv4-mapped IPv6)\n"
       "IPv6 address\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	struct prefix p = {};
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!nexthop_su) {
			vty_out(vty, "%% Nexthop required\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (!sockunion2hostprefix(nexthop_su, &p))
			return CMD_WARNING_CONFIG_FAILED;
	}

	mup_leak_prechange(afi, bgp);

	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		if (p.family == AF_INET) {
			/* Map IPv4 → ::ffff:A.B.C.D so the on-wire IPv6
			 * next-hop is well-formed.  Writeback prints back
			 * as the original IPv4 dotted-quad.
			 */
			memset(&ep->tovpn_nexthop, 0, sizeof(ep->tovpn_nexthop));
			ep->tovpn_nexthop.s6_addr[10] = 0xff;
			ep->tovpn_nexthop.s6_addr[11] = 0xff;
			memcpy(&ep->tovpn_nexthop.s6_addr[12], &p.u.prefix4.s_addr,
			       sizeof(p.u.prefix4.s_addr));
			ep->tovpn_nexthop_was_v4 = true;
		} else {
			ep->tovpn_nexthop = p.u.prefix6;
			ep->tovpn_nexthop_was_v4 = false;
		}
		ep->flags |= BGP_MUP_EXPORT_NEXTHOP_SET;
	} else {
		ep->flags &= ~BGP_MUP_EXPORT_NEXTHOP_SET;
		memset(&ep->tovpn_nexthop, 0, sizeof(ep->tovpn_nexthop));
		ep->tovpn_nexthop_was_v4 = false;
	}

	mup_leak_postchange(afi, bgp);
	return CMD_SUCCESS;
}

ALIAS (af_nexthop_mup_export,
       af_no_nexthop_mup_export_cmd,
       "no nexthop mup export",
       NO_STR
       "Specify next hop to use for VRF advertised prefixes\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n")

ALIAS (af_sid_mup_export,
       af_no_sid_mup_export_cmd,
       "no sid mup export",
       NO_STR
       "SID value for BGP-MUP\n"
       "Between current address-family and BGP-MUP\n"
       "For routes leaked from current unicast address-family to MUP\n")

/* Emit the per-(vrf, afi) MUP-policy lines under
 * `address-family ipv[46] unicast`.  Sibling of L3VPN's
 * `rd vpn export` / `rt vpn <import|export|both>` / `sid vpn export`
 * writeback in bgp_vpn_policy_config_write_afi.
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

	if (ep->flags & BGP_MUP_EXPORT_RD_SET && ep->tovpn_rd_pretty)
		vty_out(vty, "%*srd mup export %s\n", indent, "", ep->tovpn_rd_pretty);

	rt_in = ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP];
	rt_out = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
	if (rt_in && rt_out && ecommunity_cmp(rt_in, rt_out)) {
		char *b = ecommunity_ecom2str(rt_in, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "%*srt mup both %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	} else {
		if (rt_in) {
			char *b = ecommunity_ecom2str(rt_in,
						      ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);

			vty_out(vty, "%*srt mup import %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
		if (rt_out) {
			char *b = ecommunity_ecom2str(rt_out,
						      ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);

			vty_out(vty, "%*srt mup export %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
	}

	if (ep->rmap_name[BGP_MUP_POLICY_DIR_FROMMUP])
		vty_out(vty, "%*sroute-map mup import %s\n", indent, "",
			ep->rmap_name[BGP_MUP_POLICY_DIR_FROMMUP]);
	if (ep->rmap_name[BGP_MUP_POLICY_DIR_TOMUP])
		vty_out(vty, "%*sroute-map mup export %s\n", indent, "",
			ep->rmap_name[BGP_MUP_POLICY_DIR_TOMUP]);

	if (ep->flags & BGP_MUP_EXPORT_SID_AUTO) {
		vty_out(vty, "%*ssid mup export auto", indent, "");
		if (ep->locator_name && ep->locator_name[0] != '\0')
			vty_out(vty, " locator %s", ep->locator_name);
		vty_out(vty, "\n");
	} else if (ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT) {
		vty_out(vty, "%*ssid mup export explicit %pI6", indent, "",
			&ep->tovpn_sid_explicit);
		if (ep->locator_name && ep->locator_name[0] != '\0')
			vty_out(vty, " locator %s", ep->locator_name);
		vty_out(vty, "\n");
	}

	if (ep->flags & BGP_MUP_EXPORT_NEXTHOP_SET) {
		if (ep->tovpn_nexthop_was_v4) {
			struct in_addr v4;

			memcpy(&v4, &ep->tovpn_nexthop.s6_addr[12], sizeof(v4));
			vty_out(vty, "%*snexthop mup export %pI4\n", indent, "", &v4);
		} else {
			vty_out(vty, "%*snexthop mup export %pI6\n", indent, "",
				&ep->tovpn_nexthop);
		}
	}

	if (ep->flags & BGP_MUP_EXPORT_SEGMENT_INTERWORK)
		vty_out(vty, "%*ssegment mup export interwork\n", indent, "");

	if (ep->flags & BGP_MUP_EXPORT_SEGMENT_DIRECT) {
		if (ep->flags & BGP_MUP_EXPORT_DSD_ADDRESS_SET &&
		    ep->dsd_address.ipa_type == IPADDR_V4)
			vty_out(vty, "%*ssegment mup export direct address %pI4\n",
				indent, "", &ep->dsd_address.ipaddr_v4);
		else
			vty_out(vty, "%*ssegment mup export direct\n", indent, "");
	}

	if (ep->dsd_behavior) {
		const char *bkw = mup_dsd_behavior_code2keyword(ep->dsd_behavior);

		if (bkw)
			vty_out(vty, "%*sbehavior mup export %s\n", indent, "", bkw);
	}

	if (ep->dsd_mup_str)
		vty_out(vty, "%*sext-community mup export %s\n", indent, "",
			ep->dsd_mup_str);
}

/* No `address-family ipv[46] mup`-only writeback: all VRF-local MUP
 * policy now lives under unicast AF (refactor 210805).  The MUP AF
 * remains as the SAFI-global container for `neighbor activate` and
 * future retain/show knobs.
 */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	if (!CHECK_FLAG(bgp->af_flags[afi][SAFI_MUP], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
		vty_out(vty, "  no bgp retain route-target all\n");
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

	if (!o->rt_ecom)
		return;
	rt = ecommunity_dup(o->rt_ecom);

	args.dsd_endpoint = o->dsd_endpoint;
	args.dsd_behavior = o->dsd_behavior;
	mup_ec = bgp_mup_build_mup_ec(o->mup_str);
	if (!mup_ec) {
		ecommunity_free(&rt);
		return;
	}
	ecom = ecommunity_merge(ecommunity_dup(rt), mup_ec);
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
		afi_t afi;
		bool any_locator;

		any_locator = bgp_srv6_locator_lookup(bgp, bgp_get_default());

		/* Wake up per-(vrf, afi) ISD export policies that were
		 * configured before any locator was available: re-request the
		 * shared End.M.GTP{4,6}.E SID and let the SID-arrival callback
		 * replay update_all over the unicast RIB.  Per-policy locator
		 * overrides may name a locator that arrived independently of
		 * the bgp instance's primary, so we no longer gate the policy
		 * loop on `bgp_srv6_locator_lookup` — `mup_export_request_sid_if_needed`
		 * already short-circuits when its resolved name is unknown.
		 */
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

			if (!ep || !(ep->flags & BGP_MUP_EXPORT_RD_SET) ||
			    !ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP])
				continue;
			if (!ep->tovpn_sid_ready)
				mup_ensure_export_sid(bgp, afi, ep);
			/* Replay DSD scalar singleton if the policy now has
			 * everything it needs and a SID is ready.
			 */
			if (mup_dsd_policy_ready(ep) && ep->tovpn_sid_ready)
				mup_dsd_emit_singleton(bgp, afi, false);
		}

		if (!any_locator)
			continue;

		if (!bgp_mup_state_origins(bgp))
			continue;
		frr_each (bgp_mup_origin_list, bgp_mup_state_origins(bgp), o) {
			if (o->sid_ready)
				continue;
			bgp_mup_replay_origin(bgp, o);
		}
	}
}

/* Evict every (vrf_id, locator block) cache entry whose stored block
 * overlaps the deleted locator's prefix.  prefix_match either way
 * catches the typical deployments (cache block == locator block, or
 * a deeper-prefixed block under a wider locator) and the rarer cases
 * where the locator itself is deeper than the cached block (legacy
 * SIDs cached pre-locator-rename).
 */
static void bgp_mup_locator_oif_invalidate_for_locator(const struct srv6_locator *loc)
{
	struct bgp_mup_oif_cache_entry *e;

	if (!bgp_mup_iface_cache_inited)
		return;
	frr_each_safe (bgp_mup_oif_cache, &bgp_mup_oif_cache, e) {
		if (!prefix_match((const struct prefix *)&loc->prefix,
				  (const struct prefix *)&e->block) &&
		    !prefix_match((const struct prefix *)&e->block,
				  (const struct prefix *)&loc->prefix))
			continue;
		bgp_mup_oif_cache_del(&bgp_mup_oif_cache, e);
		XFREE(MTYPE_BGP_MUP_IFACE_CACHE, e);
	}
}

/* Locator-delete hook: symmetric counterpart of bgp_mup_replay_origins_all().
 * Called from bgp_zebra.c's bgp_zebra_process_srv6_locator_delete_per_bgp()
 * after the L3VPN cleanup, so an operator's `no locator NAME` (or any zebra
 * SRV6_LOCATOR_DELETE) drops MUP's cached install state in lockstep with
 * the kernel seg6local removal.  For each persisted origin whose SID falls
 * inside the deleted locator's prefix:
 *   - clear sid_ready and the (sid, action) install fingerprint so a later
 *     reannounce / replay actually re-issues zclient_send_localsid(),
 *   - evict the per-(vrf, locator block) OIF cache entries that resolved
 *     against the dead locator,
 *   - schedule a coalesced T1ST/T2ST reannounce so the BGP RIB stops
 *     emitting UPDATEs that point into the dead locator.
 * Mirrors the prechange/postchange shape L3VPN uses; MUP's equivalent of
 * prechange is the per-origin clear, of postchange is the scheduled
 * reannounce.
 */
void bgp_mup_process_srv6_locator_delete_per_bgp(struct srv6_locator *loc, struct bgp *bgp)
{
	struct bgp_mup_origin *o;
	bool any_match[AFI_MAX] = {};
	afi_t afi;

	if (!bgp || !loc)
		return;

	/* Clear per-(vrf, afi) ISD export-policy SID-ready latches whose
	 * cached SID falls inside the deleted locator and withdraw any
	 * leaked ISD NLRIs that resolved against it.  A subsequent locator
	 * add will re-request the SID via the SRv6 SID manager and the
	 * arrival callback will replay update_all to re-emit the ISDs.
	 */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
		struct prefix sid_p = { .family = AF_INET6, .prefixlen = IPV6_MAX_BITLEN };
		struct bgp *to_bgp;

		if (!ep || !ep->tovpn_sid_ready)
			continue;
		if (ep->flags & BGP_MUP_EXPORT_SID_EXPLICIT)
			continue;
		sid_p.u.prefix6 = ep->tovpn_sid;
		if (!prefix_match((const struct prefix *)&loc->prefix, &sid_p))
			continue;
		to_bgp = bgp_get_default();
		if (to_bgp)
			mup_leak_from_vrf_withdraw_all(to_bgp, bgp, afi);
		ep->tovpn_sid_ready = false;
		memset(&ep->tovpn_sid, 0, sizeof(ep->tovpn_sid));
		memset(&ep->last_installed_sid, 0, sizeof(ep->last_installed_sid));
		ep->last_installed_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	}

	if (!bgp_mup_state_origins(bgp))
		goto invalidate;

	frr_each (bgp_mup_origin_list, bgp_mup_state_origins(bgp), o) {
		struct prefix sid_p = { .family = AF_INET6, .prefixlen = IPV6_MAX_BITLEN };

		if (!o->sid_ready)
			continue;
		sid_p.u.prefix6 = o->last_installed_sid;
		if (!prefix_match((const struct prefix *)&loc->prefix, &sid_p))
			continue;
		bgp_mup_origin_clear_installed(bgp, o->afi, &o->prd, &o->dsd_endpoint);
		if (o->afi < AFI_MAX)
			any_match[o->afi] = true;
	}

invalidate:
	bgp_mup_locator_oif_invalidate_for_locator(loc);

	if (any_match[AFI_IP])
		bgp_mup_schedule_reannounce_st_routes(bgp, AFI_IP);
	if (any_match[AFI_IP6])
		bgp_mup_schedule_reannounce_st_routes(bgp, AFI_IP6);
}

/* `segment mup export <direct|interwork> [address A.B.C.D]` under
 * `address-family ipv[46] unicast`.  Master enable for ISD or DSD
 * origination; the optional `address` override is valid only for
 * `direct` (the DSD NLRI's Address per draft-ietf-bess-mup-safi
 * Section 3.1.2; default = bgp router-id).  Mirrors L3VPN's pattern
 * of placing every leak knob under unicast (`rd vpn export`,
 * `rt vpn export`, `sid vpn export`).
 */
DEFPY(af_segment_mup_export,
      af_segment_mup_export_cmd,
      "[no] segment mup export <direct$direct|interwork$interwork> [address A.B.C.D$address]",
      NO_STR
      "BGP-MUP segment to originate\n"
      "Between current address-family and BGP-MUP\n"
      "Origination from the current unicast address-family into BGP-MUP\n"
      "Direct Segment Discovery (single-NLRI per (vrf, afi); draft Section 3.1.2)\n"
      "Interwork Segment Discovery (per-prefix from this VRF unicast RIB; draft Section 3.1.1)\n"
      "Override the DSD originating-speaker address (default = bgp router-id)\n"
      "IPv4 address overriding bgp router-id\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (interwork && address_str) {
		vty_out(vty,
			"%% `address` is only valid with `segment mup export direct` (interwork uses the VRF unicast RIB)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (direct) {
		mup_dsd_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		if (yes) {
			ep->flags |= BGP_MUP_EXPORT_SEGMENT_DIRECT;
			if (address_str) {
				ep->dsd_address.ipa_type = IPADDR_V4;
				ep->dsd_address.ipaddr_v4 = address;
				ep->flags |= BGP_MUP_EXPORT_DSD_ADDRESS_SET;
			} else {
				ep->flags &= ~BGP_MUP_EXPORT_DSD_ADDRESS_SET;
				memset(&ep->dsd_address, 0, sizeof(ep->dsd_address));
			}
		} else {
			ep->flags &= ~(BGP_MUP_EXPORT_SEGMENT_DIRECT |
				       BGP_MUP_EXPORT_DSD_ADDRESS_SET);
			memset(&ep->dsd_address, 0, sizeof(ep->dsd_address));
		}
		mup_dsd_postchange(afi, bgp);
	} else { /* interwork */
		mup_leak_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		if (yes)
			ep->flags |= BGP_MUP_EXPORT_SEGMENT_INTERWORK;
		else
			ep->flags &= ~BGP_MUP_EXPORT_SEGMENT_INTERWORK;
		mup_leak_postchange(afi, bgp);
	}
	return CMD_SUCCESS;
}

/* `behavior mup export <dt4|dt6|dt46>` under unicast AF — picks the
 * DSD prefix-SID's End.DT* function.  Per draft-ietf-bess-mup-safi
 * Section 3.3.4 the function reflects the inner PDU lookup AFI (PDU
 * session type), independent of the DSD's Address AFI; the operator
 * MUST declare it explicitly.
 */
DEFPY(af_behavior_mup_export,
      af_behavior_mup_export_cmd,
      "[no] behavior mup export <dt4$dt4|dt6$dt6|dt46$dt46>",
      NO_STR
      "SRv6 endpoint behavior\n"
      "Between current address-family and BGP-MUP\n"
      "For DSD prefix-SID emitted by current unicast address-family into BGP-MUP\n"
      "End.DT4 — decap and lookup in the IPv4 table\n"
      "End.DT6 — decap and lookup in the IPv6 table\n"
      "End.DT46 — decap and lookup in either IPv4 or IPv6 table\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	mup_dsd_prechange(afi, bgp);
	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		if (dt4)
			ep->dsd_behavior = SRV6_ENDPOINT_BEHAVIOR_END_DT4;
		else if (dt6)
			ep->dsd_behavior = SRV6_ENDPOINT_BEHAVIOR_END_DT6;
		else if (dt46)
			ep->dsd_behavior = SRV6_ENDPOINT_BEHAVIOR_END_DT46;
	} else {
		ep->dsd_behavior = 0;
	}
	mup_dsd_postchange(afi, bgp);
	return CMD_SUCCESS;
}

ALIAS(af_behavior_mup_export,
      af_no_behavior_mup_export_cmd,
      "no behavior mup export",
      NO_STR
      "SRv6 endpoint behavior\n"
      "Between current address-family and BGP-MUP\n"
      "For DSD prefix-SID emitted by current unicast address-family into BGP-MUP\n")

/* `ext-community mup export ASN:NN` under unicast AF — sets the MUP
 * Direct-Type Segment Identifier extended community (draft Section 4.2)
 * carried on every DSD originated from this (vrf, afi).
 */
DEFPY(af_ext_community_mup_export,
      af_ext_community_mup_export_cmd,
      "[no] ext-community mup export ASN:NN$ec_str",
      NO_STR
      "MUP Extended Community\n"
      "Between current address-family and BGP-MUP\n"
      "For DSD originated from current unicast address-family into BGP-MUP\n"
      "MUP segment identifier (ASN:NN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = true;
	int ret;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		uint16_t mup_as = 0;
		uint32_t mup_val = 0;

		if (!bgp_mup_parse_seg_id_str(ec_str, &mup_as, &mup_val)) {
			vty_out(vty, "%% Malformed MUP segment identifier \"%s\"\n",
				ec_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		mup_dsd_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		XFREE(MTYPE_BGP_MUP_STR, ep->dsd_mup_str);
		ep->dsd_mup_str = XSTRDUP(MTYPE_BGP_MUP_STR, ec_str);
		ep->dsd_mup_as = mup_as;
		ep->dsd_mup_val = mup_val;
		mup_dsd_postchange(afi, bgp);
	} else {
		mup_dsd_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		XFREE(MTYPE_BGP_MUP_STR, ep->dsd_mup_str);
		ep->dsd_mup_as = 0;
		ep->dsd_mup_val = 0;
		mup_dsd_postchange(afi, bgp);
	}
	return CMD_SUCCESS;
}

ALIAS(af_ext_community_mup_export,
      af_no_ext_community_mup_export_cmd,
      "no ext-community mup export",
      NO_STR
      "MUP Extended Community\n"
      "Between current address-family and BGP-MUP\n"
      "For DSD originated from current unicast address-family into BGP-MUP\n")

void bgp_mup_vty_init(void)
{
	/* L3VPN-style leak-policy commands under unicast AF nodes — every
	 * VRF-local MUP knob (RD/RT/SID/segment toggle/behavior/MUP-EC)
	 * mirrors `rd vpn export` / `rt vpn <import|export|both>` /
	 * `sid vpn export`.  See refactor issue 210805.
	 */
	install_element(BGP_IPV4_NODE, &af_rd_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rd_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_rt_mup_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rt_mup_cmd);
	install_element(BGP_IPV4_NODE, &af_route_map_mup_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_no_route_map_mup_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_sid_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_sid_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_nexthop_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_nexthop_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_segment_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_behavior_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_behavior_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_ext_community_mup_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_ext_community_mup_export_cmd);

	install_element(BGP_IPV6_NODE, &af_rd_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rd_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_rt_mup_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rt_mup_cmd);
	install_element(BGP_IPV6_NODE, &af_route_map_mup_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_no_route_map_mup_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_sid_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_sid_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_nexthop_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_nexthop_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_segment_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_behavior_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_behavior_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_ext_community_mup_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_ext_community_mup_export_cmd);
}
