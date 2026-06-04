// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */

#include "hash.h"
#include "jhash.h"
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
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_rd.h"
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
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_PENDING, "BGP MUP pending SID-alloc request");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_ORIGIN, "BGP MUP persisted origin record");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_STR, "BGP MUP origin verbatim string");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUP_SELF_KEY, "BGP MUP self-DSD index key");

/* Direction-indexed RT slots on the per-(vrf, afi) MUP export policy.
 * Mirrors bgp_mplsvpn.c's BGP_VPN_POLICY_DIR_FROMVPN / DIR_TOVPN.
 */
enum bgp_mup_policy_dir {
	BGP_MUP_POLICY_DIR_FROMMUP = 0,
	BGP_MUP_POLICY_DIR_TOMUP = 1,
	BGP_MUP_POLICY_DIR_MAX = 2,
};

/* Per-(vrf, afi) MUP policy.  Carries the import/export RT lists, the
 * SR-underlay VRF table id used by both the install path (post-action
 * lookup for End.M.GTP6.D{,Di} / H.M.GTP4.D) and the originate path
 * (post-action lookup for End.M.GTP4.E / End.M.GTP6.E local SIDs), the
 * RD and SRv6 SID slots that ISD origination consumes, the per-policy
 * locator pin, the originate-side next-hop, the import/export
 * route-map slots, and the scalar DSD origination knobs.  Mirrors
 * L3VPN's vpn_policy[afi] so a vrf doing both L3VPN and MUP can keep
 * the two policies independent.
 */
/* The kernel has no default for the Source UPF Prefix length: it has to
 * match the node on the other end, so a guess would fail silently on the
 * wire.  Default to the length RFC 9433 Figure 10 leaves once the IPv4
 * address and Args.Mob.Session are accounted for, and show it in the
 * running configuration so the value in use is never invisible.
 */
#define BGP_MUP_SOURCE_UPF_PREFIX_LEN_DEFAULT 56

struct bgp_mup_export_policy {
	struct ecommunity *rtlist[BGP_MUP_POLICY_DIR_MAX];

	uint32_t flags;
#define BGP_MUP_EXPORT_POLICY_RD_SET		(1 << 0)
#define BGP_MUP_EXPORT_POLICY_NEXTHOP_SET	(1 << 1)
#define BGP_MUP_EXPORT_POLICY_SID_AUTO		(1 << 2)
#define BGP_MUP_EXPORT_POLICY_SID_EXPLICIT	(1 << 3)
#define BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK (1 << 4)
#define BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT	(1 << 5)
#define BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET	(1 << 6)
#define BGP_MUP_EXPORT_POLICY_SOURCE_UPF_PREFIX_LEN_SET (1 << 7)

	/* RD attached to ISD/DSD originated from this (vrf, afi). */
	char *tovpn_rd_pretty;
	struct prefix_rd tovpn_rd;

	/* SRv6 SID used as the End.M.GTP4.E / End.M.GTP6.E local SID for
	 * ISD origination.  tovpn_sid is filled by the SID manager when
	 * SID_AUTO is set; tovpn_sid_explicit holds the operator value
	 * when SID_EXPLICIT is set.  Both are dynamic so the SID manager
	 * release path can NULL them on locator delete.
	 */
	struct in6_addr *tovpn_sid;
	struct in6_addr *tovpn_sid_explicit;
	/* Cached locator the SID was carved out of (per-policy pin).
	 * Deep-copied so a subsequent locator delete can be reconciled
	 * even after bgp->srv6_locator has been swapped or freed.
	 */
	struct srv6_locator *tovpn_sid_locator;
	/* Operator-supplied locator NAME override; takes precedence over
	 * the bgp-instance default locator when allocating a SID.
	 */
	char *locator_name;
	/* Cached copy of the override locator (resolved from zebra) so
	 * the SID structure can be computed at arm time.  NULL until the
	 * named locator is delivered; the bgp-instance locator is used
	 * directly when no override is configured.
	 */
	struct srv6_locator *override_locator;
	/* True once the SID is ready to be advertised (tovpn_sid populated
	 * and tovpn_sid_locator pinned).  ISD emit gates on this so the
	 * advertised next-hop never refers to an unarmed SID.
	 */
	bool tovpn_sid_ready;
	/* Fingerprint of the most recent zclient_send_localsid_mobile()
	 * install.  Used to skip redundant ZAPI route_add when neither
	 * the SID nor the action changes between two emit passes.
	 */
	struct in6_addr last_installed_sid;
	enum seg6_mobile_action_t last_installed_act;
	uint8_t last_installed_v6_src_prefix_len;

	/* Next-hop carried in the originated MP_REACH attribute. */
	struct prefix tovpn_nexthop;

	/* Import/export route-map plumbing (TOMUP filters the per-vrf
	 * unicast leak; FROMMUP gates the receive-side install).
	 */
	char *rmap_name[BGP_MUP_POLICY_DIR_MAX];
	struct route_map *rmap[BGP_MUP_POLICY_DIR_MAX];

	/* Scalar DSD origination ("segment direct" sub-block).  One DSD
	 * record per (vrf, afi); the address/behavior/segment-id triple
	 * is converted into a DSD NLRI emitted alongside ISD discovery.
	 */
	struct ipaddr dsd_address;
	uint16_t dsd_behavior; /* SRV6_ENDPOINT_BEHAVIOR_END_DT4/6/46 */
	uint32_t dsd_mup_as;
	uint32_t dsd_mup_val;
	char *dsd_mup_str;

	/* Length of the RFC 9433 Figure 10 Source UPF Prefix for the outer
	 * IPv6 SA of T1ST installs into this (vrf, afi).  The prefix itself
	 * is this speaker's SRv6 locator; the T1ST IPv4 Source Address goes
	 * right after these bits, where the far End.M.GTP4.E reads it.
	 */
	uint8_t source_upf_prefix_len;
};

static struct bgp_mup_export_policy *bgp_mup_export_get(struct bgp *bgp, afi_t afi)
{
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	if (bgp->mup_export[afi])
		return bgp->mup_export[afi];
	bgp->mup_export[afi] = XCALLOC(MTYPE_BGP_MUP_EXPORT, sizeof(*bgp->mup_export[afi]));
	bgp->mup_export[afi]->last_installed_act = ZEBRA_SEG6_MOBILE_ACTION_UNSPEC;
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
		XFREE(MTYPE_BGP_NAME, p->rmap_name[dir]);
		/* p->rmap[dir] is owned by the route_map subsystem; just
		 * drop the cached resolution pointer here.
		 */
		p->rmap[dir] = NULL;
	}
	XFREE(MTYPE_BGP_NAME, p->tovpn_rd_pretty);
	XFREE(MTYPE_BGP_SRV6_SID, p->tovpn_sid);
	XFREE(MTYPE_BGP_SRV6_SID, p->tovpn_sid_explicit);
	if (p->tovpn_sid_locator)
		srv6_locator_free(p->tovpn_sid_locator);
	p->tovpn_sid_locator = NULL;
	if (p->override_locator)
		srv6_locator_free(p->override_locator);
	p->override_locator = NULL;
	XFREE(MTYPE_BGP_NAME, p->locator_name);
	XFREE(MTYPE_BGP_NAME, p->dsd_mup_str);
	XFREE(MTYPE_BGP_MUP_EXPORT, bgp->mup_export[afi]);
}

/* Add the decomposed MUP NLRI fields to a json object for show output. */
void bgp_mup_route2json(const struct prefix_mup *pm, struct json_object *json)
{
	const struct mup_prefix *mp = &pm->prefix;
	struct prefix_rd prd = {};
	int family;

	if (!mp || !json)
		return;

	json_object_int_add(json, "archType", mp->arch_type);
	json_object_int_add(json, "routeType", mp->route_type);

	memcpy(prd.val, mp->rd, sizeof(prd.val));
	json_object_string_addf(json, "rd", "%pRDP", &prd);

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		family = IS_IPADDR_V4(&mp->isd_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->isd_route.ip);
		json_object_int_add(json, "ipLen", mp->isd_route.ip_prefix_length);
		break;
	case BGP_MUP_DSD_ROUTE:
		family = IS_IPADDR_V4(&mp->dsd_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->dsd_route.ip);
		break;
	case BGP_MUP_T1ST_ROUTE:
		family = IS_IPADDR_V4(&mp->t1st_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->t1st_route.ip);
		json_object_int_add(json, "ipLen", mp->t1st_route.ip_prefix_length);
		break;
	case BGP_MUP_T2ST_ROUTE:
		family = IS_IPADDR_V4(&mp->t2st_route.endpoint_address) ? AF_INET : AF_INET6;
		json_object_string_add(json, "endpointAddressFamily",
				       family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "endpointAddress", "%pIA",
					&mp->t2st_route.endpoint_address);
		json_object_int_add(json, "teid", mp->t2st_route.teid);
		break;
	}
}

/* Render the non-key NLRI data kept with a T1ST/T2ST route: for T1ST the
 * architecture specific fields followed by TLVs, for T2ST the TLVs alone.
 * TLVs are only decomposed for the route types they apply to (draft 3.1.5);
 * everything else is shown as type plus raw hex value.
 */
void bgp_mup_nlri_data_show(const struct bgp_mup_nlri_data *data, uint16_t route_type,
			    struct vty *vty, struct json_object *json_path)
{
	struct json_object *json_tlvs = NULL;
	int off = 0;

	if (route_type == BGP_MUP_T1ST_ROUTE) {
		char buf[INET6_ADDRSTRLEN];
		uint32_t teid;
		uint8_t qfi, ep_len, src_len;

		if (data->length <
		    BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + 2 * BGP_MUP_ADDR_LEN_BYTES)
			return;
		memcpy(&teid, data->val, BGP_MUP_TEID_BYTES);
		teid = ntohl(teid);
		off = BGP_MUP_TEID_BYTES;
		qfi = data->val[off++];
		ep_len = data->val[off++];
		if (json_path) {
			json_object_int_add(json_path, "teid", teid);
			json_object_int_add(json_path, "qfi", qfi);
		} else
			vty_out(vty, "      TEID %u, QFI %u\n", teid, qfi);
		if (!(ep_len / 8) || off + ep_len / 8 + BGP_MUP_ADDR_LEN_BYTES > data->length)
			return;
		inet_ntop(ep_len == IPV4_MAX_BITLEN ? AF_INET : AF_INET6, data->val + off, buf,
			  sizeof(buf));
		if (json_path)
			json_object_string_add(json_path, "endpointAddress", buf);
		else
			vty_out(vty, "      Endpoint Address: %s\n", buf);
		off += ep_len / 8;
		src_len = data->val[off++];
		if (src_len / 8) {
			if (off + src_len / 8 > data->length)
				return;
			inet_ntop(src_len == IPV4_MAX_BITLEN ? AF_INET : AF_INET6, data->val + off,
				  buf, sizeof(buf));
			if (json_path)
				json_object_string_add(json_path, "sourceAddress", buf);
			else
				vty_out(vty, "      Source Address: %s\n", buf);
			off += src_len / 8;
		}
	}

	if (off >= data->length)
		return;

	if (json_path)
		json_tlvs = json_object_new_array();
	else
		vty_out(vty, "      MUP TLVs:\n");

	while (off + BGP_MUP_TLV_HDR_BYTES <= data->length) {
		const uint8_t *val = data->val + off + BGP_MUP_TLV_HDR_BYTES;
		uint8_t type = data->val[off];
		uint8_t len = data->val[off + 1];
		struct json_object *json_tlv = NULL;
		bool decoded = false;

		if (off + BGP_MUP_TLV_HDR_BYTES + len > data->length)
			break;

		if (json_path) {
			json_tlv = json_object_new_object();
			json_object_int_add(json_tlv, "type", type);
		}

		if (route_type == BGP_MUP_T2ST_ROUTE) {
			switch (type) {
			case BGP_MUP_TLV_SESSION_PARAMS: {
				uint32_t teid;

				memcpy(&teid, val, BGP_MUP_TEID_BYTES);
				teid = ntohl(teid);
				if (json_tlv) {
					json_object_int_add(json_tlv, "teid", teid);
					json_object_int_add(json_tlv, "qfi",
							    val[BGP_MUP_TEID_BYTES]);
				} else
					vty_out(vty,
						"        Session Parameters: TEID %u, QFI %u\n",
						teid, val[BGP_MUP_TEID_BYTES]);
				decoded = true;
				break;
			}
			case BGP_MUP_TLV_INTERWORK_ENDPOINT:
			case BGP_MUP_TLV_SOURCE_ADDRESS: {
				const char *name = (type == BGP_MUP_TLV_INTERWORK_ENDPOINT)
							   ? "Interwork Endpoint"
							   : "Source Address";
				const char *key = (type == BGP_MUP_TLV_INTERWORK_ENDPOINT)
							  ? "interworkEndpoint"
							  : "sourceAddress";

				if (len == IPV4_MAX_BYTELEN) {
					struct in_addr addr;

					memcpy(&addr, val, sizeof(addr));
					if (json_tlv)
						json_object_string_addf(json_tlv, key, "%pI4",
									&addr);
					else
						vty_out(vty, "        %s: %pI4\n", name, &addr);
					decoded = true;
				} else if (len == IPV6_MAX_BYTELEN) {
					struct in6_addr addr;

					memcpy(&addr, val, sizeof(addr));
					if (json_tlv)
						json_object_string_addf(json_tlv, key, "%pI6",
									&addr);
					else
						vty_out(vty, "        %s: %pI6\n", name, &addr);
					decoded = true;
				}
				break;
			}
			}
		}

		if (!decoded) {
			char hex[2 * UINT8_MAX + 1];
			int i;

			for (i = 0; i < len; i++)
				snprintfrr(hex + 2 * i, 3, "%02x", val[i]);
			hex[2 * len] = '\0';
			if (json_tlv)
				json_object_string_add(json_tlv, "value", hex);
			else
				vty_out(vty, "        Type %u: %s\n", type, hex);
		}

		if (json_tlv)
			json_object_array_add(json_tlvs, json_tlv);

		off += BGP_MUP_TLV_HDR_BYTES + len;
	}

	if (json_path)
		json_object_object_add(json_path, "mupTlvs", json_tlvs);
}

/* ISD leak entry points, defined alongside bgp_nlri_parse_mup below;
 * forward-declared so the SID-arrival and locator-delete hooks here
 * can drive emit/withdraw without reordering the file.
 */
static void mup_leak_from_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi);
static void mup_leak_from_vrf_withdraw_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi);

/* DSD origination hooks defined with the late DSD core block (which
 * depends on bgp_mup_local_attr / bgp_mup_originate_common appearing
 * earlier).  Forward-declared here so the front-of-file SID-alloc and
 * teardown paths can dispatch into them without moving the core up.
 */
static bool bgp_mup_dispatch_pending_sid(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
					 const struct in6_addr *sid_value);
static void bgp_mup_origins_pending_free(struct bgp *bgp);
static void bgp_mup_replay_origins(struct bgp *bgp);
static void bgp_mup_origins_locator_purge(struct bgp *bgp, const struct srv6_locator *locator);

/* Map per-(vrf, afi) ISD origination to its SRv6 Mobile action: the
 * AFI of the leaked prefix selects End.M.GTP4.E (IPv4) or
 * End.M.GTP6.E (IPv6).
 */
static enum seg6_mobile_action_t bgp_mup_isd_action_for_afi(afi_t afi)
{
	if (afi == AFI_IP)
		return ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP4_E;
	if (afi == AFI_IP6)
		return ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP6_E;
	return ZEBRA_SEG6_MOBILE_ACTION_UNSPEC;
}

/* Resolve the locator NAME a (bgp, afi) policy expects its SID to
 * be carved from.  Per-policy override (`sid ... locator NAME`)
 * wins over the bgp-instance default (`segment-routing srv6 locator
 * NAME` on the bgp instance).  Returns NULL when neither is set.
 */
static const char *bgp_mup_select_locator_name(const struct bgp *bgp,
					       const struct bgp_mup_export_policy *ep)
{
	if (ep && ep->locator_name)
		return ep->locator_name;
	if (bgp && bgp->srv6_locator_name[0] != '\0')
		return bgp->srv6_locator_name;
	return NULL;
}

/* Resolve the struct srv6_locator whose block/node/function lengths
 * describe this policy's SID.  With no `sid ... locator NAME` override
 * the bgp-instance locator applies; an override uses the separately
 * subscribed-and-cached locator, which is NULL until zebra delivers it
 * (the SID-arrival / locator-arrival retry arms it once both land).
 */
static struct srv6_locator *bgp_mup_resolve_locator(struct bgp *bgp,
						    const struct bgp_mup_export_policy *ep)
{
	struct srv6_locator *inst = bgp_srv6_locator_lookup(bgp, bgp_get_default());

	if (ep && ep->locator_name) {
		if (inst && strcmp(inst->name, ep->locator_name) == 0)
			return inst;
		if (ep->override_locator &&
		    strcmp(ep->override_locator->name, ep->locator_name) == 0)
			return ep->override_locator;
		return NULL;
	}
	return inst;
}

/* Install or uninstall the End.M.GTP*.E local SID for this (vrf,
 * afi) policy.  Dedup against last_installed_* skips ZAPI traffic
 * when neither the SID nor the action changed; locator delete uses
 * @withdraw=true to release the install before the SID disappears.
 */
static void bgp_mup_install_isd_localsid(struct bgp *bgp, afi_t afi, bool withdraw)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
	struct seg6_mobile_ctx mctx = {};
	struct srv6_locator *loc;
	enum seg6_mobile_action_t act;
	struct vrf *vrf;
	ifindex_t oif;
	uint16_t plen;
	bool dedup;

	if (!ep || !ep->tovpn_sid || !ep->tovpn_sid_locator)
		return;
	act = bgp_mup_isd_action_for_afi(afi);
	if (act == ZEBRA_SEG6_MOBILE_ACTION_UNSPEC)
		return;

	loc = ep->tovpn_sid_locator;
	plen = loc->block_bits_length + loc->node_bits_length + loc->function_bits_length;

	/* End.M.GTP{4,6}.E reads the SID locator length from
	 * SEG6_MOBILE_SR_PREFIX_LEN to position the IPv4 DA / Args.Mob.Session;
	 * it must not be inferred from the route prefix, which is unavailable
	 * when the kernel builds the lwtunnel from a nexthop object.
	 */
	mctx.sr_prefix_len = plen;

	/* End.M.GTP4.E recovers the outer IPv4 source from the inbound IPv6
	 * source per RFC 9433 Section 6.6 Figure 10; the offset has to match
	 * the one the far PE lays the address out at.  The GTP6 sibling
	 * copies its source verbatim and the kernel rejects the attribute.
	 */
	if (act == ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP4_E)
		mctx.v6_src_prefix_len = ep->source_upf_prefix_len
						? : BGP_MUP_SOURCE_UPF_PREFIX_LEN_DEFAULT;

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	mctx.vrftable = vrf ? vrf->data.l.table_id : 0;

	/* End.M.GTP6.E builds a fresh outer IPv6 whose source the kernel
	 * copies verbatim from src_addr; an all-zero SA is dropped by the
	 * IPv6 output path, so seed it with the SID locator base (the
	 * MUP-GW's SR-domain address).  End.M.GTP4.E derives its IPv4 source
	 * from the SID itself and ignores this field.
	 */
	mctx.src_addr = loc->prefix.prefix;

	/* End.M.GTP{4,6}.E emits the GTP-U packet out the originating VRF's
	 * N3-side interface.  FRR models a Linux VRF with vrf_id == the VRF
	 * device ifindex, so the SID (installed in the default VRF) egresses
	 * via that device.  Origination only runs on a non-default VRF.
	 */
	oif = (bgp->vrf_id != VRF_DEFAULT) ? bgp->vrf_id : 0;

	dedup = !withdraw && ep->last_installed_act == act &&
		ep->last_installed_v6_src_prefix_len == mctx.v6_src_prefix_len &&
		IPV6_ADDR_SAME(&ep->last_installed_sid, ep->tovpn_sid);
	if (withdraw || !dedup)
		zclient_send_localsid_mobile(bgp_zclient,
					     withdraw ? ZEBRA_ROUTE_DELETE : ZEBRA_ROUTE_ADD,
					     ep->tovpn_sid, plen, oif, act, &mctx);

	if (withdraw) {
		memset(&ep->last_installed_sid, 0, sizeof(ep->last_installed_sid));
		ep->last_installed_act = ZEBRA_SEG6_MOBILE_ACTION_UNSPEC;
		ep->last_installed_v6_src_prefix_len = 0;
	} else {
		ep->last_installed_sid = *ep->tovpn_sid;
		ep->last_installed_act = act;
		ep->last_installed_v6_src_prefix_len = mctx.v6_src_prefix_len;
	}
}

/* Pin @locator_bgp (deep copy), stash @sid as the policy's ISD SID,
 * latch ready, and install the End.M.GTP*.E local SID.  Shared by the
 * SID-manager notify path (SID_AUTO) and the explicit-SID path.
 */
static void bgp_mup_export_arm_sid(struct bgp *bgp, afi_t afi, struct bgp_mup_export_policy *ep,
				   struct srv6_locator *locator_bgp, const struct in6_addr *sid)
{
	if (ep->tovpn_sid_locator)
		srv6_locator_free(ep->tovpn_sid_locator);
	ep->tovpn_sid_locator = srv6_locator_alloc(locator_bgp->name);
	srv6_locator_copy(ep->tovpn_sid_locator, locator_bgp);

	XFREE(MTYPE_BGP_SRV6_SID, ep->tovpn_sid);
	ep->tovpn_sid = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*ep->tovpn_sid = *sid;
	ep->tovpn_sid_ready = true;

	bgp_mup_install_isd_localsid(bgp, afi, false);
}

/* Make the (vrf, afi) ISD policy's SID ready.  SID_EXPLICIT arms the
 * operator-supplied value synchronously against the resolved locator;
 * SID_AUTO asks the SRv6 SID manager and the notify hook arms it on
 * arrival.  No-op when neither flag is set, when a SID is already
 * ready, or when no locator is resolvable yet (locator-arrival replays).
 */
static void bgp_mup_request_isd_sid(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
	struct srv6_sid_ctx ctx = {};
	struct in6_addr sid = {};
	const char *loc_name;
	enum seg6_mobile_action_t act;

	if (!ep)
		return;
	if (ep->tovpn_sid_ready)
		return;
	/* `sid` is shared by both origination modes; only `segment
	 * interwork` owns an End.M.GTP*.E SID.  A `segment direct` policy
	 * gets its End.DT* SID from the DSD path instead.
	 */
	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK))
		return;

	act = bgp_mup_isd_action_for_afi(afi);
	if (act == ZEBRA_SEG6_MOBILE_ACTION_UNSPEC)
		return;

	loc_name = bgp_mup_select_locator_name(bgp, ep);
	if (!loc_name)
		return;

	/* A `sid ... locator NAME` override names a locator other than the
	 * bgp-instance default; subscribe so zebra delivers its structure
	 * (needed to arm the SID).  Idempotent and skipped once cached.
	 */
	if (ep->locator_name && !ep->override_locator &&
	    strcmp(ep->locator_name, bgp->srv6_locator_name) != 0)
		bgp_zebra_srv6_manager_get_locator(ep->locator_name);

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT)) {
		struct srv6_locator *locator_bgp = bgp_mup_resolve_locator(bgp, ep);

		if (!ep->tovpn_sid_explicit || !locator_bgp ||
		    strcmp(locator_bgp->name, loc_name) != 0)
			return;
		bgp_mup_export_arm_sid(bgp, afi, ep, locator_bgp, ep->tovpn_sid_explicit);
		return;
	}

	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO))
		return;

	ctx.mobile_behavior = act;
	ctx.vrf_id = bgp->vrf_id;
	ctx.afi = afi;
	ctx.safi = SAFI_MUP;

	(void)bgp_zebra_request_srv6_sid(&ctx, &sid, loc_name, NULL);
}

/* Undo bgp_mup_request_isd_sid() / bgp_mup_export_arm_sid() when the
 * (vrf, afi) policy stops owning an End.M.GTP*.E SID: uninstall the
 * local SID, hand an auto-allocated SID back to the SID manager (also
 * cancels one still in flight), and clear the ready latch.
 */
static void bgp_mup_release_isd_sid(struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
	struct srv6_sid_ctx ctx = {};
	const char *loc_name;

	if (!ep)
		return;

	bgp_mup_install_isd_localsid(bgp, afi, true);

	loc_name = bgp_mup_select_locator_name(bgp, ep);
	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO) && loc_name) {
		ctx.mobile_behavior = bgp_mup_isd_action_for_afi(afi);
		ctx.vrf_id = bgp->vrf_id;
		ctx.afi = afi;
		ctx.safi = SAFI_MUP;
		bgp_zebra_release_srv6_sid(&ctx, loc_name);
	}

	XFREE(MTYPE_BGP_SRV6_SID, ep->tovpn_sid);
	if (ep->tovpn_sid_locator)
		srv6_locator_free(ep->tovpn_sid_locator);
	ep->tovpn_sid_locator = NULL;
	ep->tovpn_sid_ready = false;
}

/* Hook the SRv6 SID notify path so the BGP-MUP originate side
 * claims SIDs allocated against End.M.GTP*.E.  When a SID lands
 * for the expected (vrf, afi) policy, pin the locator deeply, stash
 * the SID value, install the local SID, and flag the policy as
 * ready.  Returns true iff the notify was consumed: every SID
 * requested on behalf of the MUP AF is, so the seg6_local L3VPN
 * handling behind the caller never sees one.
 */
bool bgp_mup_handle_sid_alloc(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
			      const struct in6_addr *sid, const char *loc_name)
{
	struct bgp_mup_export_policy *ep;
	struct srv6_locator *locator_bgp;
	const char *want_name;
	afi_t afi;

	if (!bgp || !ctx || !sid || !loc_name)
		return false;
	if (ctx->safi != SAFI_MUP)
		return false;

	/* DSD originates with ctx.behavior set to a seg6local End.DT*
	 * action and ctx.mobile_behavior unset, so a parked `segment
	 * direct` request must be matched before the End.M.GTP*.E
	 * (mobile_behavior) gate below would reject it.
	 */
	if (bgp_mup_dispatch_pending_sid(bgp, ctx, sid))
		return true;

	/* zebra re-announces an already-held SID on every get; a DSD
	 * notify with nothing parked for it is such a repeat.
	 */
	if (ctx->mobile_behavior == ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP4_E)
		afi = AFI_IP;
	else if (ctx->mobile_behavior == ZEBRA_SEG6_MOBILE_ACTION_END_M_GTP6_E)
		afi = AFI_IP6;
	else
		return true;

	/* Nobody owns it any more: the policy is gone, moved off `sid
	 * auto`, dropped `segment interwork`, or rebound its locator.
	 */
	ep = bgp_mup_export_peek(bgp, afi);
	if (!ep || !CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO) ||
	    !CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK)) {
		bgp_zebra_release_srv6_sid(ctx, loc_name);
		return true;
	}

	want_name = bgp_mup_select_locator_name(bgp, ep);
	locator_bgp = bgp_mup_resolve_locator(bgp, ep);
	if (!want_name || strcmp(want_name, loc_name) != 0 || !locator_bgp ||
	    strcmp(locator_bgp->name, loc_name) != 0) {
		bgp_zebra_release_srv6_sid(ctx, loc_name);
		return true;
	}

	bgp_mup_export_arm_sid(bgp, afi, ep, locator_bgp, sid);

	/* SID is armed and the local SID installed; emit the ISD NLRIs
	 * for every locally-originated MUP-RIB prefix in this (vrf, afi).
	 */
	mup_leak_from_vrf_update_all(bgp_get_default(), bgp, afi);
	return true;
}

/* Bgp-instance locator just became available (or the configured
 * locator was rebound).  Walk per-(vrf, afi) MUP policies and kick
 * a SID request for any that have SID_AUTO set but are not yet
 * ready.  Per-instance replay of policies already configured before
 * the locator arrived.
 */
void bgp_mup_locator_arrived(struct bgp *bgp)
{
	afi_t afi;

	if (!bgp)
		return;
	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		bgp_mup_request_isd_sid(bgp, afi);
	bgp_mup_replay_origins(bgp);
}

/* A locator named by an `sid ... locator NAME` override (i.e. not the
 * bgp-instance default) just arrived from zebra.  Cache it on every
 * per-(vrf, afi) MUP policy that references it and re-kick the SID
 * request so a policy whose SID notify raced ahead of the locator can
 * finally arm.
 */
void bgp_mup_override_locator_arrived(struct bgp *bgp, struct srv6_locator *locator)
{
	afi_t afi;

	if (!bgp || !locator)
		return;
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);

		if (!ep || !ep->locator_name ||
		    strcmp(ep->locator_name, locator->name) != 0)
			continue;
		if (ep->override_locator)
			srv6_locator_free(ep->override_locator);
		ep->override_locator = srv6_locator_alloc(locator->name);
		srv6_locator_copy(ep->override_locator, locator);
		bgp_mup_request_isd_sid(bgp, afi);
	}
}

/* The configured locator was deleted: tear down any local-SID
 * installs that referenced it, drop the cached SID, and clear the
 * ready latch so ISD emit stops advertising stale SIDs.  Caller
 * iterates over bgp instances; this helper handles one.
 */
void bgp_mup_locator_delete_purge(struct bgp *bgp, const struct srv6_locator *locator)
{
	struct bgp_mup_export_policy *ep;
	afi_t afi;

	if (!bgp || !locator)
		return;
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		ep = bgp_mup_export_peek(bgp, afi);
		if (!ep)
			continue;

		/* Drop a cached override locator copy so a later re-add
		 * re-resolves it cleanly.
		 */
		if (ep->override_locator &&
		    strcmp(ep->override_locator->name, locator->name) == 0) {
			srv6_locator_free(ep->override_locator);
			ep->override_locator = NULL;
		}

		if (!ep->tovpn_sid_locator)
			continue;
		if (strcmp(ep->tovpn_sid_locator->name, locator->name) != 0)
			continue;

		/* Withdraw the advertised ISDs before the SID disappears,
		 * then uninstall the local SID and drop the cached state.
		 */
		mup_leak_from_vrf_withdraw_all(bgp_get_default(), bgp, afi);
		bgp_mup_install_isd_localsid(bgp, afi, true);

		XFREE(MTYPE_BGP_SRV6_SID, ep->tovpn_sid);
		srv6_locator_free(ep->tovpn_sid_locator);
		ep->tovpn_sid_locator = NULL;
		ep->tovpn_sid_ready = false;
	}

	/* DSD origins pin no per-policy locator copy; match them by the
	 * installed SID falling inside the deleted locator's prefix.
	 */
	bgp_mup_origins_locator_purge(bgp, locator);
}

/* On-wire size of one BGP-MUP NLRI: fixed header plus the route body.
 * T1ST/T2ST length excludes the optional TLVs, so reserve the 1-octet
 * Length field maximum for them.
 */
size_t bgp_mup_prefix_size(const struct prefix *p)
{
	const struct prefix_mup *mp = (const struct prefix_mup *)p;

	if (mp->prefix.route_type == BGP_MUP_T1ST_ROUTE ||
	    mp->prefix.route_type == BGP_MUP_T2ST_ROUTE)
		return BGP_MUP_HDR_BYTES + UINT8_MAX;

	return BGP_MUP_HDR_BYTES + mp->prefix.length;
}

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, const struct attr *attr,
			   bool addpath_capable, uint32_t addpath_tx_id)
{
	const struct prefix_mup *pm = (const struct prefix_mup *)p;
	const struct mup_prefix *mp = &pm->prefix;
	const struct bgp_mup_nlri_data *tlvs;
	uint8_t prefix_octets;
	uint8_t addr_octets;
	uint8_t total_len = 0;
	size_t len_pos;

	/* prd is unused: the RD lives inside struct mup_prefix. */
	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, mp->arch_type);
	stream_putw(s, mp->route_type);

	/* Patch the Length octet once the route body length is known. */
	len_pos = stream_get_endp(s);
	stream_putc(s, 0);

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		/* RD + Prefix Length + Prefix. */
		prefix_octets = PSIZE(mp->isd_route.ip_prefix_length);
		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->isd_route.ip_prefix_length);
		stream_put(s, &mp->isd_route.ip.ip.addr, prefix_octets);
		total_len = RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + prefix_octets;
		break;

	case BGP_MUP_DSD_ROUTE:
		/* RD + Address. */
		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		stream_put(s, mp->rd, RD_BYTES);
		stream_put(s, &mp->dsd_route.ip.ip.addr, addr_octets);
		total_len = RD_BYTES + addr_octets;
		break;

	case BGP_MUP_T1ST_ROUTE:
		/* RD + Prefix Length + Prefix, then the architecture specific
		 * fields and any TLVs carried on the attr, verbatim
		 * (draft 3.1.3.1).
		 */
		prefix_octets = PSIZE(mp->t1st_route.ip_prefix_length);
		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->t1st_route.ip_prefix_length);
		stream_put(s, &mp->t1st_route.ip.ip.addr, prefix_octets);
		total_len = RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + prefix_octets;

		tlvs = attr ? bgp_attr_get_mup_nlri_data(attr) : NULL;
		if (tlvs && total_len + tlvs->length <= UINT8_MAX) {
			stream_put(s, tlvs->val, tlvs->length);
			total_len += tlvs->length;
		} else
			zlog_warn("%s: T1ST %pFX architecture specific fields %s, encoding an incomplete NLRI",
				  __func__, p, tlvs ? "exceed the NLRI Length" : "missing");
		break;

	case BGP_MUP_T2ST_ROUTE: {
		/* RD + Endpoint Length + Endpoint + TEID (0..4 trailing octets). */
		uint8_t teid_bits;
		uint8_t teid_octets;
		uint32_t teid_be;

		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		teid_bits = (mp->t2st_route.endpoint_address_length > addr_octets * 8)
				    ? mp->t2st_route.endpoint_address_length - (addr_octets * 8)
				    : 0;
		/* draft 3.1.4.1: the TEID field is at most 4 octets. */
		if (teid_bits > BGP_MUP_TEID_BYTES * 8)
			teid_bits = BGP_MUP_TEID_BYTES * 8;
		teid_octets = (teid_bits + 7) / 8;
		teid_be = htonl(mp->t2st_route.teid);

		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->t2st_route.endpoint_address_length);
		stream_put(s, &mp->t2st_route.endpoint_address.ip.addr, addr_octets);
		if (teid_octets)
			stream_put(s, &teid_be, teid_octets);

		total_len = RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets + teid_octets;

		/* Re-encode the received optional TLVs verbatim (draft 3.1.4.1). */
		tlvs = attr ? bgp_attr_get_mup_nlri_data(attr) : NULL;
		if (tlvs) {
			if (total_len + tlvs->length <= UINT8_MAX) {
				stream_put(s, tlvs->val, tlvs->length);
				total_len += tlvs->length;
			} else
				zlog_warn("%s: T2ST %pFX TLVs (%u octets) exceed the NLRI Length, not encoded",
					  __func__, p, tlvs->length);
		}
		break;
	}

	default:
		break;
	}

	stream_putc_at(s, len_pos, total_len);
}

/* Fill in the common prefix_mup fields for a parsed BGP-MUP NLRI.  T1ST
 * and T2ST callers pass the mandatory-part length: TLVs are not route key.
 */
static inline void bgp_mup_prefix_init(struct prefix_mup *p, uint16_t route_type, int psize)
{
	p->family = AF_MUP;
	p->prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p->prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p->prefix.route_type = route_type;
	p->prefix.length = psize;
}

/* Validate the optional TLV region of a T1ST/T2ST route body: 0 if valid
 * or empty, -1 if malformed (treat-as-withdraw).  Unknown types only need
 * to be structurally sound; per-type length rules apply only to the route
 * types the TLV is applicable to (draft 3.1.5: Types 1-3 apply to ST2).
 */
int bgp_mup_parse_tlvs(uint16_t route_type, const uint8_t *buf, int len)
{
	uint8_t type, tlv_len;
	int off = 0;

	while (off < len) {
		if (off + BGP_MUP_TLV_HDR_BYTES > len)
			return -1;
		type = buf[off];
		tlv_len = buf[off + 1];
		if (off + BGP_MUP_TLV_HDR_BYTES + tlv_len > len)
			return -1;

		if (route_type == BGP_MUP_T2ST_ROUTE) {
			switch (type) {
			case BGP_MUP_TLV_SESSION_PARAMS:
				if (tlv_len != BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES)
					return -1;
				break;
			case BGP_MUP_TLV_INTERWORK_ENDPOINT:
			case BGP_MUP_TLV_SOURCE_ADDRESS:
				if (tlv_len != IPV4_MAX_BYTELEN && tlv_len != IPV6_MAX_BYTELEN)
					return -1;
				break;
			}
		}

		off += BGP_MUP_TLV_HDR_BYTES + tlv_len;
	}

	return 0;
}

static bool bgp_mup_process_isd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t prefix_len;
	uint8_t prefix_octets;

	if (psize < RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return false;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	prefix_len = pfx[RD_BYTES];
	if ((afi == AFI_IP && prefix_len > IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && prefix_len > IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return false;
	}

	prefix_octets = PSIZE(prefix_len);
	if (psize - (RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES) != prefix_octets) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI prefix length mismatch",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_ISD_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.isd_route.ip_prefix_length = prefix_len;
	p.prefix.isd_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.isd_route.ip.ip.addr, pfx + RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES,
	       prefix_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return true;
}

static bool bgp_mup_process_dsd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;

	if ((afi == AFI_IP && psize != RD_BYTES + IPV4_MAX_BYTELEN) ||
	    (afi == AFI_IP6 && psize != RD_BYTES + IPV6_MAX_BYTELEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP DSD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return false;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	bgp_mup_prefix_init(&p, BGP_MUP_DSD_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);

	if (afi == AFI_IP) {
		addr_octets = IPV4_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V4;
	} else {
		addr_octets = IPV6_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V6;
	}
	memcpy(&p.prefix.dsd_route.ip.ip.addr, pfx + RD_BYTES, addr_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return true;
}

static bool bgp_mup_process_t1st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				       uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint32_t teid;
	uint8_t prefix_len;
	uint8_t prefix_octets;
	uint8_t ep_len, src_len;
	uint8_t ep_octets, src_octets;
	int off;
	int arch_off;

	/* Minimum: RD + Prefix Length + TEID + QFI + Endpoint Length +
	 * Source Length, before any prefix or endpoint address bytes.
	 */
	if (psize < RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES +
			    BGP_MUP_ADDR_LEN_BYTES + BGP_MUP_ADDR_LEN_BYTES) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return false;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);
	off = RD_BYTES;

	prefix_len = pfx[off++];
	if ((afi == AFI_IP && prefix_len > IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && prefix_len > IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return false;
	}
	prefix_octets = PSIZE(prefix_len);

	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.t1st_route.ip_prefix_length = prefix_len;
	p.prefix.t1st_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;

	if (off + prefix_octets + BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + BGP_MUP_ADDR_LEN_BYTES >
	    psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}
	memcpy(&p.prefix.t1st_route.ip.ip.addr, pfx + off, prefix_octets);
	off += prefix_octets;

	/* The architecture specific fields are validated but excluded from
	 * the route key (draft 3.1.3); they ride on the attr instead.
	 */
	arch_off = off;
	memcpy(&teid, pfx + off, BGP_MUP_TEID_BYTES);
	teid = ntohl(teid);
	off += BGP_MUP_TEID_BYTES;
	/* draft 3.1.3.1: TEID MUST NOT be 0. */
	if (teid == 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI TEID=0",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}
	off++; /* QFI */
	/* draft 3.1.3.1: Endpoint Length must be a full host address. */
	ep_len = pfx[off++];
	if ((afi == AFI_IP && ep_len != IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && ep_len != IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid endpoint length %u for AFI %u",
			 peer->bgp->vrf_id, peer->host, ep_len, afi);
		return false;
	}
	ep_octets = ep_len / 8;
	if (off + ep_octets + BGP_MUP_ADDR_LEN_BYTES > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}
	off += ep_octets;

	/* Source Length 0 means no Source Address follows. */
	src_len = pfx[off++];
	if (src_len != 0 && ((afi == AFI_IP && src_len != IPV4_MAX_BITLEN) ||
			     (afi == AFI_IP6 && src_len != IPV6_MAX_BITLEN))) {
		flog_err(EC_BGP_MUP_PACKET,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid source length %u for AFI %u",
			 peer->bgp->vrf_id, peer->host, src_len, afi);
		return false;
	}
	if (src_len) {
		src_octets = src_len / 8;
		if (off + src_octets > psize) {
			flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated source",
				 peer->bgp->vrf_id, peer->host);
			return false;
		}
		off += src_octets;
	}

	/* Optional TLVs may follow the Source Address (draft 3.1.3.1). */
	if (bgp_mup_parse_tlvs(BGP_MUP_T1ST_ROUTE, pfx + off, psize - off) < 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI malformed TLVs",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}
	bgp_mup_prefix_init(&p, BGP_MUP_T1ST_ROUTE, arch_off);

	if (attr) {
		struct attr attr_tmp;
		struct bgp_mup_nlri_data *data;

		/* The intern below takes over attr_tmp's extra, so give the
		 * copy its own rather than letting it point at the parent's.
		 */
		bgp_attr_dup_into(&attr_tmp, attr);

		/* Carry the architecture specific fields and any TLVs on the
		 * attr so re-advertisement re-encodes them unchanged.
		 */
		data = mup_nlri_data_intern(mup_nlri_data_new(pfx + arch_off, psize - arch_off));
		bgp_attr_set_mup_nlri_data(&attr_tmp, data);
		bgp_update(peer, (struct prefix *)&p, addpath_id, &attr_tmp, afi, safi,
			   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
		/* An intern took the extra over (leaving NULL behind); free it
		 * when the update was dropped before any intern ran.
		 */
		bgp_attr_extra_discard(&attr_tmp);
		mup_nlri_data_unintern(&data);
	} else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return true;
}

static bool bgp_mup_process_t2st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				       uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;
	uint8_t teid_bits;
	uint8_t teid_octets;
	uint32_t teid_be = 0;
	uint8_t ea_len;
	int mandatory;

	if (psize < RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + IPV4_MAX_BYTELEN) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return false;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	ea_len = pfx[RD_BYTES];
	if ((afi == AFI_IP && ea_len > IPV4_MAX_BITLEN + BGP_MUP_TEID_BYTES * 8) ||
	    (afi == AFI_IP6 && ea_len > IPV6_MAX_BITLEN + BGP_MUP_TEID_BYTES * 8)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI bad endpoint length %u",
			 peer->bgp->vrf_id, peer->host, ea_len);
		return false;
	}

	addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	if (RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}

	teid_bits = (ea_len > addr_octets * 8) ? ea_len - addr_octets * 8 : 0;
	teid_octets = (teid_bits + 7) / 8;
	mandatory = RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets + teid_octets;
	if (mandatory > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI truncated TEID",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_T2ST_ROUTE, mandatory);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.t2st_route.endpoint_address_length = ea_len;
	p.prefix.t2st_route.endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.t2st_route.endpoint_address.ip.addr,
	       pfx + RD_BYTES + BGP_MUP_ADDR_LEN_BYTES, addr_octets);
	if (teid_octets) {
		memcpy(&teid_be, pfx + RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets,
		       teid_octets);
		/* Mask the sub-octet padding bits so they do not enter the
		 * route key or pass the TEID=0 check below.
		 */
		p.prefix.t2st_route.teid = ntohl(teid_be) &
					   (0xffffffffU << (BGP_MUP_TEID_BYTES * 8 - teid_bits));
	}
	/* draft 3.1.4.1: a TEID field that is present MUST NOT be 0; an
	 * endpoint-level aggregate carries no TEID field and is valid.
	 */
	if (teid_octets && p.prefix.t2st_route.teid == 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI TEID=0",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}

	/* Optional TLVs may follow the TEID (draft 3.1.4.1). */
	if (bgp_mup_parse_tlvs(BGP_MUP_T2ST_ROUTE, pfx + mandatory, psize - mandatory) < 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI malformed TLVs",
			 peer->bgp->vrf_id, peer->host);
		return false;
	}

	if (attr) {
		struct attr attr_tmp;
		struct bgp_mup_nlri_data *tlvs = NULL;

		/* The intern below takes over attr_tmp's extra, so give the
		 * copy its own rather than letting it point at the parent's.
		 */
		bgp_attr_dup_into(&attr_tmp, attr);

		/* Carry the raw TLV bytes on the attr so re-advertisement
		 * re-encodes them unchanged (draft 3.1.4.1).
		 */
		if (psize > mandatory) {
			tlvs = mup_nlri_data_intern(
				mup_nlri_data_new(pfx + mandatory, psize - mandatory));
			bgp_attr_set_mup_nlri_data(&attr_tmp, tlvs);
		}
		bgp_update(peer, (struct prefix *)&p, addpath_id, &attr_tmp, afi, safi,
			   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
		/* An intern took the extra over (leaving NULL behind); free it
		 * when the update was dropped before any intern ran.
		 */
		bgp_attr_extra_discard(&attr_tmp);
		if (tlvs)
			mup_nlri_data_unintern(&tlvs);
	} else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return true;
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

/* Parse an "ASN:NN" Direct-Type Segment Identifier operator string into
 * its 16-bit AS and 32-bit value halves.  Returns false on malformed
 * input (missing colon, overflow, trailing garbage).
 */
static bool bgp_mup_parse_seg_id_str(const char *mup_str, uint16_t *mup_as, uint32_t *mup_val)
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
 * Identifier (draft-ietf-bess-mup-safi) from an "ASN:NN" operator
 * string.  Returns the ecommunity (caller frees) or NULL on parse
 * failure.
 */
static struct ecommunity *bgp_mup_build_mup_ec(const char *mup_str)
{
	uint16_t mup_as = 0;
	uint32_t mup_val = 0;
	struct ecommunity_val ev = {};
	struct ecommunity *ec;

	if (!bgp_mup_parse_seg_id_str(mup_str, &mup_as, &mup_val))
		return NULL;
	ev.val[0] = ECOMMUNITY_ENCODE_MUP;
	ev.val[1] = ECOMMUNITY_MUP_SUBTYPE_DIRECT_SEG_AS2;
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

/* Map a DSD endpoint behavior (SRV6_ENDPOINT_BEHAVIOR_END_DT4/6/46, the
 * wire/attr encoding kept in the export policy and origin records) to
 * the seg6local action zebra installs for the local SID.  The reverse
 * mapping is implicit: the DSD attr carries the SRV6_ENDPOINT_BEHAVIOR
 * value verbatim.
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

/* Process-global self-origin index for DSD.  Keyed by the 48-bit MUP-EC
 * Direct-Type Segment Identifier of every persisted `segment direct`
 * line across all bgp instances, so the receive-side self-DSD check
 * (bgp_mup_dsd_is_self) answers in O(1) instead of walking every
 * instance's origin list per T2ST UPDATE.  Lazily created on first
 * insert, mirroring the file-static iface-state caches below; leaked at
 * process exit like those.
 */
struct bgp_mup_self_dsd_key {
	uint64_t segment_id;
};

static struct hash *bgp_mup_self_dsd_hash;

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
	struct bgp_mup_self_dsd_key *e = XCALLOC(MTYPE_BGP_MUP_SELF_KEY, sizeof(*e));

	memcpy(e, data, sizeof(*e));
	return e;
}

static void bgp_mup_self_dsd_index_add(uint64_t segment_id)
{
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };

	if (!bgp_mup_self_dsd_hash)
		bgp_mup_self_dsd_hash = hash_create(bgp_mup_self_dsd_hash_key,
						    bgp_mup_self_dsd_hash_cmp,
						    "BGP MUP self DSD hash");
	(void)hash_get(bgp_mup_self_dsd_hash, &tmp, bgp_mup_self_dsd_alloc);
}

static void bgp_mup_self_dsd_key_free(void *data)
{
	struct bgp_mup_self_dsd_key *e = data;

	XFREE(MTYPE_BGP_MUP_SELF_KEY, e);
}

static void bgp_mup_self_dsd_index_del(uint64_t segment_id)
{
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };
	struct bgp_mup_self_dsd_key *e;

	if (!bgp_mup_self_dsd_hash)
		return;
	e = hash_release(bgp_mup_self_dsd_hash, &tmp);
	XFREE(MTYPE_BGP_MUP_SELF_KEY, e);
}

/* True iff a `segment direct` line on any bgp instance owns the MUP-EC
 * Direct-Type Segment Identifier carried on a T2ST.  Used to skip
 * install for self-originated DSDs, whose resolved nexthop is a local
 * End.DT* action that would black-hole if a copy of the T2ST came back
 * over the BGP session.
 */
static bool bgp_mup_dsd_is_self(uint64_t segment_id)
{
	struct bgp_mup_self_dsd_key tmp = { .segment_id = segment_id };

	if (!bgp_mup_self_dsd_hash)
		return false;
	return hash_lookup(bgp_mup_self_dsd_hash, &tmp) != NULL;
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
		if (p[1] != ECOMMUNITY_MUP_SUBTYPE_DIRECT_SEG_AS2)
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
	const struct bgp_attr_srv6_l3service *l3 = attr ? bgp_attr_get_srv6_l3service(attr) : NULL;

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
			  " - keeping first-bound entry",
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

	bgp_mup_origins_pending_free(bgp);

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
			/* Only a real global-unicast address is a valid SRv6
			 * outer source.  Reject link-local / loopback / etc. and
			 * the IPv4-embedded pseudo-addresses kernel auto-tunnels
			 * (e.g. sit0's ::127.0.0.1) carry by default.
			 */
			if (!is_ipv6_global_unicast(&p->u.prefix6) ||
			    IN6_IS_ADDR_V4COMPAT(&p->u.prefix6) ||
			    IN6_IS_ADDR_V4MAPPED(&p->u.prefix6))
				continue;
			*out = p->u.prefix6;
			return true;
		}
	}
	return false;
}

/* Cache for bgp_mup_local_v6_source results.  The helper walks every
 * interface x every connected address per T1ST/T2ST install; the answer
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

/* Release the process-wide BGP-MUP caches.  Both the self-DSD index
 * and the per-vrf IPv6 source memo outlive every bgp instance, so
 * bgp_free() cannot own them; bgp_exit() calls this alongside the
 * other module finishers.
 */
void bgp_mup_finish(void)
{
	struct bgp_mup_v6src_cache_entry *v;

	hash_clean_and_free(&bgp_mup_self_dsd_hash, bgp_mup_self_dsd_key_free);

	if (!bgp_mup_iface_cache_inited)
		return;
	while ((v = bgp_mup_v6src_cache_pop(&bgp_mup_v6src_cache)))
		XFREE(MTYPE_BGP_MUP_IFACE_CACHE, v);
	bgp_mup_v6src_cache_fini(&bgp_mup_v6src_cache);
	bgp_mup_iface_cache_inited = false;
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
 * For v6, Args.Mob lives at offset loc_func - NOT at the SID's trailing
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
/* Architecture specific fields of a T1ST route (draft 3.1.3.1).  The route
 * key holds only the RD and the UE prefix, so these ride on the path
 * attribute and are decoded per install.
 */
struct bgp_mup_t1st_arch {
	uint32_t teid;
	uint8_t qfi;
	struct ipaddr endpoint_address;
	uint8_t source_address_length;
	struct ipaddr source_address;
};

static bool bgp_mup_t1st_arch_decode(const struct attr *attr, struct bgp_mup_t1st_arch *out)
{
	const struct bgp_mup_nlri_data *data = attr ? bgp_attr_get_mup_nlri_data(attr) : NULL;
	uint8_t ep_len, src_len;
	int off;

	if (!data ||
	    data->length < BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + 2 * BGP_MUP_ADDR_LEN_BYTES)
		return false;

	memset(out, 0, sizeof(*out));
	memcpy(&out->teid, data->val, BGP_MUP_TEID_BYTES);
	out->teid = ntohl(out->teid);
	off = BGP_MUP_TEID_BYTES;
	out->qfi = data->val[off++];

	ep_len = data->val[off++];
	if (ep_len != IPV4_MAX_BITLEN && ep_len != IPV6_MAX_BITLEN)
		return false;
	if (off + ep_len / 8 + BGP_MUP_ADDR_LEN_BYTES > data->length)
		return false;
	if (ep_len == IPV4_MAX_BITLEN) {
		out->endpoint_address.ipa_type = IPADDR_V4;
		memcpy(&out->endpoint_address.ipaddr_v4, data->val + off, IPV4_MAX_BYTELEN);
	} else {
		out->endpoint_address.ipa_type = IPADDR_V6;
		memcpy(&out->endpoint_address.ipaddr_v6, data->val + off, IPV6_MAX_BYTELEN);
	}
	off += ep_len / 8;

	src_len = data->val[off++];
	if (src_len) {
		if (src_len != IPV4_MAX_BITLEN && src_len != IPV6_MAX_BITLEN)
			return false;
		if (off + src_len / 8 > data->length)
			return false;
		if (src_len == IPV4_MAX_BITLEN) {
			out->source_address.ipa_type = IPADDR_V4;
			memcpy(&out->source_address.ipaddr_v4, data->val + off, IPV4_MAX_BYTELEN);
		} else {
			out->source_address.ipa_type = IPADDR_V6;
			memcpy(&out->source_address.ipaddr_v6, data->val + off, IPV6_MAX_BYTELEN);
		}
	}
	out->source_address_length = src_len;
	return true;
}

static bool bgp_mup_synthesize_t1st_sid(const struct bgp_mup_isd_entry *isd,
					const struct bgp_mup_t1st_arch *ext, struct in6_addr *out)
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
		if (ext->endpoint_address.ipa_type != IPADDR_V4)
			return false;
		if (loc_func + 32 + 40 > IPV6_MAX_BITLEN)
			return false;
		v4 = ntohl(ext->endpoint_address.ipaddr_v4.s_addr);
		bgp_mup_sid_set_bits(out, loc_func, 32, (uint64_t)v4);
		args_off = loc_func + 32;
	} else {
		if (loc_func + 40 > IPV6_MAX_BITLEN)
			return false;
		args_off = loc_func;
	}

	args_mob = bgp_mup_args_mob_session(ext->teid, ext->qfi);
	bgp_mup_sid_set_bits(out, args_off, 40, args_mob);
	return true;
}

/* Lay out an outer IPv6 source per RFC 9433 Section 6.6 Figure 10: keep
 * @plen bits of the Source UPF Prefix already in @sa, put @v4 right
 * after them, and clear the trailing bits the behavior ignores.
 */
static void bgp_mup_source_upf_sa(struct in6_addr *sa, uint8_t plen, struct in_addr v4)
{
	uint8_t byte = plen / 8;
	uint8_t bit = plen % 8;

	if (bit) {
		sa->s6_addr[byte] &= (uint8_t)(0xff << (8 - bit));
		byte++;
	}
	memset(&sa->s6_addr[byte], 0, sizeof(sa->s6_addr) - byte);
	bgp_mup_sid_set_bits(sa, plen, 32, ntohl(v4.s_addr));
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

static bool bgp_mup_resolve_t1st(struct bgp *bgp, const struct bgp_mup_export_policy *ep,
				 const struct srv6_locator *loc,
				 const struct bgp_mup_t1st_arch *ext,
				 struct bgp_mup_t1st_resolved *out)
{
	struct bgp_mup_isd_entry *isd;
	afi_t afi;

	afi = (ext->endpoint_address.ipa_type == IPADDR_V4) ? AFI_IP : AFI_IP6;
	isd = bgp_mup_isd_lookup(bgp, afi, &ext->endpoint_address);
	if (!isd) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: T1ST endpoint has no matching ISD; skip install");
		return false;
	}
	if (!bgp_mup_synthesize_t1st_sid(isd, ext, &out->sid)) {
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
		/* RFC 9433 Section 6.6 Figure 10: Source UPF Prefix, then the
		 * IPv4 SA, then bits End.M.GTP4.E ignores.  The prefix is this
		 * speaker's SRv6 locator, so the address the far gateway
		 * answers to routes back here; `source-upf-prefix-len` says
		 * how much of it precedes the IPv4 SA, and must match the
		 * gateway's extraction offset.
		 */
		uint8_t plen = BGP_MUP_SOURCE_UPF_PREFIX_LEN_DEFAULT;

		if (ep && CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SOURCE_UPF_PREFIX_LEN_SET))
			plen = ep->source_upf_prefix_len;

		if (loc) {
			out->outer_sa = loc->prefix.prefix;
			out->have_outer_sa = true;
		} else if (bgp_mup_local_v6_source(bgp->vrf_id, &out->outer_sa)) {
			out->have_outer_sa = true;
		}
		if (out->have_outer_sa)
			bgp_mup_source_upf_sa(&out->outer_sa, plen,
					      ext->source_address.ipaddr_v4);
	}
	if (!out->have_outer_sa) {
		if (bgp_mup_local_v6_source(bgp->vrf_id, &out->outer_sa))
			out->have_outer_sa = true;
	}
	return out->have_outer_sa;
}

/* `encap-behavior` has no per-vrf form: its command writes the default
 * instance whatever node it is typed under, so reading a per-vrf
 * instance would always give back the H.Encaps default.
 */
static enum srv6_headend_behavior bgp_mup_dl_encap_behavior(void)
{
	struct bgp *bgp_default = bgp_get_default();

	return bgp_default ? bgp_default->srv6_encap_behavior
			   : SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
}

static void bgp_mup_build_t1st_route(const struct mup_prefix *mp,
				     const struct bgp_mup_t1st_arch *ext,
				     const struct bgp_mup_t1st_resolved *r,
				     enum srv6_headend_behavior encap_behavior,
				     struct zapi_route *api)
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
	/* Recurse the End.M.GTP*.E gate in the default vrf: the SR-domain
	 * underlay ("forward to B") is shared across slices, not a per-slice
	 * FIB (RFC 9433 Section 8 slicing is a logical overlay on one SR
	 * domain), so the gate SID locator is reachable in the global table.
	 * The route prefix still lands in the slice table (api->vrf_id is set
	 * to the install vrf by the caller); only this nexthop recurses
	 * globally.  The slice is selected by the destination End.DT SID at
	 * the far PE, not by an underlay table here.  Leaving api_nh->vrf_id
	 * zero (VRF_DEFAULT) is the global recursion.
	 */
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
	/* An encapsulating behavior, never H.Insert: T1ST is DL ingress at
	 * the MUP-PE so the inner is whatever traffic was destined to the
	 * UE prefix and need not be IPv6.  H.Encaps.Red additionally drops
	 * the SID that already appears in the outer DA, which for an IPv4
	 * endpoint leaves a single-SID policy with no SRH at all.
	 */
	api_nh->srv6_encap_behavior = encap_behavior;
	/* Per-route outer source (SEG6_IPTUNNEL_SRC): the T1ST Source
	 * Address (draft-ietf-bess-mup-safi Section 3.3.9) in the Figure 10
	 * layout End.M.GTP4.E restores the IPv4 SA from.  Without it the
	 * kernel would pick the egress interface address.
	 */
	api_nh->srv6_encap_source = r->outer_sa;
	api->nexthop_num = 1;
}

static void bgp_mup_build_t2st_route(struct bgp *bgp, const struct mup_prefix *mp,
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
	if (ep_v4) {
		/* H.M.GTP4.D writes the outer IPv6 source that the far
		 * End.M.GTP4.E reads back per RFC 9433 Section 6.6 Figure 10,
		 * so both ends have to agree on where the IPv4 sits.  The
		 * GTP6 sibling has no such field and the kernel rejects the
		 * attribute there.
		 */
		struct bgp *vrf_bgp = bgp_lookup_by_vrf_id(vrf_id);
		struct bgp_mup_export_policy *vep =
			vrf_bgp ? bgp_mup_export_peek(vrf_bgp, AFI_IP) : NULL;

		api_nh->seg6_mobile_ctx.v6_src_prefix_len =
			(vep && vep->source_upf_prefix_len)
				? vep->source_upf_prefix_len
				: BGP_MUP_SOURCE_UPF_PREFIX_LEN_DEFAULT;
	}
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
	/* The seg6_mobile lwtunnel has no reduced form, so this never
	 * follows `encap-behavior`, and zebra omits the plain seg6 encap
	 * once a seg6_mobile action is set.  Assign it all the same: the
	 * enum's zero value is H.Insert, which would otherwise surface in
	 * the route dump and in the forwarding-state hash key.
	 */
	api_nh->srv6_encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
	api_nh->seg6_mobile_ctx.sr_prefix_len = loc_func;
	/* No SEG6_MOBILE_VRFTABLE: the rebuilt SRv6 packet's egress ("forward
	 * to B", RFC 9433 Section 6.7 S07 for H.M.GTP4.D / Section 6.3 S04 for
	 * End.M.GTP6.D) is the shared SR underlay and resolves in the global
	 * FIB.  Leaving seg6_mobile_ctx.vrftable zero makes zebra omit the
	 * attribute, so the kernel seg6_lookup_nexthop runs in the main table.
	 * The per-slice table applies only to the inner End.DT decap that
	 * terminates the PDU session at the far PE, not to this underlay hop.
	 */
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
 * every caller centrally - a vrf with rtlist set but the toggle clear
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
 * this RT - the caller skips the kernel install in that case.
 *
 * Mirrors L3VPN's vpn_leak_to_vrf_update_onevrf, which tests only
 * vpn_policy[afi].rtlist[FROMVPN] (the import side).  An instance with
 * no `route-target import` line never imports - operators use it just
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

/* Build the inner forwarding prefix (UE / endpoint) carried by a MUP
 * NLRI so the receive-side `route-map import` can match on it.  This is
 * the prefix the install would put into the per-vrf RIB, not the MUP
 * route key.
 */
static void bgp_mup_inner_prefix(const struct mup_prefix *mp, struct prefix *out)
{
	memset(out, 0, sizeof(*out));
	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		out->family = (mp->isd_route.ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
		out->prefixlen = mp->isd_route.ip_prefix_length;
		if (out->family == AF_INET)
			out->u.prefix4 = mp->isd_route.ip.ipaddr_v4;
		else
			out->u.prefix6 = mp->isd_route.ip.ipaddr_v6;
		break;
	case BGP_MUP_DSD_ROUTE:
		if (mp->dsd_route.ip.ipa_type == IPADDR_V4) {
			out->family = AF_INET;
			out->prefixlen = IPV4_MAX_BITLEN;
			out->u.prefix4 = mp->dsd_route.ip.ipaddr_v4;
		} else {
			out->family = AF_INET6;
			out->prefixlen = IPV6_MAX_BITLEN;
			out->u.prefix6 = mp->dsd_route.ip.ipaddr_v6;
		}
		break;
	case BGP_MUP_T1ST_ROUTE:
		out->family = (mp->t1st_route.ip.ipa_type == IPADDR_V4) ? AF_INET : AF_INET6;
		out->prefixlen = mp->t1st_route.ip_prefix_length;
		if (out->family == AF_INET)
			out->u.prefix4 = mp->t1st_route.ip.ipaddr_v4;
		else
			out->u.prefix6 = mp->t1st_route.ip.ipaddr_v6;
		break;
	case BGP_MUP_T2ST_ROUTE:
		if (IS_IPADDR_V4(&mp->t2st_route.endpoint_address)) {
			out->family = AF_INET;
			out->prefixlen = IPV4_MAX_BITLEN;
			out->u.prefix4 = mp->t2st_route.endpoint_address.ipaddr_v4;
		} else {
			out->family = AF_INET6;
			out->prefixlen = IPV6_MAX_BITLEN;
			out->u.prefix6 = mp->t2st_route.endpoint_address.ipaddr_v6;
		}
		break;
	}
}

/* Apply the receive-side `route-map import` (rmap[FROMMUP]) of the VRF
 * that imports this NLRI's RT before any install side-effects.  Returns
 * true if the route should proceed to install, false if RMAP_DENYMATCH
 * says skip.  No rmap configured (or no matched VRF) is PERMITMATCH.
 *
 * The matched VRF is the same one bgp_mup_match_install_vrf selects for
 * the dataplane install, so the rmap applied here is the matched-install
 * VRF's, not a per-VRF iteration.  When several non-default VRFs declare
 * the same RT under `rt import`, only the first matched VRF's
 * rmap[FROMMUP] runs.
 */
static bool bgp_mup_apply_import_rmap(afi_t afi, const struct mup_prefix *mp,
				      struct bgp_path_info *info)
{
	vrf_id_t install_vrf_id;
	struct bgp *vrf_bgp;
	struct bgp_mup_export_policy *ep;
	struct bgp_path_info tmp_info;
	struct bgp_path_info_extra path_extra;
	struct attr static_attr = {};
	struct prefix p_inner;
	struct peer *peer;
	route_map_result_t rmap_ret;

	if (!info || !info->attr)
		return true;
	install_vrf_id = bgp_mup_match_install_vrf(afi, info->attr);
	if (install_vrf_id == VRF_UNKNOWN)
		return true;
	vrf_bgp = bgp_lookup_by_vrf_id(install_vrf_id);
	if (!vrf_bgp)
		return true;
	ep = bgp_mup_export_peek(vrf_bgp, afi);
	if (!ep || !ep->rmap[BGP_MUP_POLICY_DIR_FROMMUP])
		return true;

	bgp_mup_inner_prefix(mp, &p_inner);
	bgp_attr_dup_into(&static_attr, info->attr);
	peer = info->peer ? info->peer : vrf_bgp->peer_self;
	prep_for_rmap_apply(&tmp_info, &path_extra, info->net, info, peer, NULL, &static_attr);
	rmap_ret = route_map_apply(ep->rmap[BGP_MUP_POLICY_DIR_FROMMUP], &p_inner, &tmp_info);
	bgp_attr_flush(&static_attr);
	if (rmap_ret == RMAP_DENYMATCH) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: route-map import on vrf %s denied %pFX (route_type %u); skip install",
				   vrf_bgp->name ? vrf_bgp->name : "default", &p_inner,
				   mp->route_type);
		return false;
	}
	return true;
}

/* Move the nexthop the T1ST/T2ST resolution built into the interned
 * forwarding state that rides on the leaked unicast path.  bgp_zebra.c
 * rebuilds the zapi nexthop from it at announce time, the same way an
 * L3VPN path's SID travels on srv6_l3service.
 */
static struct bgp_mup_fwd *bgp_mup_fwd_from_nexthop(const struct zapi_nexthop *api_nh)
{
	struct bgp_mup_fwd *fwd = mup_fwd_new();
	uint8_t i;

	fwd->nh_type = api_nh->type;
	fwd->nh_vrf_id = api_nh->vrf_id;
	fwd->ifindex = api_nh->ifindex;
	fwd->gate = api_nh->gate.ipv6;
	fwd->seg_num = api_nh->seg_num;
	for (i = 0; i < api_nh->seg_num && i < array_size(fwd->segs); i++)
		fwd->segs[i] = api_nh->seg6_segs[i];
	fwd->encap_behavior = api_nh->srv6_encap_behavior;
	fwd->encap_source = api_nh->srv6_encap_source;
	fwd->seg6_mobile_action = api_nh->seg6_mobile_action;
	fwd->seg6_mobile_ctx = api_nh->seg6_mobile_ctx;

	return fwd;
}

/* Find the path this MUP route previously leaked into `bn`.  With no
 * source path to match on, fall back to any imported path carrying MUP
 * forwarding state: the withdraw then still reaches the entry a prior
 * announce created.
 */
static struct bgp_path_info *bgp_mup_leak_find(struct bgp_dest *bn, struct bgp_path_info *source)
{
	struct bgp_path_info *bpi;

	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (source) {
			if (bpi->extra && bpi->extra->vrfleak &&
			    bpi->extra->vrfleak->parent == source)
				return bpi;
			continue;
		}
		if (bpi->sub_type == BGP_ROUTE_IMPORTED && bgp_attr_get_mup_fwd(bpi->attr))
			return bpi;
	}
	return NULL;
}

/* Leak a resolved T1ST/T2ST into the importing vrf's unicast RIB.  The
 * prefix lives in the vrf's unicast address space, so it has to reach the
 * FIB through that RIB's best-path selection - installing it straight to
 * zebra would let a MUP route and, say, an L3VPN route for the same UE
 * prefix overwrite each other's zebra entry with no arbitration.
 */
static void bgp_mup_leak_update(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi,
				const struct prefix *p, struct bgp_path_info *source,
				struct attr *static_attr)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;

	bn = bgp_afi_node_get(to_bgp->rib[afi][SAFI_UNICAST], afi, SAFI_UNICAST, p, NULL);
	bpi = bgp_mup_leak_find(bn, source);

	if (bpi) {
		if (!CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) &&
		    attrhash_cmp(bpi->attr, static_attr)) {
			bgp_dest_unlock_node(bn);
			return;
		}
		bgp_path_info_set_flag(bn, bpi, BGP_PATH_ATTR_CHANGED);
		if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(bn, bpi);
		bgp_attr_unintern(&bpi->attr);
		bpi->attr = bgp_attr_intern(static_attr);
		bpi->uptime = monotime(NULL);
		bgp_path_info_set_flag(bn, bpi, BGP_PATH_VALID);
		bgp_process(to_bgp, bn, bpi, afi, SAFI_UNICAST);
		bgp_dest_unlock_node(bn);
		return;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, 0, to_bgp->peer_self,
			bgp_attr_intern(static_attr), bn);

	bgp_path_info_extra_get(new);
	if (!new->extra->vrfleak)
		new->extra->vrfleak = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
					      sizeof(struct bgp_path_info_extra_vrfleak));
	if (source) {
		new->extra->vrfleak->parent = bgp_path_info_lock(source);
		bgp_dest_lock_node((struct bgp_dest *)source->net);
		if (source->peer)
			new->extra->vrfleak->peer_orig = peer_lock(source->peer);
	}
	new->extra->vrfleak->bgp_orig = bgp_lock(from_bgp);

	/* The nexthop is an SRv6 SID zebra recurses on, not an address BGP
	 * nexthop tracking resolves, so validity is not conditional here.
	 */
	bgp_path_info_set_flag(bn, new, BGP_PATH_VALID);
	bgp_path_info_add(bn, new);
	bgp_aggregate_increment(to_bgp, p, new, afi, SAFI_UNICAST);
	bgp_process(to_bgp, bn, new, afi, SAFI_UNICAST);
}

static void bgp_mup_leak_withdraw(struct bgp *to_bgp, afi_t afi, const struct prefix *p,
				  struct bgp_path_info *source)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;

	bn = bgp_node_lookup(to_bgp->rib[afi][SAFI_UNICAST], p);
	if (!bn)
		return;

	bpi = bgp_mup_leak_find(bn, source);
	if (bpi) {
		bgp_aggregate_decrement(to_bgp, p, bpi, afi, SAFI_UNICAST);
		bgp_path_info_mark_for_delete(bn, bpi);
		bgp_process(to_bgp, bn, bpi, afi, SAFI_UNICAST);
	}
	bgp_dest_unlock_node(bn);
}

static int bgp_mup_st_announce(struct bgp_dest *dest, struct bgp_path_info *info, struct bgp *bgp,
			       const struct prefix_mup *pm, const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	afi_t afi = bgp_mup_afi_from_prefix(mp);
	vrf_id_t install_vrf_id = bgp_mup_match_install_vrf(afi, info->attr);
	struct bgp_mup_fwd *fwd;
	struct attr attr_tmp;
	struct bgp *to_bgp;

	(void)dest;

	/* No per-vrf instance imports this RT - there is no local table
	 * the install should land in.
	 */
	if (install_vrf_id == VRF_UNKNOWN) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP-MUP: route_type %u has no per-vrf RT match; skip install",
				   pm->prefix.route_type);
		return 0;
	}

	if (mp->route_type == BGP_MUP_T1ST_ROUTE) {
		struct bgp *vrf_bgp = bgp_lookup_by_vrf_id(install_vrf_id);
		const struct bgp_mup_export_policy *ep =
			vrf_bgp ? bgp_mup_export_peek(vrf_bgp, afi) : NULL;
		const struct srv6_locator *loc =
			vrf_bgp ? bgp_srv6_locator_lookup(vrf_bgp, bgp_get_default()) : NULL;
		struct bgp_mup_t1st_resolved r;
		struct bgp_mup_t1st_arch ext;

		if (!bgp_mup_t1st_arch_decode(info->attr, &ext) ||
		    !bgp_mup_resolve_t1st(bgp, ep, loc, &ext, &r)) {
			/* Withdraw any prior install for this T1ST: an ISD
			 * may have been removed or the source-address
			 * resolution failed.  Idempotent if nothing was
			 * installed.
			 */
			bgp_mup_st_delete_send(bgp, info, mp);
			return 0;
		}
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t1st_route(mp, &ext, &r, bgp_mup_dl_encap_behavior(), &api);
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
		/* T2ST install is symmetric across v4/v6 - both place the
		 * GTP-U-decap+SRv6-encap action at the MUP-GW ingress (RFC 9433
		 * Section 6.6 H.M.GTP4.D for v4; Section 6.3 End.M.GTP6.D for
		 * v6).  bgp_mup_build_t2st_route picks the right kernel action
		 * (and the corresponding SR policy carrier - nh6 vs SRH segs)
		 * from endpoint_address's family.  For v6, the configured SR
		 * Policy is pushed verbatim per RFC 9433 Section 6.3 S04 ("SRH
		 * containing B"); a single-segment policy [End.DT6@MUP-PE]
		 * therefore lands at MUP-PE with segments_left == 0 so End.DT6
		 * decaps cleanly.
		 */
		bgp_mup_zapi_init(&api, bgp, info, true);
		bgp_mup_build_t2st_route(bgp, mp, dsd, install_vrf_id, &api);
	}
	to_bgp = bgp_lookup_by_vrf_id(install_vrf_id);
	if (!to_bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("BGP-MUP: leaking route_type %u into vrf %u unicast RIB",
			   pm->prefix.route_type, install_vrf_id);

	fwd = mup_fwd_intern(bgp_mup_fwd_from_nexthop(&api.nexthops[0]));
	bgp_attr_dup_into(&attr_tmp, info->attr);
	bgp_attr_set_mup_fwd(&attr_tmp, fwd);

	bgp_mup_leak_update(to_bgp, bgp, afi, &api.prefix, info, &attr_tmp);

	bgp_attr_extra_discard(&attr_tmp);
	mup_fwd_unintern(&fwd);
	return 0;
}

static void bgp_mup_st_delete_send(struct bgp *bgp, struct bgp_path_info *info,
				   const struct mup_prefix *mp)
{
	struct zapi_route api = {};
	vrf_id_t install_vrf_id;
	afi_t afi = bgp_mup_afi_from_prefix(mp);
	struct bgp *to_bgp;

	bgp_mup_zapi_init(&api, bgp, info, false);
	if (!bgp_mup_build_st_delete(mp, &api))
		return;
	/* The leak went into the per-vrf table that imports the route's
	 * RT - the withdraw must target the same table.  Falling back to
	 * bgp->vrf_id (== default) here would leave a stale path in the
	 * per-vrf table when the matching ISD/DSD is removed.  Mirrors
	 * L3VPN's vpn_leak_to_vrf_withdraw which walks each
	 * import-matching vrf to issue the withdraw.
	 */
	install_vrf_id = bgp_mup_match_install_vrf(afi, info ? info->attr : NULL);
	if (install_vrf_id == VRF_UNKNOWN)
		return;

	to_bgp = bgp_lookup_by_vrf_id(install_vrf_id);
	if (!to_bgp)
		return;

	bgp_mup_leak_withdraw(to_bgp, afi, &api.prefix, info);
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

	/* Receive-side `route-map import` gate, applied uniformly to every
	 * MUP route type before it reaches the discovery cache (ISD/DSD)
	 * or the install path (T1ST/T2ST).  A DENYMATCH skips this
	 * re-announce; any prior cached/installed state is torn down by
	 * the withdraw mup_import_replay issues ahead of the re-announce
	 * when the route-map changes.  Denying an ISD/DSD also withdraws
	 * the T1ST/T2ST that resolved against it via the cache-removal
	 * reannounce cascade.
	 */
	if (!bgp_mup_apply_import_rmap(afi, mp, info))
		return 0;

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

/* Leaked MUP paths carry no SRv6 L3VPN SID, so bgp_zebra's own SRv6
 * encap refresh walk never reaches them.
 */
void bgp_mup_srv6_encap_behavior_changed(void)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		bgp_mup_schedule_reannounce_st_routes(bgp, AFI_IP);
		bgp_mup_schedule_reannounce_st_routes(bgp, AFI_IP6);
	}
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

/* Fill the flat SAFI_MUP RIB lookup key from the 8 RD octets carried
 * in an ISD NLRI.  SAFI_MUP keeps a single table keyed by the NLRI
 * itself; the prd is only the handle bgp_afi_node_get and
 * bgp_safi_node_lookup expect.
 */
static void bgp_mup_prd_from_bytes(struct prefix_rd *prd, const uint8_t *rd)
{
	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;
	memcpy(prd->val, rd, 8);
}

/* Build the locally-originated attribute for an ISD NLRI: an IPv6
 * MP_REACH next-hop, the SRv6 L3 Service Prefix-SID TLV carrying the
 * shared End.M.GTP{4,6}.E SID, and the export RT ecommunity.  Mirrors
 * the attribute L3VPN stamps in vpn_leak_from_vrf_update: the caller
 * owns @attrp and bgp_mup_originate_common() interns it once.
 */
static void bgp_mup_build_local_attr(struct attr *attrp, struct bgp *bgp,
				     const struct in6_addr *sid, uint16_t endpoint_behavior,
				     uint8_t loc_block_len, uint8_t loc_node_len, uint8_t func_len,
				     uint8_t arg_len, struct ecommunity *ecom,
				     const struct in6_addr *nexthop_override)
{
	struct bgp_attr_srv6_l3service *l3;
	struct attr attr = {};

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);

	/* MUP NLRI carries an IPv6 next-hop on the wire; an unset policy
	 * leaves it zero, matching L3VPN's TOVPN_NEXTHOP default posture.
	 */
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
	if (nexthop_override)
		attr.mp_nexthop_global = *nexthop_override;

	l3 = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE, sizeof(*l3));
	l3->sid = *sid;
	l3->endpoint_behavior = endpoint_behavior;
	l3->loc_block_len = loc_block_len;
	l3->loc_node_len = loc_node_len;
	l3->func_len = func_len;
	l3->arg_len = arg_len;
	bgp_attr_set_srv6_l3service(&attr, l3);
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));

	if (ecom) {
		bgp_attr_set_ecommunity(&attr, ecommunity_dup(ecom));
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));
	}

	*attrp = attr;
}

/* Inject or withdraw a locally-originated NLRI in the default-vrf
 * SAFI_MUP RIB.  Withdraw removes the BGP_ROUTE_STATIC path this
 * originator owns; the update path interns @attr and either refreshes
 * the existing self-path in place or adds a new one.  Lifted from the
 * L3VPN vpn_leak_from_vrf_update RIB mechanics; the dataplane local
 * SID is installed separately by bgp_mup_handle_sid_alloc.
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
		/* Refresh: swap the attribute in place and re-run selection. */
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

/* The default route is never an ISD candidate: ISD advertises N3
 * (gNB-side) reachability prefixes only, per draft-ietf-bess-mup-safi.
 */
static bool bgp_mup_origin_skip_prefix(const struct prefix *p)
{
	return !p || p->prefixlen == 0;
}

/* Resolve the export policy that makes (bgp_vrf, afi) an active ISD
 * originator: a non-default VRF instance with an RD configured and
 * `segment interwork` selected.  Returns NULL otherwise.  Mirrors
 * L3VPN's "is this (vrf, afi) leaking to vpn" predicate.
 */
static struct bgp_mup_export_policy *bgp_mup_origin_active(struct bgp *bgp_vrf, afi_t afi)
{
	struct bgp_mup_export_policy *ep;

	if (!bgp_vrf || bgp_vrf->vrf_id == VRF_DEFAULT)
		return NULL;
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;
	ep = bgp_mup_export_peek(bgp_vrf, afi);
	if (!ep)
		return NULL;
	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_RD_SET))
		return NULL;
	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK))
		return NULL;
	return ep;
}

/* Arguments threaded from a leaked unicast/MUP-RIB prefix into the
 * ISD emit path.  @ecom is borrowed (the policy's export RT list),
 * not owned.
 */
struct bgp_mup_origin_args {
	afi_t afi;
	struct prefix_rd prd;
	struct prefix isd_prefix; /* ISD only */
	struct ecommunity *ecom;
	/* DSD only (BGP_MUP_DSD_ROUTE).  dsd_endpoint is the originating
	 * PE address carried in the DSD NLRI; dsd_behavior is the
	 * SRV6_ENDPOINT_BEHAVIOR_END_DT* attr encoding; explicit_sid is
	 * set from `sid explicit` and bypasses the async SID manager.
	 */
	struct ipaddr dsd_endpoint;
	uint16_t dsd_behavior;
	bool has_explicit_sid;
	struct in6_addr explicit_sid;
};

/* Build one ISD NLRI for @args and submit it to the default-vrf MUP
 * RIB.  @from_bgp is the originating per-VRF instance whose
 * mup_export[afi] policy carries the shared End.M.GTP{4,6}.E SID; the
 * SID structure lengths come from @from_bgp's locator.  Control-plane
 * only: the matching local SID is installed by the SID-arrival hook.
 */
static int bgp_mup_emit_isd(struct bgp *to_bgp, struct bgp *from_bgp,
			    const struct bgp_mup_origin_args *args, const struct in6_addr *sid,
			    bool withdraw)
{
	struct bgp_mup_export_policy *ep;
	struct prefix_mup p = {};
	struct attr static_attr = {};
	struct attr *attr = NULL;
	struct srv6_locator *loc = NULL;
	uint16_t behavior = 0;
	uint8_t prefix_octets;
	int ret;

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
		struct in6_addr nh_storage = {};
		const struct in6_addr *nh = NULL;

		loc = bgp_srv6_locator_lookup(from_bgp, bgp_get_default());
		if (!loc)
			return -1;
		behavior = (args->afi == AFI_IP) ? SRV6_ENDPOINT_BEHAVIOR_END_M_GTP4_E
						 : SRV6_ENDPOINT_BEHAVIOR_END_M_GTP6_E;

		ep = bgp_mup_export_peek(from_bgp, args->afi);
		if (ep && CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_NEXTHOP_SET)) {
			if (ep->tovpn_nexthop.family == AF_INET6) {
				nh_storage = ep->tovpn_nexthop.u.prefix6;
				nh = &nh_storage;
			} else if (ep->tovpn_nexthop.family == AF_INET) {
				nh_storage.s6_addr[10] = 0xff;
				nh_storage.s6_addr[11] = 0xff;
				memcpy(&nh_storage.s6_addr[12], &ep->tovpn_nexthop.u.prefix4, 4);
				nh = &nh_storage;
			}
		}
		bgp_mup_build_local_attr(&static_attr, to_bgp, sid, behavior,
					 loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 args->ecom, nh);
		attr = &static_attr;
	}
	ret = bgp_mup_originate_common(to_bgp, args->afi, &p, attr, withdraw);
	if (attr)
		bgp_attr_flush(attr);

	/* Seed the default-vrf ISD discovery cache with the locally-
	 * originated entry so a T1ST received on this node (self-origin)
	 * resolves against it, mirroring the cache upsert the receive path
	 * performs for ISDs learned from a peer.
	 */
	if (withdraw)
		bgp_mup_isd_cache_remove(to_bgp, args->afi, &args->prd, &args->isd_prefix);
	else if (loc)
		bgp_mup_isd_cache_upsert(to_bgp, args->afi, &args->prd, &args->isd_prefix, sid,
					 loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 behavior);
	return ret;
}

/* Leak one locally-originated MUP-RIB path from @from_bgp into an ISD
 * advertisement.  Gated on an active interwork policy, an armed SID,
 * a non-default prefix, and the export-side route-map.  The route-map
 * is filter-only: the emitted ISD attribute is rebuilt from policy
 * (SID/RT/nexthop), so set-clauses cannot ride through to the wire.
 */
static void mup_leak_from_vrf_update(struct bgp *to_bgp, struct bgp *from_bgp,
				     struct bgp_path_info *path_vrf)
{
	struct bgp_mup_export_policy *ep;
	struct bgp_mup_origin_args args = {};
	const struct prefix *p;
	afi_t afi;

	if (!to_bgp || !from_bgp || !path_vrf || !path_vrf->net)
		return;
	p = bgp_dest_get_prefix(path_vrf->net);
	afi = family2afi(p->family);
	if (bgp_mup_origin_skip_prefix(p))
		return;

	ep = bgp_mup_origin_active(from_bgp, afi);
	if (!ep)
		return;

	/* Locally-originated MUP entries (BGP_ROUTE_STATIC from `network`,
	 * BGP_ROUTE_REDISTRIBUTE from `redistribute`) are valid ISD
	 * sources as soon as they land; selection runs asynchronously, so
	 * gating on BGP_PATH_VALID would race the SID-arrival replay.
	 * Skip only paths actively being removed or suppressed.
	 */
	if (CHECK_FLAG(path_vrf->flags, BGP_PATH_REMOVED))
		return;
	if (bgp_path_suppressed(path_vrf))
		return;

	if (!ep->tovpn_sid_ready)
		return; /* defer: SID-arrival hook replays via update_all */

	if (ep->rmap[BGP_MUP_POLICY_DIR_TOMUP]) {
		struct bgp_path_info info;
		struct bgp_path_info_extra path_extra;
		struct attr static_attr = {};
		struct peer *peer = path_vrf->peer ? path_vrf->peer : to_bgp->peer_self;
		route_map_result_t rmap_ret;

		bgp_attr_dup_into(&static_attr, path_vrf->attr);
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
	(void)bgp_mup_emit_isd(to_bgp, from_bgp, &args, ep->tovpn_sid, false);
}

/* Walk @from_bgp's locally-originated (afi, SAFI_MUP) entries and emit
 * an ISD advertisement for each.  Entries land here via `network` and
 * `redistribute` under the MUP AF; the sub_type check is the
 * locally-originated filter.  Called on SID arrival and on a
 * `segment interwork` postchange.
 */
static void mup_leak_from_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;

	if (!to_bgp || !from_bgp)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (!from_bgp->rib[afi][SAFI_MUP])
		return;

	for (bn = bgp_table_top(from_bgp->rib[afi][SAFI_MUP]); bn; bn = bgp_route_next(bn)) {
		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
			if (bpi->sub_type != BGP_ROUTE_STATIC &&
			    bpi->sub_type != BGP_ROUTE_REDISTRIBUTE)
				continue;
			mup_leak_from_vrf_update(to_bgp, from_bgp, bpi);
		}
	}
}

/* Withdraw the ISD advertisement that mup_leak_from_vrf_update would
 * have emitted for @path_vrf.  Unlike the update path this does not
 * gate on tovpn_sid_ready: the SID may already be gone (locator
 * delete), and the originate-common withdraw is a no-op when no
 * self-path exists.
 */
static void mup_leak_from_vrf_withdraw(struct bgp *to_bgp, struct bgp *from_bgp,
				       struct bgp_path_info *path_vrf)
{
	struct bgp_mup_export_policy *ep;
	struct bgp_mup_origin_args args = {};
	const struct prefix *p;
	afi_t afi;

	if (!to_bgp || !from_bgp || !path_vrf || !path_vrf->net)
		return;
	p = bgp_dest_get_prefix(path_vrf->net);
	afi = family2afi(p->family);
	if (bgp_mup_origin_skip_prefix(p))
		return;

	ep = bgp_mup_origin_active(from_bgp, afi);
	if (!ep)
		return;

	args.afi = afi;
	args.prd = ep->tovpn_rd;
	args.isd_prefix = *p;
	(void)bgp_mup_emit_isd(to_bgp, from_bgp, &args, ep->tovpn_sid, true);
}

/* Withdraw every ISD advertisement originated from @from_bgp's
 * (afi, SAFI_MUP) RIB.  Called on a `segment interwork` prechange and
 * on locator delete.
 */
static void mup_leak_from_vrf_withdraw_all(struct bgp *to_bgp, struct bgp *from_bgp, afi_t afi)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;

	if (!to_bgp || !from_bgp)
		return;
	if (from_bgp->vrf_id == VRF_DEFAULT)
		return;
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	if (!from_bgp->rib[afi][SAFI_MUP])
		return;

	for (bn = bgp_table_top(from_bgp->rib[afi][SAFI_MUP]); bn; bn = bgp_route_next(bn)) {
		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
			if (bpi->sub_type != BGP_ROUTE_STATIC &&
			    bpi->sub_type != BGP_ROUTE_REDISTRIBUTE)
				continue;
			mup_leak_from_vrf_withdraw(to_bgp, from_bgp, bpi);
		}
	}
}

/* Per-prefix origination hooks called from the generic redistribute /
 * static-route machinery in bgp_route.c when a locally-originated route
 * lands in (or leaves) a (vrf, afi, SAFI_MUP) RIB.  Mirror the
 * SAFI_UNICAST vpn_leak_from_vrf_update / _withdraw calls there: the
 * `segment interwork` postchange walk only catches routes already in the
 * RIB, so a redistributed route arriving asynchronously after the policy
 * is armed needs this per-prefix kick to originate its ISD.
 */
void bgp_mup_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	mup_leak_from_vrf_update(bgp_get_default(), from_bgp, pi);
}

void bgp_mup_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	mup_leak_from_vrf_withdraw(bgp_get_default(), from_bgp, pi);
}

/* Drop every ISD advertisement before an origination-affecting config
 * change so stale NLRIs do not linger.  Sibling of L3VPN's
 * vpn_leak_prechange.
 */
static void mup_leak_prechange(afi_t afi, struct bgp *bgp)
{
	struct bgp *to_bgp = bgp_get_default();

	if (!to_bgp || !bgp)
		return;
	mup_leak_from_vrf_withdraw_all(to_bgp, bgp, afi);
}

/* Re-arm the shared SID and re-emit every ISD advertisement after an
 * origination-affecting config change.  Sibling of L3VPN's
 * vpn_leak_postchange.  When the SID is not yet ready the emit pass is
 * a no-op and the SID-arrival hook replays it later.
 */
static void mup_leak_postchange(afi_t afi, struct bgp *bgp)
{
	struct bgp *to_bgp = bgp_get_default();

	if (!to_bgp || !bgp)
		return;
	bgp_mup_request_isd_sid(bgp, afi);
	mup_leak_from_vrf_update_all(to_bgp, bgp, afi);
}

/* ------------------------------------------------------------------ *
 * DSD scalar origination (`segment direct`).
 *
 * Unlike ISD (which leaks per-prefix from the per-vrf unicast RIB),
 * DSD originates a single NLRI per (vrf, afi) describing the local
 * End.DT* decapsulation endpoint.  When the SID is auto-allocated the
 * operator's args are parked on bgp->mup_pending until zebra answers;
 * the configured line is mirrored into bgp->mup_origins so it survives
 * SID-alloc cycles and replays on locator (re)arrival.
 * ------------------------------------------------------------------
 */

/* When the operator types `segment direct ...` without `sid explicit`,
 * we ask zebra's SRv6 SID manager for a function and complete the
 * originate when the SID arrives via ZAPI_SRV6_SID_ALLOCATED.  Match
 * SID-alloc replies by ctx (FIFO within a (behavior, afi, safi) class) - zebra
 * processes get-sid requests serially per locator.
 */
struct bgp_mup_pending {
	struct bgp_mup_pending_list_item item;
	struct bgp_mup_origin_args args; /* args.ecom is dup'd & owned */
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
	struct bgp_mup_pending *p;

	if (!bgp->mup_pending)
		return NULL;
	frr_each_safe (bgp_mup_pending_list, bgp->mup_pending, p) {
		if (p->ctx.behavior == ctx->behavior && p->ctx.vrf_id == ctx->vrf_id &&
		    p->ctx.afi == ctx->afi && p->ctx.safi == ctx->safi) {
			bgp_mup_pending_list_del(bgp->mup_pending, p);
			return p;
		}
	}
	return NULL;
}

/* Pop a pending entry matching the operator's withdraw NLRI key, used
 * to cancel a not-yet-allocated SID request when `no segment direct`
 * arrives before zebra answered.  NULL means the SID alloc already
 * completed and the route is in the RIB (regular withdraw applies).
 */
static struct bgp_mup_pending *
bgp_mup_pending_pop_for_withdraw(struct bgp *bgp, const struct bgp_mup_origin_args *args)
{
	struct bgp_mup_pending *p;

	if (!bgp->mup_pending)
		return NULL;
	frr_each_safe (bgp_mup_pending_list, bgp->mup_pending, p) {
		if (p->args.afi != args->afi)
			continue;
		if (memcmp(p->args.prd.val, args->prd.val, sizeof(p->args.prd.val)) != 0)
			continue;
		if (!ipaddr_is_same(&p->args.dsd_endpoint, &args->dsd_endpoint))
			continue;
		bgp_mup_pending_list_del(bgp->mup_pending, p);
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

/* Persistent record of an operator-configured `segment direct` line.
 * Survives SID-alloc cycles so the running config can re-emit the
 * originate after a locator (re)arrival.  rt_str / mup_str preserve the
 * operator's exact text for verbatim `show running-config` roundtrip.
 */
struct bgp_mup_origin {
	struct bgp_mup_origin_list_item item;
	afi_t afi;
	struct prefix_rd prd;
	struct ipaddr dsd_endpoint;
	uint16_t dsd_behavior;
	bool has_explicit_sid;
	struct in6_addr explicit_sid;
	char *rt_str;
	struct ecommunity *rt_ecom;
	char *mup_str;
	uint64_t segment_id; /* pre-parsed mup_as<<32 | mup_val */
	bool has_segment_id;
	/* In-memory marker: SID assigned and local install issued.  Reset
	 * on bgpd restart so the locator-arrival replay re-runs `segment
	 * direct` lines that landed before chunks were ready.  The (sid,
	 * act) fingerprint suppresses redundant netlink installs on replay.
	 */
	bool sid_ready;
	struct in6_addr last_installed_sid;
	enum seg6local_action_t last_installed_act;
};
DECLARE_LIST(bgp_mup_origin_list, struct bgp_mup_origin, item);

static struct bgp_mup_origin_list_head *bgp_mup_get_origin_list(struct bgp *bgp)
{
	if (!bgp->mup_origins) {
		bgp->mup_origins = XCALLOC(MTYPE_BGP_MUP_LIST, sizeof(*bgp->mup_origins));
		bgp_mup_origin_list_init(bgp->mup_origins);
	}
	return bgp->mup_origins;
}

static bool bgp_mup_origin_match(const struct bgp_mup_origin *o, afi_t afi,
				 const struct prefix_rd *prd, const struct ipaddr *dsd_endpoint)
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

	if (!bgp->mup_origins)
		return NULL;
	frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
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

static bool bgp_mup_origin_segment_id(const struct bgp_mup_origin *o, uint64_t *out)
{
	if (!o->has_segment_id)
		return false;
	*out = o->segment_id;
	return true;
}

/* Record the (sid, action) just pushed to zebra so a later emit can
 * skip the redundant zclient_send_localsid().  No-op if the origin is
 * not (yet) persisted - the synchronous explicit-SID path emits before
 * persist, which is fine: the very first install is never deduped.
 */
static void bgp_mup_origin_mark_installed(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
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

static bool bgp_mup_origin_localsid_cached(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
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

static void bgp_mup_origin_clear_installed(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
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
 * same NLRI key.  Carries over the install fingerprint so a synchronous
 * explicit-SID emit (run before persist) survives the replacement.
 */
static void bgp_mup_origin_persist(struct bgp *bgp, const struct bgp_mup_origin_args *args,
				   const char *rt_str, const char *mup_str)
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
		sid_ready = o->sid_ready;
		last_sid = o->last_installed_sid;
		last_act = o->last_installed_act;
		bgp_mup_origin_list_del(bgp->mup_origins, o);
		bgp_mup_origin_free(o);
	}
	o = XCALLOC(MTYPE_BGP_MUP_ORIGIN, sizeof(*o));
	o->afi = args->afi;
	o->prd = args->prd;
	o->dsd_endpoint = args->dsd_endpoint;
	o->dsd_behavior = args->dsd_behavior;
	o->has_explicit_sid = args->has_explicit_sid;
	o->explicit_sid = args->explicit_sid;
	o->rt_str = XSTRDUP(MTYPE_BGP_MUP_STR, rt_str);
	o->rt_ecom = rt_ecom;
	o->sid_ready = sid_ready;
	o->last_installed_sid = last_sid;
	o->last_installed_act = last_act;
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

static void bgp_mup_origin_forget(struct bgp *bgp, afi_t afi, const struct prefix_rd *prd,
				  const struct ipaddr *dsd_endpoint)
{
	struct bgp_mup_origin *o = bgp_mup_origin_find(bgp, afi, prd, dsd_endpoint);
	uint64_t segment_id;

	if (!o)
		return;
	if (bgp_mup_origin_segment_id(o, &segment_id))
		bgp_mup_self_dsd_index_del(segment_id);
	bgp_mup_origin_list_del(bgp->mup_origins, o);
	bgp_mup_origin_free(o);
}

/* Drain and free the per-bgp DSD pending + origin lists on instance
 * teardown.  Called from bgp_mup_caches_free().
 */
static void bgp_mup_origins_pending_free(struct bgp *bgp)
{
	struct bgp_mup_pending *p;
	struct bgp_mup_origin *o;

	if (bgp->mup_pending) {
		while ((p = bgp_mup_pending_list_pop(bgp->mup_pending)))
			bgp_mup_pending_free(p);
		bgp_mup_pending_list_fini(bgp->mup_pending);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_pending);
	}
	if (bgp->mup_origins) {
		while ((o = bgp_mup_origin_list_pop(bgp->mup_origins))) {
			uint64_t segment_id;

			if (bgp_mup_origin_segment_id(o, &segment_id))
				bgp_mup_self_dsd_index_del(segment_id);
			bgp_mup_origin_free(o);
		}
		bgp_mup_origin_list_fini(bgp->mup_origins);
		XFREE(MTYPE_BGP_MUP_LIST, bgp->mup_origins);
	}
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
		bgp_mup_dsd_cache_upsert(cache_bgp, args->afi, &args->prd, &args->dsd_endpoint, sid,
					 loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 args->dsd_behavior, has_seg, seg_id);
	} else {
		bgp_mup_dsd_cache_remove(cache_bgp, args->afi, &args->prd, &args->dsd_endpoint);
	}
}

/* Synchronous DSD originate: build the prefix_mup + attr from a known
 * SID, submit to the default-vrf MUP RIB, and install the local End.DT*
 * seg6local action.  Mirrors bgp_mplsvpn.c::vpn_leak_zebra_vrf_sid_
 * update_per_af() - DSD is a per-VRF VPN segment, so the SID terminates
 * by decapsulating SRv6 and looking up the inner packet in bgp's vrf
 * table.
 */
static int bgp_mup_emit_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
			    const struct in6_addr *sid, bool withdraw)
{
	struct prefix_mup p = {};
	struct attr static_attr = {};
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
		struct in6_addr nh_storage = {};
		const struct in6_addr *nh = NULL;

		if (ep && CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_NEXTHOP_SET)) {
			if (ep->tovpn_nexthop.family == AF_INET6) {
				nh_storage = ep->tovpn_nexthop.u.prefix6;
				nh = &nh_storage;
			} else if (ep->tovpn_nexthop.family == AF_INET) {
				nh_storage.s6_addr[10] = 0xff;
				nh_storage.s6_addr[11] = 0xff;
				memcpy(&nh_storage.s6_addr[12], &ep->tovpn_nexthop.u.prefix4, 4);
				nh = &nh_storage;
			}
		}
		bgp_mup_build_local_attr(&static_attr, bgp, sid, args->dsd_behavior,
					 loc->block_bits_length, loc->node_bits_length,
					 loc->function_bits_length, loc->argument_bits_length,
					 args->ecom, nh);
		attr = &static_attr;
	}
	/* Read the MUP-EC segment id off @attr before the origination
	 * interns it: interning takes over the locally-owned attr extra.
	 */
	bgp_mup_emit_dsd_cache_update(bgp, args, sid, loc, attr, withdraw);
	ret = bgp_mup_originate_common(bgp, args->afi, &p, attr, withdraw);

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
			/* Install at /loc_func, NOT /128: H.M.GTP4.D at the
			 * peer MUP-GW rewrites the SRv6 destination to encode
			 * the v4 source + Args.Mob.Session, so the decap-side
			 * End.DT* action must match the locator+function
			 * prefix range.  oif = per-vrf loopback so the post-
			 * action IP lookup happens in bgp's vrf table - the
			 * same hint L3VPN's tovpn_sid install passes.
			 */
			uint16_t plen = loc->block_bits_length + loc->node_bits_length +
					loc->function_bits_length;
			struct interface *vrf_lo = if_get_vrf_loopback(bgp->vrf_id);
			ifindex_t oif = vrf_lo ? vrf_lo->ifindex : 0;

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
		bgp_attr_flush(attr);
	return ret;
}

/* Originate (or withdraw) the DSD for @args. */
static int bgp_mup_originate_dsd(struct bgp *bgp, const struct bgp_mup_origin_args *args,
				bool withdraw)
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
	 * haven't arrived; the persisted origin replays via
	 * bgp_mup_replay_origins() from the locator-arrival hook.
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
		ctx.afi = args->afi;
		ctx.safi = SAFI_MUP;

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
	p->ctx.afi = args->afi;
	p->ctx.safi = SAFI_MUP;
	bgp_mup_pending_list_add_tail(bgp_mup_get_pending_list(bgp), p);

	{
		struct in6_addr sid = {};

		bgp_zebra_request_srv6_sid(&p->ctx, &sid, bgp->srv6_locator_name, NULL);
	}
	return 0;
}

/* SID-manager async completion hook for DSD (called from the front-of-
 * file bgp_mup_handle_sid_alloc).  Returns true when a parked `segment
 * direct` request matched @ctx and was dispatched into emit_dsd().
 */
static bool bgp_mup_dispatch_pending_sid(struct bgp *bgp, const struct srv6_sid_ctx *ctx,
					 const struct in6_addr *sid_value)
{
	struct bgp_mup_pending *p = bgp_mup_pending_pop(bgp, ctx);

	if (!p)
		return false;
	(void)bgp_mup_emit_dsd(bgp, &p->args, sid_value, false);
	bgp_mup_pending_free(p);
	return true;
}

/* Build the originate args from the per-(vrf, afi) export policy's
 * `segment direct` sub-block.  The DSD address defaults to the
 * speaker's IPv4 router-id; RD / RT / SID come from the shared
 * `rd` / `rt export` / `sid` knobs on the enclosing MUP-AF policy.
 */
static bool mup_dsd_policy_ready(const struct bgp_mup_export_policy *ep)
{
	if (!ep)
		return false;
	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT))
		return false;
	if (!CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_RD_SET))
		return false;
	if (!ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP])
		return false;
	if (!ep->dsd_mup_str || !ep->dsd_behavior)
		return false;
	return true;
}

static void mup_dsd_args_from_policy(struct bgp *bgp, afi_t afi,
				     const struct bgp_mup_export_policy *ep,
				     struct bgp_mup_origin_args *args, struct ecommunity **out_rt,
				     struct ecommunity **out_mup_ec, struct ecommunity **out_ecom)
{
	struct ecommunity *rt = ecommunity_dup(ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP]);
	struct ecommunity *mup_ec = bgp_mup_build_mup_ec(ep->dsd_mup_str);

	args->afi = afi;
	args->prd = ep->tovpn_rd;
	args->dsd_behavior = ep->dsd_behavior;

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET)) {
		args->dsd_endpoint = ep->dsd_address;
	} else {
		/* Default to the IPv4 router-id; the DSD NLRI Address AFI is
		 * independent from the inner-PDU AFI per
		 * draft-ietf-bess-mup-safi.
		 */
		args->dsd_endpoint.ipa_type = IPADDR_V4;
		args->dsd_endpoint.ipaddr_v4 = bgp->router_id;
	}

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT) && ep->tovpn_sid_explicit) {
		args->has_explicit_sid = true;
		args->explicit_sid = *ep->tovpn_sid_explicit;
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
	    !CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET)) {
		zlog_warn("BGP-MUP: vrf %s has no router-id and no `segment direct` address override; deferring DSD origination",
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

/* Re-emit one persisted `segment direct` origin from its saved
 * rt_ecom / mup_str so the persistent record stays the single source of
 * truth.  Called after a locator (re)arrival for origins not yet bound
 * to a SID.
 */
static void bgp_mup_replay_origin(struct bgp *bgp, struct bgp_mup_origin *o)
{
	struct bgp_mup_origin_args args = {};
	struct ecommunity *rt, *mup_ec, *ecom;

	if (!o->rt_ecom)
		return;
	mup_ec = bgp_mup_build_mup_ec(o->mup_str);
	if (!mup_ec)
		return;
	rt = ecommunity_dup(o->rt_ecom);
	ecom = ecommunity_merge(ecommunity_dup(rt), mup_ec);

	args.afi = o->afi;
	args.prd = o->prd;
	args.dsd_endpoint = o->dsd_endpoint;
	args.dsd_behavior = o->dsd_behavior;
	args.has_explicit_sid = o->has_explicit_sid;
	args.explicit_sid = o->explicit_sid;
	args.ecom = ecom;

	(void)bgp_mup_originate_dsd(bgp, &args, false);

	ecommunity_free(&rt);
	ecommunity_free(&mup_ec);
	ecommunity_free(&ecom);
}

/* Locator-arrival hook helper: replay every persisted DSD origin on
 * @bgp that has no SID bound yet.  Wired into bgp_mup_locator_arrived().
 */
static void bgp_mup_replay_origins(struct bgp *bgp)
{
	struct bgp_mup_origin *o;

	if (!bgp->mup_origins)
		return;
	frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
		if (o->sid_ready)
			continue;
		bgp_mup_replay_origin(bgp, o);
	}
}

/* Locator-delete hook helper: withdraw and uninstall every persisted
 * DSD origin on @bgp whose installed SID falls inside the deleted
 * locator's prefix.  Wired into bgp_mup_locator_delete_purge().
 */
static void bgp_mup_origins_locator_purge(struct bgp *bgp, const struct srv6_locator *locator)
{
	struct bgp_mup_origin *o;

	if (!bgp->mup_origins)
		return;
	frr_each (bgp_mup_origin_list, bgp->mup_origins, o) {
		struct prefix sid_p = { .family = AF_INET6, .prefixlen = IPV6_MAX_BITLEN };
		struct prefix_mup p = {};
		uint8_t addr_octets;
		uint16_t plen;
		struct interface *vrf_lo;
		ifindex_t oif;
		enum seg6local_action_t act;

		if (!o->sid_ready)
			continue;
		sid_p.u.prefix6 = o->last_installed_sid;
		if (!prefix_match((const struct prefix *)&locator->prefix, &sid_p))
			continue;

		/* Withdraw the originated DSD NLRI so peers see the withdraw
		 * before the SID disappears.
		 */
		addr_octets = (o->afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		bgp_mup_prefix_init(&p, BGP_MUP_DSD_ROUTE, 8 + addr_octets);
		memcpy(p.prefix.rd, o->prd.val, 8);
		p.prefix.dsd_route.ip = o->dsd_endpoint;
		(void)bgp_mup_originate_common(bgp, o->afi, &p, NULL, true);

		/* Tear down the End.DT* localsid whose locator is gone. */
		act = o->last_installed_act;
		if (act != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			struct seg6local_context lctx = {};
			struct vrf *vrf = vrf_lookup_by_id(bgp->vrf_id);

			vrf_lo = if_get_vrf_loopback(bgp->vrf_id);
			oif = vrf_lo ? vrf_lo->ifindex : 0;
			plen = locator->block_bits_length + locator->node_bits_length +
			       locator->function_bits_length;
			lctx.block_len = locator->block_bits_length;
			lctx.node_len = locator->node_bits_length;
			lctx.function_len = locator->function_bits_length;
			lctx.argument_len = locator->argument_bits_length;
			lctx.table = vrf ? vrf->data.l.table_id : RT_TABLE_MAIN;
			zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE,
					      &o->last_installed_sid, plen, oif, act, &lctx);
		}

		/* Auto-allocated DSDs: release the SID so a recreate with a
		 * different prefix doesn't leak.  Explicit SIDs are not
		 * manager-allocated; the arrival replay re-installs them.
		 */
		if (!o->has_explicit_sid) {
			struct srv6_sid_ctx ctx = {};

			ctx.behavior = bgp_mup_dsd_zebra_action(o->dsd_behavior);
			ctx.vrf_id = bgp->vrf_id;
			ctx.afi = o->afi;
			ctx.safi = SAFI_MUP;
			bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_locator_name);
		}

		bgp_mup_origin_clear_installed(bgp, o->afi, &o->prd, &o->dsd_endpoint);
	}
}

int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	int ret;
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	bool ok;
	int psize = 0;
	uint8_t arch_type;
	uint16_t route_type;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	/* Anchor the parsed parent attr for the duration of the walk.  Without
	 * it bgp_attr_owns_extra() treats the parent as transient, so the first
	 * intern of it - bgp_adj_in_set() under `soft-reconfiguration inbound` -
	 * takes attr->extra over instead of duplicating it.  The parent keeps
	 * pointing at that extra and frees it when the UPDATE is done, leaving
	 * the interned attr with a dangling extra that crashes the next
	 * attrhash_key_make(), e.g. on the withdraw of the same NLRI.  Mirrors
	 * bgp_nlri_parse_evpn() / bgp_nlri_parse_vpn().
	 */
	if (attr) {
		memset(&attr->attr_intern_reuse, 0, sizeof(attr->attr_intern_reuse));
		attr->attr_intern_reuse.parsed_attr = attr;
	}

	for (; pnt < lim; pnt += psize) {
		if (addpath_capable) {
			if (pnt + BGP_ADDPATH_ID_LEN > lim) {
				ret = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
				goto done;
			}
			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Architecture Type + Route Type + Length. */
		if (pnt + BGP_MUP_HDR_BYTES > lim) {
			ret = BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE;
			goto done;
		}

		arch_type = pnt[0];
		memcpy(&route_type, pnt + BGP_MUP_ARCH_TYPE_BYTES, BGP_MUP_ROUTE_TYPE_BYTES);
		route_type = ntohs(route_type);
		psize = pnt[BGP_MUP_ARCH_TYPE_BYTES + BGP_MUP_ROUTE_TYPE_BYTES];
		pnt += BGP_MUP_HDR_BYTES;

		if (pnt + psize > lim) {
			ret = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			goto done;
		}

		/* draft 3.1 only defines 3gpp-5g; skip other architectures. */
		if (arch_type != BGP_MUP_ARCH_3GPP_5G)
			continue;

		switch (route_type) {
		case BGP_MUP_ISD_ROUTE:
			ok = bgp_mup_process_isd_route(peer, afi, safi, withdraw ? NULL : attr,
						       pnt, psize, addpath_id);
			break;

		case BGP_MUP_DSD_ROUTE:
			ok = bgp_mup_process_dsd_route(peer, afi, safi, withdraw ? NULL : attr,
						       pnt, psize, addpath_id);
			break;

		case BGP_MUP_T1ST_ROUTE:
			ok = bgp_mup_process_t1st_route(peer, afi, safi, withdraw ? NULL : attr,
							pnt, psize, addpath_id);
			break;

		case BGP_MUP_T2ST_ROUTE:
			ok = bgp_mup_process_t2st_route(peer, afi, safi, withdraw ? NULL : attr,
							pnt, psize, addpath_id);
			break;

		default:
			/* Unknown route type: silently ignore (draft 3.1). */
			ok = true;
			break;
		}

		/* draft 3.1.x: a malformed NLRI is treat-as-withdraw
		 * (RFC 7606) -- skip it and keep parsing the UPDATE.
		 */
		if (!ok)
			continue;
	}

	ret = (pnt == lim) ? BGP_NLRI_PARSE_OK : BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

done:
	if (attr)
		memset(&attr->attr_intern_reuse, 0, sizeof(attr->attr_intern_reuse));

	return ret;
}

#include "bgpd/bgp_vty.h"
#include "lib/command.h"

#include "bgpd/bgp_mup_clippy.c"

static afi_t bgp_mup_export_node2afi(struct vty *vty)
{
	if (vty->node == BGP_MUPV4_NODE || vty->node == BGP_MUPV4_SEGMENT_DIRECT_NODE)
		return AFI_IP;
	if (vty->node == BGP_MUPV6_NODE || vty->node == BGP_MUPV6_SEGMENT_DIRECT_NODE)
		return AFI_IP6;
	return AFI_MAX;
}

static int bgp_mup_export_check_ctx(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	if (afi == AFI_MAX) {
		vty_out(vty,
			"%% BGP-MUP origination knobs only valid under address-family ipv4|ipv6 mup\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% BGP-MUP origination knobs must be configured under a non-default vrf bgp instance (`router bgp ASN vrf NAME`); the default-vrf instance only carries the BGP-MUP session\n");
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
 * of BGP_CONFIG_MUP_TO_VRF_IMPORT on the first `rt import` line:
 * existing seg6-mobile configs with `rt import` but no explicit
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

/* `rt <import|export|both> RTLIST` under `address-family ipv[46] mup`
 * - BGP-MUP analogue of L3VPN's `rt vpn <import|export|both>`.  Stored
 * on the per-vrf bgp instance and consulted by
 * bgp_mup_match_install_vrf and the ISD/DSD cache upsert paths via the
 * FROMMUP slot; the TOMUP slot is the export RT stamped on originated
 * ISD/DSD NLRIs.
 */
DEFPY (af_rt_mup,
       af_rt_mup_cmd,
       "[no] rt <import|export|both>$direction_str RTLIST...",
       NO_STR
       "Specify route target list\n"
       "For received BGP-MUP routes matched for install into this vrf: match any\n"
       "For locally-originated BGP-MUP routes: set\n"
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
       "no rt <import|export|both>$direction_str",
       NO_STR
       "Specify route target list\n"
       "For received BGP-MUP routes matched for install into this vrf\n"
       "For locally-originated BGP-MUP routes\n"
       "both import and export\n")

/* `rd ASN:NN|IP:NN` under `address-family ipv[46] mup` - BGP-MUP
 * analogue of L3VPN's `rd vpn export`.  Sets the RD that origination
 * stamps on ISD/DSD NLRIs originated from this (vrf, afi).
 */
DEFPY (af_rd_mup,
       af_rd_mup_cmd,
       "[no] rd ASN:NN_OR_IP-ADDRESS:NN$rd_str",
       NO_STR
       "Specify route distinguisher\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	struct prefix_rd prd;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!str2prefix_rd(rd_str, &prd)) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	ep = bgp_mup_export_get(bgp, afi);
	XFREE(MTYPE_BGP_NAME, ep->tovpn_rd_pretty);
	if (yes) {
		ep->tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME, rd_str);
		ep->tovpn_rd = prd;
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_RD_SET);
	} else {
		memset(&ep->tovpn_rd, 0, sizeof(ep->tovpn_rd));
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_RD_SET);
	}
	return CMD_SUCCESS;
}

ALIAS (af_rd_mup,
       af_no_rd_mup_cmd,
       "no rd",
       NO_STR
       "Specify route distinguisher\n")

/* `sid <auto|explicit X:X::X:X> [locator NAME]` under
 * `address-family ipv[46] mup` - BGP-MUP analogue of L3VPN's
 * `sid vpn export`.  Selects the SRv6 SID used as the End.M.GTP4.E /
 * End.M.GTP6.E local SID for ISD origination.  The optional
 * `locator NAME` overrides the bgp-instance default locator for this
 * (vrf, afi).
 */
DEFPY (af_sid_mup,
       af_sid_mup_cmd,
       "[no] sid <auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value> [locator WORD$locator_name]",
       NO_STR
       "SID value for BGP-MUP\n"
       "Automatically assign a SID from the bgp-instance SRv6 locator\n"
       "Explicitly assign a SID value\n"
       "SID value\n"
       "Allocate the SID from a named SRv6 locator instead of the bgp default\n"
       "Locator name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	ep = bgp_mup_export_get(bgp, afi);

	if (!yes) {
		bgp_mup_release_isd_sid(bgp, afi);
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO);
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT);
		XFREE(MTYPE_BGP_SRV6_SID, ep->tovpn_sid_explicit);
		XFREE(MTYPE_BGP_NAME, ep->locator_name);
		return CMD_SUCCESS;
	}

	if (sid_auto && sid_explicit) {
		vty_out(vty, "%% auto and explicit are mutually exclusive\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (sid_auto) {
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO);
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT);
		XFREE(MTYPE_BGP_SRV6_SID, ep->tovpn_sid_explicit);
	} else {
		struct in6_addr *sid;

		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT);
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO);
		if (!ep->tovpn_sid_explicit)
			ep->tovpn_sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID,
							 sizeof(struct in6_addr));
		sid = ep->tovpn_sid_explicit;
		*sid = sid_value;
	}

	XFREE(MTYPE_BGP_NAME, ep->locator_name);
	if (locator_name)
		ep->locator_name = XSTRDUP(MTYPE_BGP_NAME, locator_name);
	return CMD_SUCCESS;
}

ALIAS (af_sid_mup,
       af_no_sid_mup_cmd,
       "no sid",
       NO_STR
       "SID value for BGP-MUP\n")

/* `source-upf-prefix-len M` under `address-family ipv[46] mup` - how
 * many bits of the Source UPF Prefix (RFC 9433 Section 6.6 Figure 10)
 * precede the IPv4 Source Address in the outer IPv6 source of T1ST
 * installs.  The prefix itself is this speaker's SRv6 locator; only
 * the length has to be agreed with the gateway that reads the IPv4
 * back out.
 */
DEFPY (af_source_upf_prefix_len_mup,
       af_source_upf_prefix_len_mup_cmd,
       "[no] source-upf-prefix-len [(1-96)$plen]",
       NO_STR
       "Bits of the Source UPF Prefix preceding the IPv4 Source Address\n"
       "Prefix length; must match the gateway extraction offset\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	struct listnode *node;
	struct bgp *b;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes && !plen_str) {
		vty_out(vty, "%% Prefix length required\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		ep->source_upf_prefix_len = plen;
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SOURCE_UPF_PREFIX_LEN_SET);
	} else {
		ep->source_upf_prefix_len = 0;
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SOURCE_UPF_PREFIX_LEN_SET);
	}

	/* The End.M.GTP4.E endpoint this address family originates reads the
	 * IPv4 source back at this offset, and T1ST already installed into
	 * this vrf carry the old one.
	 */
	bgp_mup_install_isd_localsid(bgp, afi, false);
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, b))
		bgp_mup_schedule_reannounce_st_routes(b, afi);
	return CMD_SUCCESS;
}

/* `nexthop <A.B.C.D|X:X::X:X>` under `address-family ipv[46] mup` -
 * BGP-MUP analogue of L3VPN's `nexthop vpn export`.  Sets the next-hop
 * that origination stamps on the MP_REACH attribute for ISD/DSD
 * originated from this (vrf, afi).
 */
DEFPY (af_nexthop_mup,
       af_nexthop_mup_cmd,
       "[no] nexthop [<A.B.C.D|X:X::X:X>$nh_su]",
       NO_STR
       "Specify next-hop for BGP-MUP advertised prefixes\n"
       "IPv4 next-hop\n"
       "IPv6 next-hop\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	struct prefix p = {};
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!nh_su) {
			vty_out(vty, "%% Next-hop required\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (!sockunion2hostprefix(nh_su, &p))
			return CMD_WARNING_CONFIG_FAILED;
	}

	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		ep->tovpn_nexthop = p;
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_NEXTHOP_SET);
	} else {
		memset(&ep->tovpn_nexthop, 0, sizeof(ep->tovpn_nexthop));
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_NEXTHOP_SET);
	}
	return CMD_SUCCESS;
}

/* `segment interwork` under `address-family ipv[46] mup` toggles
 * Interwork Segment Discovery origination for this (vrf, afi): every
 * locally-originated MUP-RIB prefix (`network` / `redistribute`) is
 * advertised as an ISD route carrying the shared End.M.GTP*.E SID.
 * Per draft-ietf-bess-mup-safi origination runs on a non-default vrf
 * instance; the prechange/postchange bracket withdraws stale ISDs and
 * re-emits under the new policy, matching L3VPN's vpn_leak bracket.
 */
DEFPY (af_mup_segment_interwork,
       af_mup_segment_interwork_cmd,
       "[no] segment interwork",
       NO_STR
       "Segment routing origination mode for this MUP address-family\n"
       "Enable Interwork Segment Discovery (per-prefix ISD) origination\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_mup_export_policy *ep;
	afi_t afi;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);

	if (vty->node == BGP_MUPV4_NODE)
		afi = AFI_IP;
	else if (vty->node == BGP_MUPV6_NODE)
		afi = AFI_IP6;
	else {
		vty_out(vty,
			"%% segment interwork only valid under address-family ipv4|ipv6 mup\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->vrf_id == VRF_DEFAULT) {
		vty_out(vty,
			"%% segment interwork must be configured under a non-default vrf bgp instance; the default-vrf instance only carries the BGP-MUP session\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	mup_leak_prechange(afi, bgp);
	mup_dsd_prechange(afi, bgp);
	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK);
		/* ISD and DSD are mutually exclusive per (vrf, afi): turning
		 * on interwork clears any `segment direct` sub-block so the
		 * policy emits at most one of ISD or DSD.
		 */
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT |
					      BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET);
		memset(&ep->dsd_address, 0, sizeof(ep->dsd_address));
	} else {
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK);
		bgp_mup_release_isd_sid(bgp, afi);
	}
	mup_dsd_postchange(afi, bgp);
	mup_leak_postchange(afi, bgp);
	return CMD_SUCCESS;
}

/* `segment direct` enters the DSD sub-block (BGP_IPV[46]_MUP_SEGMENT_
 * DIRECT_NODE) where the address / behavior / segment-id knobs live.
 * Mutually exclusive with `segment interwork`.
 */
DEFPY_NOSH (af_mup_segment_direct,
	    af_mup_segment_direct_cmd,
	    "segment direct",
	    "Segment routing origination mode for this MUP address-family\n"
	    "Enable Direct Segment Discovery (single-NLRI per vrf,afi) origination\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	mup_leak_prechange(afi, bgp);
	mup_dsd_prechange(afi, bgp);
	ep = bgp_mup_export_get(bgp, afi);
	SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT);
	UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK);
	bgp_mup_release_isd_sid(bgp, afi);
	mup_dsd_postchange(afi, bgp);
	mup_leak_postchange(afi, bgp);

	vty->node = (afi == AFI_IP) ? BGP_MUPV4_SEGMENT_DIRECT_NODE
				    : BGP_MUPV6_SEGMENT_DIRECT_NODE;
	return CMD_SUCCESS;
}

DEFPY (af_no_mup_segment_direct,
       af_no_mup_segment_direct_cmd,
       "no segment direct",
       NO_STR
       "Segment routing origination mode for this MUP address-family\n"
       "Direct Segment Discovery sub-block\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	mup_dsd_prechange(afi, bgp);
	ep = bgp_mup_export_get(bgp, afi);
	UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT |
				      BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET);
	memset(&ep->dsd_address, 0, sizeof(ep->dsd_address));
	ep->dsd_behavior = 0;
	XFREE(MTYPE_BGP_NAME, ep->dsd_mup_str);
	ep->dsd_mup_as = 0;
	ep->dsd_mup_val = 0;
	mup_dsd_postchange(afi, bgp);
	return CMD_SUCCESS;
}

/* Sub-node knobs under BGP_IPV[46]_MUP_SEGMENT_DIRECT_NODE. */

DEFPY (af_mup_segment_direct_address,
       af_mup_segment_direct_address_cmd,
       "[no] address A.B.C.D$address",
       NO_STR
       "DSD originating-speaker address (default = bgp router-id)\n"
       "IPv4 address overriding the bgp router-id\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	mup_dsd_prechange(afi, bgp);
	ep = bgp_mup_export_get(bgp, afi);
	if (yes) {
		ep->dsd_address.ipa_type = IPADDR_V4;
		ep->dsd_address.ipaddr_v4 = address;
		SET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET);
	} else {
		UNSET_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET);
		memset(&ep->dsd_address, 0, sizeof(ep->dsd_address));
	}
	mup_dsd_postchange(afi, bgp);
	return CMD_SUCCESS;
}

DEFPY (af_mup_segment_direct_behavior,
       af_mup_segment_direct_behavior_cmd,
       "[no] behavior <dt4$dt4|dt6$dt6|dt46$dt46>",
       NO_STR
       "SRv6 endpoint behavior for the DSD prefix-SID\n"
       "End.DT4 - decap and lookup in the IPv4 table\n"
       "End.DT6 - decap and lookup in the IPv6 table\n"
       "End.DT46 - decap and lookup in either the IPv4 or IPv6 table\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

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

ALIAS (af_mup_segment_direct_behavior,
       af_no_mup_segment_direct_behavior_cmd,
       "no behavior",
       NO_STR
       "SRv6 endpoint behavior for the DSD prefix-SID\n")

DEFPY (af_mup_segment_direct_segment_id,
       af_mup_segment_direct_segment_id_cmd,
       "[no] segment-id ASN:NN$ec_str",
       NO_STR
       "BGP MUP Extended Community, Direct-Type Segment Identifier sub-type\n"
       "MUP segment identifier (ASN:NN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_mup_export_node2afi(vty);
	struct bgp_mup_export_policy *ep;
	int idx = 0;
	bool yes = !argv_find(argv, argc, "no", &idx);
	int ret;

	ret = bgp_mup_export_check_ctx(vty, bgp, afi);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		uint16_t mup_as = 0;
		uint32_t mup_val = 0;

		if (!bgp_mup_parse_seg_id_str(ec_str, &mup_as, &mup_val)) {
			vty_out(vty, "%% Malformed MUP segment identifier \"%s\"\n", ec_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		mup_dsd_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		XFREE(MTYPE_BGP_NAME, ep->dsd_mup_str);
		ep->dsd_mup_str = XSTRDUP(MTYPE_BGP_NAME, ec_str);
		ep->dsd_mup_as = mup_as;
		ep->dsd_mup_val = mup_val;
		mup_dsd_postchange(afi, bgp);
	} else {
		mup_dsd_prechange(afi, bgp);
		ep = bgp_mup_export_get(bgp, afi);
		XFREE(MTYPE_BGP_NAME, ep->dsd_mup_str);
		ep->dsd_mup_as = 0;
		ep->dsd_mup_val = 0;
		mup_dsd_postchange(afi, bgp);
	}
	return CMD_SUCCESS;
}

/* Re-evaluate the receive-side install of every locally-importing MUP
 * path on @vrf_bgp/@afi.  Called when this VRF's `route-map import`
 * (or its body) changes so already-received T1ST/T2ST routes pick up
 * the new filter.  MUP installs are global SRv6 dataplane state, so the
 * walk is single-pass over the default-instance MUP RIB rather than
 * per-VRF.
 */
static void mup_import_replay(struct bgp *vrf_bgp, afi_t afi)
{
	struct bgp *default_bgp = bgp_get_default();
	struct bgp_table *table;
	struct bgp_dest *dest;

	if (!default_bgp || !vrf_bgp)
		return;
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	table = default_bgp->rib[afi][SAFI_MUP];
	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *p = bgp_dest_get_prefix(dest);
		struct bgp_path_info *pi;

		if (p->family != AF_MUP)
			continue;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			struct ecommunity *route_rt;

			if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				continue;
			if (!pi->attr)
				continue;
			route_rt = bgp_attr_get_ecommunity(pi->attr);
			if (!route_rt)
				continue;
			if (!bgp_mup_route_rt_in_import(vrf_bgp, afi, route_rt))
				continue;
			(void)bgp_mup_zebra_withdraw(dest, pi, default_bgp);
			(void)bgp_mup_zebra_announce(dest, pi, default_bgp);
			break;
		}
	}
}

/* Mirror af_route_map_vpn_imexport_cmd in bgpd/bgp_vty.c.  Like L3VPN,
 * MUP's route-map DEFPY takes only <import|export> (no `both`).  The
 * TOMUP slot filters VRF->MUP leaked ISD/DSD (mup_leak_from_vrf_update);
 * the FROMMUP slot gates the receive-side install
 * (bgp_mup_apply_import_rmap).
 */
DEFPY (af_mup_route_map,
       af_mup_route_map_cmd,
       "[no] route-map <import|export>$direction_str RMAP$rmap_str",
       NO_STR
       "Route-map to filter MUP routes\n"
       "Apply on receive (gates per-VRF install)\n"
       "Apply on origination (filters locally-emitted ISD/DSD)\n"
       "Name of route-map\n")
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
		XFREE(MTYPE_BGP_NAME, ep->rmap_name[dir]);
		ep->rmap[dir] = NULL;
		if (yes) {
			ep->rmap_name[dir] = XSTRDUP(MTYPE_BGP_NAME, rmap_str);
			ep->rmap[dir] = route_map_lookup_warn_noexist(vty, rmap_str);
		}

		if (dir == BGP_MUP_POLICY_DIR_TOMUP)
			mup_leak_postchange(afi, bgp);
		else
			mup_import_replay(bgp, afi);
	}

	return CMD_SUCCESS;
}

ALIAS (af_mup_route_map,
       af_no_mup_route_map_cmd,
       "no route-map <import|export>$direction_str",
       NO_STR
       "Route-map to filter MUP routes\n"
       "Apply on receive (gates per-VRF install)\n"
       "Apply on origination (filters locally-emitted ISD/DSD)\n")

/* Re-resolve route-map pointers on every (bgp, afi) whose policy
 * references @rmap_name and replay the affected leak/install paths so
 * an edit / definition / deletion of a route-map body propagates to
 * already-leaked ISD/DSD (TOMUP) and already-installed receive-side
 * state (FROMMUP).  Mirrors vpn_policy_routemap_update in
 * bgpd/bgp_mplsvpn.c.
 */
static void mup_policy_routemap_update(struct bgp *bgp, const char *rmap_name)
{
	struct route_map *rmap;
	struct bgp_mup_export_policy *ep;
	afi_t afi;
	enum bgp_mup_policy_dir dir;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT &&
	    bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	rmap = route_map_lookup_by_name(rmap_name); /* NULL if deleted */

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		ep = bgp_mup_export_peek(bgp, afi);
		if (!ep)
			continue;

		for (dir = 0; dir < BGP_MUP_POLICY_DIR_MAX; ++dir) {
			if (!ep->rmap_name[dir] ||
			    strcmp(rmap_name, ep->rmap_name[dir]) != 0)
				continue;

			if (dir == BGP_MUP_POLICY_DIR_TOMUP)
				mup_leak_prechange(afi, bgp);

			ep->rmap[dir] = rmap;

			if (dir == BGP_MUP_POLICY_DIR_TOMUP)
				mup_leak_postchange(afi, bgp);
			else
				mup_import_replay(bgp, afi);
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

void bgp_mup_vty_init(void)
{
	install_element(BGP_MUPV4_NODE, &af_rt_mup_cmd);
	install_element(BGP_MUPV4_NODE, &af_no_rt_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_rt_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_no_rt_mup_cmd);

	install_element(BGP_MUPV4_NODE, &af_rd_mup_cmd);
	install_element(BGP_MUPV4_NODE, &af_no_rd_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_rd_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_no_rd_mup_cmd);

	install_element(BGP_MUPV4_NODE, &af_sid_mup_cmd);
	install_element(BGP_MUPV4_NODE, &af_no_sid_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_sid_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_no_sid_mup_cmd);

	install_element(BGP_MUPV4_NODE, &af_source_upf_prefix_len_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_source_upf_prefix_len_mup_cmd);
	install_element(BGP_MUPV4_NODE, &af_nexthop_mup_cmd);
	install_element(BGP_MUPV6_NODE, &af_nexthop_mup_cmd);

	install_element(BGP_MUPV4_NODE, &af_mup_route_map_cmd);
	install_element(BGP_MUPV4_NODE, &af_no_mup_route_map_cmd);
	install_element(BGP_MUPV6_NODE, &af_mup_route_map_cmd);
	install_element(BGP_MUPV6_NODE, &af_no_mup_route_map_cmd);

	install_element(BGP_MUPV4_NODE, &af_mup_segment_interwork_cmd);
	install_element(BGP_MUPV6_NODE, &af_mup_segment_interwork_cmd);

	install_element(BGP_MUPV4_NODE, &af_mup_segment_direct_cmd);
	install_element(BGP_MUPV4_NODE, &af_no_mup_segment_direct_cmd);
	install_element(BGP_MUPV6_NODE, &af_mup_segment_direct_cmd);
	install_element(BGP_MUPV6_NODE, &af_no_mup_segment_direct_cmd);

	install_element(BGP_MUPV4_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_address_cmd);
	install_element(BGP_MUPV4_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_behavior_cmd);
	install_element(BGP_MUPV4_SEGMENT_DIRECT_NODE, &af_no_mup_segment_direct_behavior_cmd);
	install_element(BGP_MUPV4_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_segment_id_cmd);
	install_element(BGP_MUPV6_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_address_cmd);
	install_element(BGP_MUPV6_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_behavior_cmd);
	install_element(BGP_MUPV6_SEGMENT_DIRECT_NODE, &af_no_mup_segment_direct_behavior_cmd);
	install_element(BGP_MUPV6_SEGMENT_DIRECT_NODE, &af_mup_segment_direct_segment_id_cmd);
}

/* Emit every per-(vrf, afi) BGP-MUP policy line under
 * `address-family ipv[46] mup`.  Origination knobs (rd / rt / sid /
 * nexthop / segment interwork) are written on the non-default vrf
 * instance.  All BGP-MUP config is self-contained in the MUP AF;
 * nothing is emitted under `address-family ipv[46] unicast`.
 */
void bgp_mup_config_write_af(struct vty *vty, struct bgp *bgp, afi_t afi)
{
	struct bgp_mup_export_policy *ep = bgp_mup_export_peek(bgp, afi);
	struct ecommunity *rt_in, *rt_out;

	if (!ep)
		return;

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_RD_SET) && ep->tovpn_rd_pretty)
		vty_out(vty, "  rd %s\n", ep->tovpn_rd_pretty);

	rt_in = ep->rtlist[BGP_MUP_POLICY_DIR_FROMMUP];
	rt_out = ep->rtlist[BGP_MUP_POLICY_DIR_TOMUP];
	if (rt_in && rt_out && ecommunity_cmp(rt_in, rt_out)) {
		char *b = ecommunity_ecom2str(rt_in, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);

		vty_out(vty, "  rt both %s\n", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	} else {
		if (rt_in) {
			char *b = ecommunity_ecom2str(rt_in, ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);

			vty_out(vty, "  rt import %s\n", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
		if (rt_out) {
			char *b = ecommunity_ecom2str(rt_out, ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);

			vty_out(vty, "  rt export %s\n", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
	}

	if (ep->rmap_name[BGP_MUP_POLICY_DIR_FROMMUP])
		vty_out(vty, "  route-map import %s\n",
			ep->rmap_name[BGP_MUP_POLICY_DIR_FROMMUP]);
	if (ep->rmap_name[BGP_MUP_POLICY_DIR_TOMUP])
		vty_out(vty, "  route-map export %s\n",
			ep->rmap_name[BGP_MUP_POLICY_DIR_TOMUP]);

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_AUTO)) {
		if (ep->locator_name)
			vty_out(vty, "  sid auto locator %s\n", ep->locator_name);
		else
			vty_out(vty, "  sid auto\n");
	} else if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SID_EXPLICIT) &&
		   ep->tovpn_sid_explicit) {
		if (ep->locator_name)
			vty_out(vty, "  sid explicit %pI6 locator %s\n", ep->tovpn_sid_explicit,
				ep->locator_name);
		else
			vty_out(vty, "  sid explicit %pI6\n", ep->tovpn_sid_explicit);
	}

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SOURCE_UPF_PREFIX_LEN_SET))
		vty_out(vty, "  source-upf-prefix-len %u\n", ep->source_upf_prefix_len);

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_NEXTHOP_SET)) {
		if (ep->tovpn_nexthop.family == AF_INET)
			vty_out(vty, "  nexthop %pI4\n", &ep->tovpn_nexthop.u.prefix4);
		else if (ep->tovpn_nexthop.family == AF_INET6)
			vty_out(vty, "  nexthop %pI6\n", &ep->tovpn_nexthop.u.prefix6);
	}

	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_INTERWORK))
		vty_out(vty, "  segment interwork\n");
	if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_SEGMENT_DIRECT)) {
		vty_out(vty, "  segment direct\n");
		if (CHECK_FLAG(ep->flags, BGP_MUP_EXPORT_POLICY_DSD_ADDRESS_SET))
			vty_out(vty, "   address %pI4\n", &ep->dsd_address.ipaddr_v4);
		if (ep->dsd_behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4)
			vty_out(vty, "   behavior dt4\n");
		else if (ep->dsd_behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT6)
			vty_out(vty, "   behavior dt6\n");
		else if (ep->dsd_behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46)
			vty_out(vty, "   behavior dt46\n");
		if (ep->dsd_mup_str)
			vty_out(vty, "   segment-id %s\n", ep->dsd_mup_str);
		vty_out(vty, "  exit\n");
	}
}
