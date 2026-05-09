// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for bgp_nlri_parse_mup (draft-ietf-bess-mup-safi route types 1..4).
 * Copyright (C) 2026 Yuya Kusakabe
 */

#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mup.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;

/*
 * Wire format: arch_type(1) | route_type(2 BE) | length(1) | body(length)
 *
 * AFI for all tests: AFI_IP unless noted.
 */

#define MUP_ARCH    0x01       /* BGP_MUP_ARCH_3GPP_5G */
#define MUP_ISD_RT  0x00, 0x01 /* BGP_MUP_ISD_ROUTE  big-endian */
#define MUP_DSD_RT  0x00, 0x02 /* BGP_MUP_DSD_ROUTE  big-endian */
#define MUP_T1ST_RT 0x00, 0x03 /* BGP_MUP_T1ST_ROUTE big-endian */
#define MUP_T2ST_RT 0x00, 0x04 /* BGP_MUP_T2ST_ROUTE big-endian */

/* RD type 0 (AS:value): 0x00 0x00 <AS2> <val4> */
#define RD0 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01

struct nlri_test {
	const char *name;
	const char *desc;
	const uint8_t data[256];
	int len;
	afi_t afi;
	int expect; /* expected bgp_nlri_parse_mup return code */
};

/* clang-format off */
static struct nlri_test mup_segments[] = {
	/* ------------------------------------------------------------------ */
	/* Happy path: one well-formed PDU per route type                      */
	/* ------------------------------------------------------------------ */
	{
		"isd-v4-ok",
		"ISD IPv4, /24 prefix, well-formed",
		{
			/* arch | route-type | length */
			MUP_ARCH, MUP_ISD_RT,
			/* body length = RD(8) + pfxlen(1) + pfx-octets(3) = 12 */
			12,
			/* RD type-0: AS 100 : value 1 */
			RD0,
			/* prefix length (bits) */
			24,
			/* prefix 192.168.1.0/24 */
			192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"dsd-v4-ok",
		"DSD IPv4, PE address 10.0.0.1, well-formed",
		{
			MUP_ARCH, MUP_DSD_RT,
			/* body = RD(8) + IPv4(4) = 12 */
			12,
			RD0,
			/* PE address 10.0.0.1 */
			10, 0, 0, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-v4-ok",
		"T1ST IPv4, /0 UE prefix, TEID 1, QFI 9, EP 10.1.2.3/32, no SA, well-formed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body = RD(8) + pfxlen(1) + pfx-octets(0) +
			 *        TEID(4) + QFI(1) + ep_len(1) + ep(4) +
			 *        src_len(1) = 20
			 */
			20,
			RD0,
			/* UE prefix length 0 (no bytes follow) */
			0,
			/* TEID = 1 (non-zero, big-endian) */
			0x00, 0x00, 0x00, 0x01,
			/* QFI */
			9,
			/* endpoint address length in bits = 32 */
			32,
			/* endpoint 10.1.2.3 */
			10, 1, 2, 3,
			/* source address length = 0 (absent) */
			0,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v4-ok",
		"T2ST IPv4, EP 10.2.0.1, TEID 2, ea_len=64, well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/*
			 * body = RD(8) + ea_len(1) + addr(4) + teid_octets(4)
			 * ea_len=64: 32 addr bits + 32 TEID bits => teid_octets=4
			 * total = 8+1+4+4 = 17
			 */
			17,
			RD0,
			/* ea_len = 64 bits */
			64,
			/* endpoint address 10.2.0.1 */
			10, 2, 0, 1,
			/* TEID = 2 (non-zero, big-endian, packed in 4 bytes) */
			0x00, 0x00, 0x00, 0x02,
		},
		.len = 4 + 17,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: outer header too short — returns MUP_MISSING_TYPE        */
	/* ------------------------------------------------------------------ */
	{
		"truncated-header",
		"NLRI truncated before 4-byte header completes",
		{
			/* Only 3 bytes: arch + route_type(2 bytes) — no length */
			MUP_ARCH, MUP_ISD_RT,
		},
		.len = 3,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: body length overflows outer NLRI — returns PACKET_OVERFLOW */
	/* ------------------------------------------------------------------ */
	{
		"body-overflow",
		"Route-type length field claims more bytes than the NLRI holds",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* claim 20 bytes in body, but only 12 follow */
			20,
			RD0,
			24, 192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: leftover bytes after consuming NLRI                      */
	/*                                                                    */
	/* A single trailing byte looks like the start of a new header; the  */
	/* loop's 4-byte-header check fires first → MUP_MISSING_TYPE.        */
	/* PACKET_LENGTH is only reachable if pnt lands *exactly* mid-body,  */
	/* which cannot happen because psize is always <= (lim - pnt) after  */
	/* the overflow guard.  Test the reachable path.                      */
	/* ------------------------------------------------------------------ */
	{
		"trailing-garbage",
		"Single trailing byte re-enters header check, returns MUP_MISSING_TYPE",
		{
			MUP_ARCH, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
			/* extra garbage byte — triggers partial-header path */
			0xff,
		},
		.len = 4 + 12 + 1,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): prefix length > AFI max — outer returns OK       */
	/* (inner decoder logs and skips the NLRI per RFC 7606 treat-as-withdraw) */
	/* ------------------------------------------------------------------ */
	{
		"isd-prefix-len-overflow",
		"ISD IPv4, prefix_len=33 (>32) — inner decoder skips, outer returns OK",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* body: RD(8) + pfxlen(1) + pfx-octets for /33 = PSIZE(33)=5 */
			14,
			RD0,
			/* prefix length 33 — exceeds IPv4 max */
			33,
			192, 168, 1, 0, 0,
		},
		.len = 4 + 14,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T1ST with TEID=0 — inner skips, outer returns OK */
	/* ------------------------------------------------------------------ */
	{
		"t1st-teid-zero",
		"T1ST IPv4, TEID=0 — inner decoder skips (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			20,
			RD0,
			0,
			/* TEID = 0 (forbidden) */
			0x00, 0x00, 0x00, 0x00,
			9,
			32,
			10, 1, 2, 3,
			0,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T1ST endpoint length > AFI max — inner skips     */
	/* ------------------------------------------------------------------ */
	{
		"t1st-ep-len-overflow",
		"T1ST IPv4, endpoint_length=33 (>32) — inner decoder skips",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body: RD(8)+pfxlen(1)+teid(4)+qfi(1)+ep_len(1) = 15
			 * ep_len=33 => ep_octets=4 (ep_len/8); but parser
			 * rejects ep_len>32 for AFI_IP before reading ep bytes.
			 * We need psize>=16 so the initial length check passes,
			 * and the overall body size plausible.
			 * layout: RD(8)+pfx_len(1)+teid(4)+qfi(1)+ep_len(1)=15
			 * plus 1 spare byte to pass the ep_octets+1>psize guard.
			 */
			16,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			/* endpoint_length = 33 bits — exceeds IPv4 max */
			33,
		},
		.len = 4 + 16,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T2ST with TEID=0 — inner skips, outer returns OK */
	/* ------------------------------------------------------------------ */
	{
		"t2st-teid-zero",
		"T2ST IPv4, TEID=0 — inner decoder skips (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T2ST_RT,
			17,
			RD0,
			64,
			10, 2, 0, 1,
			/* TEID = 0 (forbidden) */
			0x00, 0x00, 0x00, 0x00,
		},
		.len = 4 + 17,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): DSD with wrong body size for AFI — inner skips   */
	/* ------------------------------------------------------------------ */
	{
		"dsd-wrong-size",
		"DSD IPv4, body=13 (not 12) — inner decoder skips",
		{
			MUP_ARCH, MUP_DSD_RT,
			13,
			RD0,
			10, 0, 0, 1,
			/* one extra byte makes psize 13 != 12 for AFI_IP */
			0x00,
		},
		.len = 4 + 13,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Unknown arch_type — outer silently skips, returns OK               */
	/* ------------------------------------------------------------------ */
	{
		"unknown-arch-type",
		"Unknown arch_type=0xFF — outer loop skips, returns OK",
		{
			/* arch_type = 0xFF (undefined) */
			0xFF, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* sentinel */
	{ NULL, NULL, { 0 }, 0, 0, 0 },
};

/* clang-format on */

static void run_test(struct peer *peer, struct nlri_test *t)
{
	struct bgp_nlri packet = {};
	int ret;
	int oldfailed = failed;

	packet.afi = t->afi;
	packet.safi = SAFI_MUP;
	packet.nlri = (uint8_t *)t->data;
	packet.length = t->len;

	ret = bgp_nlri_parse_mup(peer, NULL, &packet, 0);

	printf("%s: %s\n", t->name, t->desc);
	printf("  got=%d expected=%d: %s\n", ret, t->expect, (ret == t->expect) ? "OK" : "FAIL");

	if (ret != t->expect)
		failed++;

	if (failed > oldfailed)
		printf("  *** FAILED\n");
	printf("\n");
}

static struct bgp *bgp;
static as_t asn = 100;

int main(void)
{
	struct interface ifp;
	struct peer *peer;
	int i;

	conf_bgp_debug_neighbor_events = -1UL;
	conf_bgp_debug_packet = -1UL;
	conf_bgp_debug_as4 = -1UL;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("test bgp mup nlri");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_labels_init();

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return 1;

	peer = peer_create_accept(bgp, NULL);
	peer->host = (char *)"test-peer";
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(BGP_MAX_PACKET_SIZE);

	ifp.ifindex = 0;
	peer->nexthop.ifp = &ifp;

	for (i = AFI_IP; i < AFI_MAX; i++) {
		peer->afc[i][SAFI_MUP] = 1;
		peer->afc_adv[i][SAFI_MUP] = 1;
		peer->afc_nego[i][SAFI_MUP] = 1;
	}

	i = 0;
	while (mup_segments[i].name)
		run_test(peer, &mup_segments[i++]);

	printf("failures: %d\n", failed);
	return failed;
}
