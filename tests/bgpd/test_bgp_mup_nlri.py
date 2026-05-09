# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpMupNlri(frrtest.TestMultiOut):
    program = "./test_bgp_mup_nlri"


TestBgpMupNlri.okfail("isd-v4-ok: ISD IPv4, /24 prefix, well-formed")
TestBgpMupNlri.okfail("dsd-v4-ok: DSD IPv4, PE address 10.0.0.1, well-formed")
TestBgpMupNlri.okfail(
    "t1st-v4-ok: T1ST IPv4, /0 UE prefix, TEID 1, QFI 9, EP 10.1.2.3/32, no SA, well-formed"
)
TestBgpMupNlri.okfail(
    "t2st-v4-ok: T2ST IPv4, EP 10.2.0.1, TEID 2, ea_len=64, well-formed"
)
TestBgpMupNlri.okfail(
    "truncated-header: NLRI truncated before 4-byte header completes"
)
TestBgpMupNlri.okfail(
    "body-overflow: Route-type length field claims more bytes than the NLRI holds"
)
TestBgpMupNlri.okfail(
    "trailing-garbage: Single trailing byte re-enters header check, returns MUP_MISSING_TYPE"
)
TestBgpMupNlri.okfail(
    "isd-prefix-len-overflow: ISD IPv4, prefix_len=33 (>32) — inner decoder skips, outer returns OK"
)
TestBgpMupNlri.okfail(
    "t1st-teid-zero: T1ST IPv4, TEID=0 — inner decoder skips (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "t1st-ep-len-overflow: T1ST IPv4, endpoint_length=33 (>32) — inner decoder skips"
)
TestBgpMupNlri.okfail(
    "t2st-teid-zero: T2ST IPv4, TEID=0 — inner decoder skips (treat-as-withdraw)"
)
TestBgpMupNlri.okfail(
    "dsd-wrong-size: DSD IPv4, body=13 (not 12) — inner decoder skips"
)
TestBgpMupNlri.okfail(
    "unknown-arch-type: Unknown arch_type=0xFF — outer loop skips, returns OK"
)
