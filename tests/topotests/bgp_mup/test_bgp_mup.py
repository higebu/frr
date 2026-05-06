#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Yuya Kusakabe
#
r"""
Test BGP-MUP SAFI (draft-ietf-bess-mup-safi):
- BGP session establishment over BGP-MUP peerings
- BGP-MUP capability negotiation for both AFI=IPv4 and AFI=IPv6
- ISD origination via `segment interwork` driven by the SAFI_MUP RIB
  locally-originated set (network/redistribute under MUP AF) and DSD
  origination via the `segment direct` sub-block (auto-allocated SIDs
  from zebra's SRv6 SID manager)
- Propagation of ISD/DSD routes from r1 to r2
- Persistence of `segment` lines in running-config
- Cleanup via `no segment ...`
- T1ST resolution against the ISD cache (Section 3.3.9): r2 receives
  a T1ST from an ExaBGP MUP-Controller peer whose endpoint falls
  inside r1's ISD prefix, synthesizes the End.M.GTP4.E SID
  (RFC 9433 Section 6.6), and installs an SRv6 H.Encaps route to the
  UE prefix.
- T2ST resolution against the DSD cache (Section 3.3.12): r2 receives
  a T2ST whose MUP-EC Direct-Type Segment Identifier matches r1's
  DSD, looks up the DSD's prefix-SID, and installs an H.M.GTP4.D
  seg6local route to the GTP-U endpoint.
- Negative cases: T1ST without a covering ISD and T2ST without a
  matching DSD must NOT install any FIB state.

Topology:

    +-----+         +-----+         +-------+
    | r1  |---------|  r2 |---------| peer1 |
    +-----+         +-----+         +-------+
       AS 65001       AS 65002       AS 65003
              eBGP (v6)       eBGP (v4) ExaBGP

r1 hosts an SRv6 locator (2001:db8:e::/64) and originates two ISD
routes (one v4, one v6) from `slice1` via `segment interwork` driven
by `redistribute connected` against a dummy netdev `lo-slice1`, plus
one DSD (v4) from `slice2` via the `segment direct` sub-block.  r2
receives them and caches them in the ISD/DSD discovery tables.
peer1 (ExaBGP) plays the MUP-Controller and injects T1ST/T2ST routes
into r2 to exercise the deferred resolution path.
"""

import os
import sys
import json
import time
import functools

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """r1 <--s1--> r2 <--s2--> peer1 (ExaBGP MUP-Controller)."""
    for i in (1, 2):
        tgen.add_router("r{}".format(i))

    sw = tgen.add_switch("s1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("s2")
    sw2.add_link(tgen.gears["r2"])
    peer = tgen.add_exabgp_peer(
        "peer1", ip="10.0.2.105/24", defaultRoute="via 10.0.2.1"
    )
    sw2.add_link(peer)

    # r1 binds ISD origination to vrf slice1 and DSD origination to
    # vrf slice2 (both refuse under the default vrf bgp instance,
    # mirroring End.DT* vrf-mandatory).  Both vrfs need real netdevs
    # before bgpd starts.
    for slice_name, slice_table in (("slice1", 100), ("slice2", 101)):
        tgen.gears["r1"].run("ip link add {} type vrf table {}".format(
            slice_name, slice_table
        ))
        tgen.gears["r1"].run("ip link set {} up".format(slice_name))

    # Dummy netdev inside slice1 carrying the ISD source prefixes.
    # frr.conf assigns 10.99.0.1/24 + 2001:db8:99::1/64 here, then
    # `redistribute connected` under MUP AF injects them into the
    # SAFI_MUP RIB as locally-originated and `segment interwork`
    # emits one ISD NLRI per non-default prefix.
    tgen.gears["r1"].run("ip link add lo-slice1 type dummy")
    tgen.gears["r1"].run("ip link set lo-slice1 master slice1")
    tgen.gears["r1"].run("ip link set lo-slice1 up")

    # r2 is the receive-only PE: it never originates ISD/DSD, but it
    # still needs per-vrf bgp instances to declare `rt import` values
    # for the T1ST/T2ST received from peer1.  bgpd refuses
    # `router bgp ASN vrf NAME` if the netdev doesn't exist.  Two
    # slices verify per-(vrf, afi) install-vrf selection on receive.
    for slice_name, slice_table in (("slice1", 100), ("slice2", 101)):
        tgen.gears["r2"].run("ip link add {} type vrf table {}".format(
            slice_name, slice_table
        ))
        tgen.gears["r2"].run("ip link set {} up".format(slice_name))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # Start ExaBGP after FRR is up so the BGP session establishes
    # against an already-listening r2.
    for pname, peer in tgen.exabgp_peers().items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)
        logger.info("started %s", pname)


def teardown_module(mod):
    get_topogen().stop_topology()


def _open_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(path)


def _check_router_json(router, command, reffile, label):
    expected = _open_json_file(reffile)
    test_func = functools.partial(
        topotest.router_json_cmp, router, command, expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"{}" {} JSON output mismatches'.format(
        router.name, label
    )


def _wait_for(router, predicate, label, count=60, wait=1):
    """Poll predicate(router) until it returns None (success) or timeout."""

    def _attempt():
        return predicate(router)

    _, result = topotest.run_and_expect(_attempt, None, count=count, wait=wait)
    assert result is None, '"{}" {} expectation not met: {}'.format(
        router.name, label, result
    )


def test_bgp_session_established():
    """The BGP session over the MUP-only AFs must reach Established."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BGP session establishes over BGP-MUP")

    for rname in ("r1", "r2"):
        _check_router_json(
            tgen.gears[rname],
            "show bgp neighbor json",
            os.path.join(CWD, rname, "bgp_neighbor.json"),
            "neighbor",
        )


def test_bgp_mup_capability():
    """ipv4Mup AND ipv6Mup must show advertisedAndReceived on both sides."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BGP-MUP multiprotocol capability negotiation")

    for rname in ("r1", "r2"):
        _check_router_json(
            tgen.gears[rname],
            "show bgp neighbor json",
            os.path.join(CWD, rname, "bgp_capability.json"),
            "MUP capability",
        )


def _grep(router, command, pattern):
    """Run `command` and return True if `pattern` (a substring) is in stdout."""
    output = router.vtysh_cmd(command)
    return pattern in output


def test_isd_dsd_originated_on_r1():
    """r1 must have its ISD(v4)+ISD(v6)+DSD(v4) routes in the local
    RIB.  ISD pair is sourced from slice1 (interwork); DSD comes from
    slice2 (direct) — split because `segment interwork` and `segment
    direct` are mutually exclusive per (vrf, afi)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying ISD/DSD originated locally on r1")
    r1 = tgen.gears["r1"]

    expectations = [
        ("show bgp ipv4 mup all", "10.99.0.0/24", "ISD(v4)"),
        ("show bgp ipv4 mup all", "10.0.0.250", "DSD(v4)"),
        ("show bgp ipv6 mup all", "2001:db8:99::/64", "ISD(v6)"),
    ]
    for cmd, pat, label in expectations:
        _wait_for(
            r1,
            lambda r, c=cmd, p=pat: None
            if _grep(r, c, p)
            else "expected '{}' in `{}`".format(p, c),
            label,
        )


def test_isd_dsd_propagated_to_r2():
    """All originated routes must arrive at r2 over BGP-MUP."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying ISD/DSD propagated from r1 to r2")
    r2 = tgen.gears["r2"]

    expectations = [
        ("show bgp ipv4 mup all", "10.99.0.0/24", "ISD(v4)"),
        ("show bgp ipv4 mup all", "10.0.0.250", "DSD(v4)"),
        ("show bgp ipv6 mup all", "2001:db8:99::/64", "ISD(v6)"),
    ]
    for cmd, pat, label in expectations:
        _wait_for(
            r2,
            lambda r, c=cmd, p=pat: None
            if _grep(r, c, p)
            else "expected '{}' in `{}`".format(p, c),
            label,
        )


def test_prefix_sid_structure_propagated():
    """RFC 9252 Section 3.1 SID Structure sub-sub-TLV (block 24 /
    node 24 / func 8 / arg 0) must round-trip from r1's locator
    config to r2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv4 mup all detail-routes",
                 "sid structure=[24 24 8 0 0 0]")
        else "SID Structure sub-sub-TLV not seen on r2",
        "Prefix-SID Structure",
    )


def test_policy_lines_in_running_config():
    """`show running-config` on r1 must emit the new self-contained
    MUP-AF policy lines (rd / rt / sid / segment <interwork|direct>
    + sub-block).  No `mup` infix, no `export` direction qualifier
    on unidirectional commands."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    expected_lines = [
        "rd 100:100",
        "rt export 65001:1",
        "rd 200:200",
        "rt export 65001:2",
        "sid auto",
        "sid auto locator loc-mup-v6",
        "segment interwork",
        "segment direct",
        "address 10.0.0.250",
        "behavior dt4",
        "segment-id 65001:10",
    ]
    for line in expected_lines:
        assert line in output, (
            "running-config missing line: {}\n--- output ---\n{}".format(
                line, output
            )
        )


def test_per_policy_locator_selection():
    """The IPv6 MUP AF on r1 has `sid auto locator loc-mup-v6`, so
    r1's End.M.GTP6.E SID for the IPv6 ISD must be allocated from
    `loc-mup-v6` (2001:db8:f::/48).  The IPv4 AF has no override, so
    its End.M.GTP4.E SID stays under the bgp default `default`
    (2001:db8:e::/48)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv6 mup all detail-routes",
                 "Remote SID: 2001:db8:f:")
        else "IPv6 ISD SID must fall inside loc-mup-v6 (2001:db8:f::/48)",
        "IPv6 ISD anchored under loc-mup-v6",
    )

    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv4 mup all detail-routes",
                 "Remote SID: 2001:db8:e:")
        else "IPv4 ISD SID must fall inside default locator (2001:db8:e::/48)",
        "IPv4 ISD anchored under default locator",
    )


def test_t1st_received_from_peer1():
    """peer1's T1ST routes must reach r2's BGP-MUP RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    for ue in ("192.168.1.5", "192.168.2.5"):
        _wait_for(
            r2,
            lambda r, p=ue: None
            if _grep(r, "show bgp ipv4 mup all", p)
            else "expected T1ST UE {} in r2's MUP RIB".format(p),
            "T1ST {}".format(ue),
        )


def test_t2st_received_from_peer1():
    """peer1's T2ST routes must reach r2's BGP-MUP RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    for ep in ("10.0.0.250", "10.0.0.99"):
        _wait_for(
            r2,
            lambda r, p=ep: None
            if _grep(r, "show bgp ipv4 mup all", p)
            else "expected T2ST endpoint {} in r2's MUP RIB".format(p),
            "T2ST {}".format(ep),
        )


def _route_via_bgp(router, prefix, family="ip", vrf=None):
    """Return True iff `show <family> route [vrf VRF] <prefix> json`
    reports a BGP-installed route on `router`."""
    if vrf:
        cmd = "show {} route vrf {} {} json".format(family, vrf, prefix)
    else:
        cmd = "show {} route {} json".format(family, prefix)
    output = router.vtysh_cmd(cmd, isjson=True)
    if not isinstance(output, dict):
        return False
    routes = output.get(prefix) or output.get(prefix.split("/")[0])
    if not routes:
        # vtysh sometimes keys by prefix and sometimes by host address;
        # if neither hit, scan the whole dict.
        routes = []
        for v in output.values():
            if isinstance(v, list):
                routes.extend(v)
    for r in routes if isinstance(routes, list) else []:
        if r.get("protocol") == "bgp":
            return True
    return False


def test_t1st_resolved_via_isd_cache():
    """r2 must install an SRv6 H.Encaps route for 192.168.1.5/32 in
    vrf slice1 once r1's ISD 10.99.0.0/24 covers the T1ST endpoint
    10.99.0.5 (draft Section 3.3.9 + RFC 9433 Section 6.6)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "192.168.1.5/32", vrf="slice1")
        else "BGP route for 192.168.1.5/32 not installed in vrf slice1",
        "T1ST UE 192.168.1.5/32 resolved",
    )


def test_t1st_skipped_without_isd():
    """T1ST 192.168.2.5/32 has endpoint 10.123.0.5 with no covering
    ISD; r2 must NOT install a FIB route for it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    time.sleep(5)
    assert not _route_via_bgp(r2, "192.168.2.5/32"), (
        "T1ST without a covering ISD must not install a route"
    )
    assert not _route_via_bgp(r2, "192.168.2.5/32", vrf="slice1"), (
        "T1ST without a covering ISD must not install a route in slice1"
    )


def test_t2st_resolved_via_dsd_cache():
    """r2 must install an H.M.GTP4.D seg6local route for
    10.0.0.250/32 in vrf slice1 once r1's DSD with MUP-EC 65001:10
    is in the cache (draft Section 3.3.12)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "10.0.0.250/32", vrf="slice1")
        else "BGP route for 10.0.0.250/32 not installed in vrf slice1",
        "T2ST 10.0.0.250/32 resolved",
    )


def test_t2st_skipped_without_dsd():
    """T2ST 10.0.0.99 carries MUP-EC 65001:99 with no matching DSD;
    r2 must NOT install a FIB route for it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    time.sleep(5)
    assert not _route_via_bgp(r2, "10.0.0.99/32"), (
        "T2ST without a matching DSD must not install a route"
    )
    assert not _route_via_bgp(r2, "10.0.0.99/32", vrf="slice1"), (
        "T2ST without a matching DSD must not install a route in slice1"
    )


def test_t2st_install_vrf_selected_by_import_rt():
    """Two-VRF receive-side selection regression: r2 carries slice1
    (rt import 65001:1) and slice2 (rt import 65001:2).  The T2ST
    10.0.0.250 from peer1 carries RT 65001:1, so it must install
    only in slice1 — never in slice2, never in the default vrf."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "10.0.0.250/32", vrf="slice1")
        else "expected T2ST 10.0.0.250/32 in vrf slice1",
        "T2ST 10.0.0.250/32 in slice1",
    )

    time.sleep(5)
    assert not _route_via_bgp(r2, "10.0.0.250/32", vrf="slice2"), (
        "T2ST RT 65001:1 must not install in slice2 (slice2 only "
        "imports 65001:2)"
    )
    assert not _route_via_bgp(r2, "10.0.0.250/32"), (
        "T2ST must not install in default vrf"
    )


def test_route_map_export_filter():
    """`route-map export RMAP` under `address-family ipv[46] mup`
    filters which SAFI_MUP-RIB locally-originated prefixes leak as
    ISD NLRIs."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Add a second `network` prefix into the (slice1, AFI_IP, SAFI_MUP)
    # RIB so the rmap filter has two distinct prefixes to discriminate.
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  network 10.99.99.0/24\n"
        " exit-address-family\n"
        "exit\n"
    )

    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv4 mup all", "10.99.99.0/24")
        else "expected 10.99.99.0/24 ISD on r2 before rmap is applied",
        "baseline: 10.99.99.0/24 leaked",
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list N3-PFX seq 10 permit 10.99.0.0/24\n"
        "route-map N3-ONLY permit 10\n"
        " match ip address prefix-list N3-PFX\n"
        "exit\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  route-map export N3-ONLY\n"
        " exit-address-family\n"
        "exit\n"
    )

    _wait_for(
        r2,
        lambda r: None
        if not _grep(r, "show bgp ipv4 mup all", "10.99.99.0/24")
        else "10.99.99.0/24 must be withdrawn while N3-ONLY is attached",
        "filter on: 10.99.99.0/24 withdrawn",
    )
    assert _grep(r2, "show bgp ipv4 mup all", "10.99.0.0/24"), (
        "10.99.0.0/24 must remain after the export filter is attached"
    )

    output = r1.vtysh_cmd("show running-config")
    assert "route-map export N3-ONLY" in output, (
        "running-config missing route-map export line\n--- output ---\n"
        + output
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  no route-map export N3-ONLY\n"
        " exit-address-family\n"
        "exit\n"
    )

    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv4 mup all", "10.99.99.0/24")
        else "10.99.99.0/24 must be re-leaked after the export filter is removed",
        "filter off: 10.99.99.0/24 re-leaked",
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  no network 10.99.99.0/24\n"
        " exit-address-family\n"
        "exit\n"
        "no route-map N3-ONLY permit 10\n"
        "no ip prefix-list N3-PFX\n"
    )


def test_route_map_import_filter():
    """`route-map import RMAP` under `address-family ipv[46] mup`
    filters which received MUP NLRIs are admitted into the per-VRF
    install path."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "192.168.1.5/32", vrf="slice1")
        else "precondition: 192.168.1.5/32 must be installed before the rmap toggle",
        "baseline T1ST install",
    )

    r2.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list NO-N3 seq 10 deny 10.99.0.0/24 le 32\n"
        "ip prefix-list NO-N3 seq 20 permit 0.0.0.0/0 le 32\n"
        "route-map RX-FILTER permit 10\n"
        " match ip address prefix-list NO-N3\n"
        "exit\n"
        "router bgp 65002 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  route-map import RX-FILTER\n"
        " exit-address-family\n"
        "exit\n"
    )

    _wait_for(
        r2,
        lambda r: None
        if not _route_via_bgp(r, "192.168.1.5/32", vrf="slice1")
        else "T1ST must be withdrawn while RX-FILTER denies its covering ISD",
        "filter on: T1ST install withdrawn",
    )

    assert _route_via_bgp(r2, "10.0.0.250/32", vrf="slice1"), (
        "T2ST 10.0.0.250/32 must remain installed; the rmap denies only the ISD prefix"
    )

    output = r2.vtysh_cmd("show running-config")
    assert "route-map import RX-FILTER" in output, (
        "running-config missing route-map import line\n--- output ---\n"
        + output
    )

    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002 vrf slice1\n"
        " address-family ipv4 mup\n"
        "  no route-map import RX-FILTER\n"
        " exit-address-family\n"
        "exit\n"
    )

    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "192.168.1.5/32", vrf="slice1")
        else "T1ST must reinstall once RX-FILTER detaches and the ISD is re-cached",
        "filter off: T1ST install resumed",
    )

    r2.vtysh_cmd(
        "configure terminal\n"
        "no route-map RX-FILTER permit 10\n"
        "no ip prefix-list NO-N3\n"
        "exit\n"
    )


def test_no_segment_removes_route():
    """`no segment direct` must withdraw the DSD from both r1 and r2
    RIBs, drop the line from running-config, AND cause r2 to remove
    the matching T2ST FIB route once the DSD cache loses its entry."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice2\n"
        " address-family ipv4 mup\n"
        "  no segment direct\n"
        " exit-address-family\n"
        "exit\n"
    )

    # Match the DSD NLRI form `[2]:[12]:[10.0.0.250]` specifically —
    # the T2ST received from peer1 also contains "10.0.0.250" in its
    # NLRI (route_type 4: `[4]:[17]:[64/10.0.0.250]`), so a bare
    # substring match would still hit even after the DSD is gone.
    dsd_nlri = "[2]:[12]:[10.0.0.250]"
    _wait_for(
        r1,
        lambda r: None
        if not _grep(r, "show bgp ipv4 mup all", dsd_nlri)
        else "DSD still present on r1",
        "DSD withdrawn from r1",
    )
    _wait_for(
        r2,
        lambda r: None
        if not _grep(r, "show bgp ipv4 mup all", dsd_nlri)
        else "DSD still present on r2",
        "DSD withdrawn from r2",
    )
    _wait_for(
        r2,
        lambda r: None
        if not _route_via_bgp(r, "10.0.0.250/32", vrf="slice1")
        else "T2ST FIB entry still present on r2 after DSD withdrawal",
        "T2ST 10.0.0.250/32 withdrawn from r2 FIB",
    )

    output = r1.vtysh_cmd("show running-config")
    assert "segment direct" not in output, (
        "running-config still contains the withdrawn DSD enable line"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
