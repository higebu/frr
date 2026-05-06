#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Yuya Kusakabe
#
r"""
Test BGP-MUP SAFI (draft-ietf-bess-mup-safi):
- BGP session establishment over BGP-MUP peerings
- BGP-MUP capability negotiation for both AFI=IPv4 and AFI=IPv6
- ISD origination via the export-policy form (`rd/rt/sid mup export`
  under the VRF's unicast AF + `redistribute connected` driving the
  leak from the unicast RIB) and DSD origination via `segment direct`
  (auto-allocated SIDs from zebra's SRv6 SID manager)
- Propagation of ISD/DSD routes from r1 to r2
- Persistence of `segment` lines in running-config
- Cleanup via `no segment ...`
- T1ST resolution against the ISD cache (§3.3.9): r2 receives a T1ST
  from an ExaBGP MUP-Controller peer whose endpoint falls inside r1's
  ISD prefix, synthesizes the End.M.GTP4.E SID (RFC 9433 §6.6), and
  installs an SRv6 H.Encaps route to the UE prefix.
- T2ST resolution against the DSD cache (§3.3.12): r2 receives a T2ST
  whose MUP-EC Direct-Type Segment Identifier matches r1's DSD, looks
  up the DSD's prefix-SID, and installs an H.M.GTP4.D seg6local route
  to the GTP-U endpoint.
- Negative cases: T1ST without a covering ISD and T2ST without a
  matching DSD must NOT install any FIB state.

Topology:

    +-----+         +-----+         +-------+
    | r1  |---------|  r2 |---------| peer1 |
    +-----+         +-----+         +-------+
       AS 65001       AS 65002       AS 65003
              eBGP (v6)       eBGP (v4) ExaBGP

r1 hosts an SRv6 locator (2001:db8:e::/64) and originates two ISD
routes (one v4, one v6) — leaked from slice1's unicast RIB via
`rd/rt/sid mup export` + `redistribute connected` against a dummy
netdev `lo-slice1` — plus two DSD routes (v4) via `segment direct`;
r2 receives them and caches them in the ISD/DSD discovery tables.
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

    # ISD export (`rd/rt/sid mup export` under unicast AF) and DSD
    # (`segment direct` under MUP AF) both reject under the default
    # vrf bgp instance (RFC 8986 §4.7-§4.8: End.DT4/DT6 are
    # vrf-mandatory).  r1's frr.conf binds both originations to
    # `router bgp 65001 vrf slice1`, which needs an actual vrf netdev
    # to exist before bgpd starts.
    tgen.gears["r1"].run("ip link add slice1 type vrf table 100")
    tgen.gears["r1"].run("ip link set slice1 up")
    # Dummy netdev inside slice1 carrying the ISD source prefixes.
    # frr.conf assigns 10.99.0.1/24 + 2001:db8:99::1/64 here, then
    # `redistribute connected` pulls them into slice1's BGP unicast
    # RIB and `rd/rt/sid mup export` leaks them into BGP-MUP as ISD
    # NLRIs.
    tgen.gears["r1"].run("ip link add lo-slice1 type dummy")
    tgen.gears["r1"].run("ip link set lo-slice1 master slice1")
    tgen.gears["r1"].run("ip link set lo-slice1 up")

    # r2 is the receive-only PE: it never originates ISD/DSD, but it
    # still needs per-vrf bgp instances to declare `rt mup import`
    # values for the T1ST/T2ST received from peer1.  bgpd refuses
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
    """r1 must have its ISD(v4)+DSD(v4)+ISD(v6) routes in the local
    RIB.  Per refactor 210805, DSD is a single per-(vrf, afi) NLRI;
    a second DSD with a different RT is no longer expressible at the
    single (slice1, AFI_IP) policy."""
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
    """RFC 9252 §3.1 SID Structure sub-sub-TLV (block 24 / node 24 /
    func 8 / arg 0) must round-trip from r1's locator config to r2.

    Layout chosen so loc_func (= 56) leaves room for both the IPv4 DA
    (32 bits at offset 56) and Args.Mob.Session (40 bits at offset 88)
    when r2 synthesizes End.M.GTP4.E SIDs per RFC 9433 §6.6: a larger
    locator (e.g. /64 with block 40+node 24+func 16) overflows IPV6_MAX
    once those mobile-args are layered on."""
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


def test_export_and_segment_lines_in_running_config():
    """`show running-config` on r1 must emit the new L3VPN-style MUP
    policy lines under unicast AF (rd|rt|sid mup export, segment mup
    export <interwork|direct>, behavior mup export, ext-community mup
    export).

    The IPv6 unicast AF uses the per-policy `locator loc-mup-v6`
    override, so the `sid mup export auto locator loc-mup-v6` form
    must round-trip too — separate from the IPv4 unicast AF's plain
    `sid mup export auto`.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    expected_lines = [
        "rd mup export 100:100",
        "rt mup export 65001:1",
        "rd mup export 200:200",
        "rt mup export 65001:2",
        "sid mup export auto",
        "sid mup export auto locator loc-mup-v6",
        "segment mup export interwork",
        "segment mup export direct address 10.0.0.250",
        "behavior mup export dt4",
        "ext-community mup export 65001:10",
    ]
    for line in expected_lines:
        assert line in output, (
            "running-config missing line: {}\n--- output ---\n{}".format(
                line, output
            )
        )


def test_per_policy_locator_selection():
    """The IPv6 unicast AF on r1 has `sid mup export auto locator
    loc-mup-v6`, so r1's End.M.GTP6.E SID for the IPv6 ISD must be
    allocated from `loc-mup-v6` (2001:db8:f::/48), not from the bgp
    instance default `default` (2001:db8:e::/48).  The IPv4 AF has
    no override, so its End.M.GTP4.E SID stays under `default`.

    Verifies the deliberate L3VPN-baseline deviation documented in
    `closed/.../feature-isd-derive-from-vrf-rib-design.md`: MUP's
    SID encodes behaviour (End.M.GTP4.E vs End.M.GTP6.E) in the
    function bits, so per-AFI / per-slice locator partitioning is
    operationally meaningful."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # IPv6 ISD must be anchored under loc-mup-v6 (2001:db8:f::/48).
    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv6 mup all detail-routes",
                 "Remote SID: 2001:db8:f:")
        else "IPv6 ISD SID must fall inside loc-mup-v6 (2001:db8:f::/48)",
        "IPv6 ISD anchored under loc-mup-v6",
    )

    # IPv4 ISD must stay under the bgp default locator
    # (2001:db8:e::/48), confirming the override is per-AFI.
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
    10.99.0.5 (draft §3.3.9 + RFC 9433 §6.6).  r2 is a pure
    receive-only PE — it has no `segment` line, only a
    `route-target import 65001:1` under `address-family ipv4 mup` of
    the slice1 vrf instance.  Resolution is order-independent:
    bgp_mup_isd_cache_upsert() retries any T1ST already in the RIB."""
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
    """T1ST 192.168.2.5/32 has endpoint 10.123.0.5 with no covering ISD;
    r2 must NOT install a FIB route for it (in either default vrf or
    vrf slice1)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    # Wait long enough that the resolution path would have completed
    # if it were going to.
    time.sleep(5)
    assert not _route_via_bgp(r2, "192.168.2.5/32"), (
        "T1ST without a covering ISD must not install a route"
    )
    assert not _route_via_bgp(r2, "192.168.2.5/32", vrf="slice1"), (
        "T1ST without a covering ISD must not install a route in slice1"
    )


def test_t2st_resolved_via_dsd_cache():
    """r2 must install an H.M.GTP4.D seg6local route for 10.0.0.250/32
    in vrf slice1 once r1's DSD with MUP-EC 65001:10 is in the cache
    (draft §3.3.12)."""
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
    r2 must NOT install a FIB route for it (in either default vrf or
    vrf slice1)."""
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
    """Two-VRF receive-side selection regression:
    r2 carries slice1 (rt mup import 65001:1) and slice2
    (rt mup import 65001:2).  The T2ST 10.0.0.250 from peer1 carries
    RT 65001:1, so it must install only in slice1 — never in slice2,
    never in the default vrf.  Mirrors L3VPN's
    vpn_leak_to_vrf_update_onevrf rtlist[FROMVPN] match per
    bgp_mplsvpn.c."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # slice1 install: RT-1 matches.
    _wait_for(
        r2,
        lambda r: None
        if _route_via_bgp(r, "10.0.0.250/32", vrf="slice1")
        else "expected T2ST 10.0.0.250/32 in vrf slice1",
        "T2ST 10.0.0.250/32 in slice1",
    )

    # slice2 must not see it — RT-1 is not in slice2's import list.
    time.sleep(5)
    assert not _route_via_bgp(r2, "10.0.0.250/32", vrf="slice2"), (
        "T2ST RT 65001:1 must not install in slice2 (slice2 only "
        "imports 65001:2)"
    )
    assert not _route_via_bgp(r2, "10.0.0.250/32"), (
        "T2ST must not install in default vrf"
    )


def test_route_map_mup_export_filter():
    """`route-map mup export RMAP` filters which VRF unicast prefixes
    leak as ISD NLRIs.  Mirrors L3VPN's `route-map vpn export` —
    `bgp_mplsvpn.c:vpn_leak_from_vrf_update` runs the per-direction
    rmap before the emit; MUP's parallel hook is in
    `bgp_mup.c:mup_leak_from_vrf_update`.

    Phase 1 covers the export side only; the import slot of the same
    DEFPY stores state but does not yet apply (Phase 2)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Add a second connected prefix into slice1.  redistribute connected
    # leaks both into BGP unicast, and (until the rmap below kicks in)
    # both reach r2 as ISD NLRIs.
    r1.run("ip addr add 10.99.99.1/24 dev lo-slice1")

    _wait_for(
        r2,
        lambda r: None
        if _grep(r, "show bgp ipv4 mup all", "10.99.99.0/24")
        else "expected 10.99.99.0/24 ISD on r2 before rmap is applied",
        "baseline: 10.99.99.0/24 leaked",
    )

    # Configure a route-map permitting only 10.99.0.0/24, then attach
    # it to slice1's ipv4 unicast AF as the export rmap.  10.99.99.0/24
    # must drop out of r2's MUP RIB; 10.99.0.0/24 stays.
    r1.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list N3-PFX seq 10 permit 10.99.0.0/24\n"
        "route-map N3-ONLY permit 10\n"
        " match ip address prefix-list N3-PFX\n"
        "exit\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 unicast\n"
        "  route-map mup export N3-ONLY\n"
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

    # `show running-config` must round-trip the rmap line.
    output = r1.vtysh_cmd("show running-config")
    assert "route-map mup export N3-ONLY" in output, (
        "running-config missing route-map mup export line\n--- output ---\n"
        + output
    )

    # Detach the rmap; 10.99.99.0/24 must reappear on r2.
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 unicast\n"
        "  no route-map mup export N3-ONLY\n"
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

    # Cleanup helper state so downstream tests aren't perturbed.
    r1.run("ip addr del 10.99.99.1/24 dev lo-slice1")
    r1.vtysh_cmd(
        "configure terminal\n"
        "no route-map N3-ONLY permit 10\n"
        "no ip prefix-list N3-PFX\n"
        "exit\n"
    )


def test_no_segment_removes_route():
    """`no segment mup export direct` must withdraw the DSD from both
    r1 and r2 RIBs, drop the line from running-config, AND cause r2 to
    remove the matching T2ST FIB route once the DSD cache loses its
    entry."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001 vrf slice1\n"
        " address-family ipv4 unicast\n"
        "  no segment mup export direct\n"
        " exit-address-family\n"
        "exit\n"
    )

    # Match the DSD NLRI form `[2]:[12]:[10.0.0.250]` specifically — the
    # T2ST received from peer1 also contains "10.0.0.250" in its NLRI
    # (route_type 4: `[4]:[17]:[64/10.0.0.250]`), so a bare substring
    # match would still hit even after the DSD is gone.
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
    assert "segment mup export direct" not in output, (
        "running-config still contains the withdrawn DSD enable line"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
