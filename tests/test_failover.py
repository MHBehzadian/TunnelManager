from __future__ import annotations

import pytest

from tests.conftest import FakeDNS
from tunnelmanager.models import L_DOWN, L_UP, OFFLINE, ONLINE

pytestmark = pytest.mark.asyncio


async def connected(w):
    await w.orch.check_all()  # servers online
    await w.orch.discover_all()
    await w.settle(1)


async def test_discover_picks_fastest_working_transport(world):
    w = world
    w.net.block(w.i1, w.k1, "tcp")  # the fastest one is filtered on this pair
    await connected(w)
    assert w.link(w.i1, w.k1).transport == "tcpmux"  # 40ms, next best
    assert w.link(w.i2, w.k1).transport == "tcp"  # 35ms
    assert all(x.status == L_UP for x in w.store.links.values())
    assert w.link(w.i1, w.k1).tests["tcp"]["ok"] is False
    # the final deploy carries the Iran-side forwarded ports
    assert w.net.iran_ports[w.link(w.i1, w.k1).id] == ["443", "8443=2096"]
    # the domain had no tunnel yet: it gets the primary one
    assert w.dom.link_id == w.link(w.i1, w.k1).id
    assert FakeDNS.records["a.example.ir"] == w.i1.ip


async def test_down_tunnel_switches_dns_first_then_repairs_then_fails_back(world):
    w = world
    await connected(w)
    primary = w.link(w.i1, w.k1)
    first = primary.transport
    w.net.block(w.i1, w.k1, first)  # DPI starts killing it
    await w.settle(2)
    # the standby on the second Iran server takes over right away
    assert w.dom.link_id == w.link(w.i2, w.k1).id
    assert FakeDNS.records["a.example.ir"] == w.i2.ip
    assert w.said("رکورد a.example.ir از I1")
    # meanwhile the broken tunnel was rebuilt on another transport
    assert primary.status == L_UP and primary.transport != first
    assert w.said("دوباره برقرار شد")
    # it is not trusted yet: no failback before it has been stable for 10 minutes
    await w.settle(2)
    assert w.dom.link_id == w.link(w.i2, w.k1).id
    w.age(601)
    await w.settle(1)
    assert w.dom.link_id == primary.id
    assert FakeDNS.records["a.example.ir"] == w.i1.ip
    assert w.said("برگشت به سرور اصلی")


async def test_iran_down_moves_domain_and_reports_each_step(world):
    w = world
    await connected(w)
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.i1.status == OFFLINE
    assert w.dom.link_id == w.link(w.i2, w.k1).id
    assert w.said("سرور داخل I1 (10.0.2.1) به مشکل خورد")
    assert w.said("I1 در دسترس نیست")
    # propagation: the resolvers catch up -> "server 2 is behind the domain"
    assert w.dom.pending_ip == w.i2.ip
    w.answers["a.example.ir"] = [w.i2.ip]
    await w.settle(1)
    assert w.dom.pending_ip == ""
    assert w.said("پشت دامنه a.example.ir قرار گرفت")
    # I1 comes back: reported, but traffic stays put until it proves stable
    w.net.dead.discard(w.i1.id)
    await w.settle(2)
    assert w.i1.status == ONLINE and w.said("دوباره در دسترس است")
    assert w.dom.link_id == w.link(w.i2, w.k1).id
    w.age(601)
    await w.settle(1)
    assert w.dom.link_id == w.link(w.i1, w.k1).id


async def test_flapping_primary_is_abandoned_even_if_never_fully_down(world):
    w = world
    await connected(w)
    w.store.settings.fail_threshold = 5  # each drop is too short to count as "down"
    key = (w.i1.id, w.k1.id, w.link(w.i1, w.k1).transport)
    for _ in range(3):
        w.net.blocked.add(key)
        await w.settle(1)
        w.net.blocked.discard(key)
        await w.settle(1)
    assert w.link(w.i1, w.k1).status == L_UP  # it is up right now...
    assert w.dom.link_id == w.link(w.i2, w.k1).id  # ...but not trusted
    assert w.said("مدام قطع و وصل می‌شود")
    # stable for the window again -> traffic returns
    w.age(700)
    await w.settle(1)
    assert w.dom.link_id == w.link(w.i1, w.k1).id


async def test_no_switch_without_reason(world):
    w = world
    await connected(w)
    calls = len(FakeDNS.calls)
    link = w.link(w.i1, w.k1)
    key = (w.i1.id, w.k1.id, link.transport)
    w.net.blocked.add(key)  # one dropped check
    await w.settle(1)
    w.net.blocked.discard(key)
    await w.settle(3)
    assert len(FakeDNS.calls) == calls
    assert w.dom.link_id == link.id


async def test_kharej_down_hands_ports_over_on_same_iran(world):
    w = world
    await connected(w)
    dns_calls = len(FakeDNS.calls)
    w.net.dead.add(w.k1.id)
    await w.settle(3)
    a, b = w.link(w.i1, w.k1), w.link(w.i1, w.k2)
    assert w.k1.status == OFFLINE
    assert w.store.handover == {a.id: b.id}
    # the Iran side of K2's tunnel now exposes K1's ports too; A's are freed
    assert w.net.iran_ports[b.id] == ["2053", "443", "8443=2096"]
    assert w.net.iran_ports[a.id] == []
    assert w.dom.link_id == a.id and w.dom.status == "ok"
    assert len(FakeDNS.calls) == dns_calls  # the record did not move
    assert w.said("به تانل K2 ⇄ I1 منتقل شد")
    # K1 back: ports return only after it has been stable
    w.net.dead.discard(w.k1.id)
    await w.settle(3)
    assert a.status == L_UP and w.store.handover
    w.age(601)
    await w.settle(1)
    assert w.store.handover == {}
    assert w.net.iran_ports[b.id] == ["2053"]
    assert w.net.iran_ports[a.id] == ["443", "8443=2096"]


async def test_explicit_group_is_respected(world):
    w = world
    await connected(w)
    a, c = w.link(w.i1, w.k1), w.link(w.i2, w.k2)
    w.dom.group = [a.id, c.id]  # only these two, in this order
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.link_id == c.id  # not I2-K1, which is outside the group


async def test_pinned_transport_never_changes(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    assert await w.orch.set_transport(link, "wsmux", pin=True)
    w.net.block(w.i1, w.k1, "wsmux")
    await w.settle(3)
    assert link.transport == "wsmux"
    assert w.dom.link_id == w.link(w.i2, w.k1).id


async def test_dns_failure_is_reported_and_retried(world):
    w = world
    await connected(w)
    FakeDNS.fail = True
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.link_id == w.link(w.i1, w.k1).id
    assert w.said("ناموفق بود")
    FakeDNS.fail = False
    await w.settle(1)
    assert w.dom.link_id == w.link(w.i2, w.k1).id


async def test_no_path_anywhere_marks_domain_broken(world):
    w = world
    await connected(w)
    w.net.dead.update({w.i1.id, w.i2.id})
    await w.settle(3)
    assert w.dom.status == "broken"
    assert w.said("هیچ تانل سالمی")


async def test_existing_tunnels_are_adopted(world):
    w = world
    w.net.plant(w.i1, w.k1, "my-tunnel", "wsmux", 4000, ["443", "2096=2096"], token="t0k")
    await w.orch.check_all()
    adopted = [x for x in w.store.links.values() if not x.managed]
    assert len(adopted) == 1
    x = adopted[0]
    assert (x.iran_name, x.kharej_name, x.transport, x.tunnel_port, x.token) == ("my-tunnel", "my-tunnel", "wsmux", 4000, "t0k")
    assert x.ports == ["443", "2096=2096"]
    assert x.iran_base["mux_con"] == 8  # its other settings are kept
    # the placeholder the panel offered for that pair is gone
    assert w.store.links_between(w.i1.id, w.k1.id) == [x]
    assert w.said("تانل موجود «my-tunnel»")
    await w.settle(1)
    assert x.status == L_UP
    # the domain uses it: it is the tunnel to its kharej on the preferred Iran server
    assert w.dom.link_id == x.id
    # scanning again does not duplicate it
    w.orch.last_scan = 0
    await w.orch.check_all()
    assert len([y for y in w.store.links.values() if not y.managed]) == 1


async def test_repair_rewrites_adopted_tunnel_with_a_probe(world):
    w = world
    w.net.plant(w.i1, w.k1, "my-tunnel", "tcp", 4000, ["443"])
    await w.orch.check_all()
    x = next(y for y in w.store.links.values() if not y.managed)
    assert x.probe_port == 0
    w.net.block(w.i1, w.k1, "tcp")
    await w.settle(3)
    assert x.status == L_UP and x.transport != "tcp"
    assert x.probe_port >= 61000  # health is now checked end to end
    assert x.iran_name == "my-tunnel"  # still the user's own tunnel
    assert x.status != L_DOWN


async def test_unbuilt_placeholder_is_never_the_primary(world):
    w = world
    w.net.plant(w.i2, w.k1, "only-one", "tcpmux", 4000, ["443"])
    await w.orch.check_all()
    await w.settle(1)
    # I1-K1 exists only as an offer (not built): the built tunnel on I2 is primary
    assert w.link(w.i1, w.k1).status == "pending"
    assert w.store.primary_of(w.dom).iran_name == "only-one"
    assert w.dom.link_id == w.store.primary_of(w.dom).id
