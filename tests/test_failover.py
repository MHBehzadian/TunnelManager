from __future__ import annotations

from tests.conftest import FakeDNS
from tunnelmanager.models import L_DOWN, L_UP, OFFLINE, ONLINE


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
    # the record already pointed at I1: adopted as is, with the ports served there
    assert w.dom.iran_id == w.i1.id and w.dom.ports == ["443", "8443=2096"]
    assert FakeDNS.calls == []


async def test_down_tunnel_switches_dns_first_then_repairs_then_fails_back(world):
    w = world
    await connected(w)
    primary = w.link(w.i1, w.k1)
    first = primary.transport
    w.net.block(w.i1, w.k1, first)  # DPI starts killing it
    await w.settle(2)
    # the standby on the second Iran server takes over right away
    assert w.dom.iran_id == w.i2.id
    assert FakeDNS.records["a.example.ir"] == w.i2.ip
    assert w.said("رکورد a.example.ir از I1")
    # meanwhile the broken tunnel was rebuilt on another transport
    assert primary.status == L_UP and primary.transport != first
    assert w.said("دوباره برقرار شد")
    # not trusted yet: no failback before 10 minutes of stability
    await w.settle(2)
    assert w.dom.iran_id == w.i2.id
    w.age(601)
    await w.settle(1)
    assert w.dom.iran_id == w.i1.id
    assert FakeDNS.records["a.example.ir"] == w.i1.ip
    assert w.said("برگشت به سرور اصلی")


async def test_iran_down_moves_domain_and_reports_each_step(world):
    w = world
    await connected(w)
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.i1.status == OFFLINE
    assert w.dom.iran_id == w.i2.id
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
    assert w.dom.iran_id == w.i2.id
    w.age(601)
    await w.settle(1)
    assert w.dom.iran_id == w.i1.id


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
    assert w.link(w.i1, w.k1).status == L_UP  # up right now...
    assert w.dom.iran_id == w.i2.id  # ...but not trusted
    assert w.said("مدام قطع و وصل می‌شود")
    w.age(700)
    await w.settle(1)
    assert w.dom.iran_id == w.i1.id


async def test_no_switch_without_reason(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    key = (w.i1.id, w.k1.id, link.transport)
    w.net.blocked.add(key)  # one dropped check
    await w.settle(1)
    w.net.blocked.discard(key)
    await w.settle(3)
    assert FakeDNS.calls == []
    assert w.dom.iran_id == w.i1.id


async def test_kharej_down_hands_ports_over_on_same_iran(world):
    w = world
    await connected(w)
    w.net.dead.add(w.k1.id)
    await w.settle(3)
    a, b = w.link(w.i1, w.k1), w.link(w.i1, w.k2)
    assert w.k1.status == OFFLINE
    assert w.store.handover == {a.id: b.id}
    # the Iran side of K2's tunnel now exposes K1's ports too; A's are freed
    assert w.net.iran_ports[b.id] == ["2053", "443", "8443=2096"]
    assert w.net.iran_ports[a.id] == []
    assert w.dom.iran_id == w.i1.id and w.dom.status == "ok"
    assert FakeDNS.calls == []  # the record did not move
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


async def test_one_domain_ports_to_different_kharejs(world):
    """443 goes to K1 and 2053 to K2, both through I1. DNS may only move to an
    Iran server that carries *both* ports."""
    w = world
    await connected(w)
    w.dom.kharej_id, w.dom.ports = "", ["443", "2053"]
    await w.settle(1)
    info = w.orch.domain_info(w.dom)
    assert [(r["spec"], r["kharej_id"]) for r in info["routes"]] == [("443", w.k1.id), ("2053", w.k2.id)]
    assert w.dom.status == "ok"

    # the K2 path from I1 breaks: I2 carries 443 (K1) and 2053 (K2) -> move there
    w.net.block(w.i1, w.k2, "tcpmux", "wsmux", "tcp", "quic")
    await w.settle(3)
    assert w.dom.iran_id == w.i2.id
    assert w.said("443→K1، 2053→K2")


async def test_no_move_to_a_server_missing_one_of_the_ports(world):
    w = world
    await connected(w)
    w.dom.kharej_id, w.dom.ports = "", ["443", "2053"]
    # I2 has no tunnel to K2 at all (and none may be built): it could only carry 443
    w.store.settings.auto_mesh = False
    w.store.remove_link(w.link(w.i2, w.k2).id)
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.iran_id == w.i1.id  # moving would break port 2053 for everyone
    assert FakeDNS.calls == []
    assert w.dom.status == "broken"
    assert w.said("همه پورت‌هایش (443, 2053)")


async def test_dead_kharej_on_one_port_only_moves_that_port(world):
    w = world
    await connected(w)
    w.dom.kharej_id, w.dom.ports = "", ["443", "2053"]
    w.net.dead.add(w.k2.id)
    await w.settle(3)
    # 2053's kharej is gone: its port moves to K1's tunnel on the same Iran server
    a, b = w.link(w.i1, w.k1), w.link(w.i1, w.k2)
    assert w.store.handover == {b.id: a.id}
    assert w.dom.iran_id == w.i1.id and FakeDNS.calls == []


async def test_explicit_group_is_respected(world):
    w = world
    await connected(w)
    a, b = w.link(w.i1, w.k1), w.link(w.i2, w.k1)
    w.dom.group = [a.id]  # only I1: never move elsewhere
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.iran_id == w.i1.id and FakeDNS.calls == []
    w.dom.group = [a.id, b.id]
    await w.settle(1)
    assert w.dom.iran_id == w.i2.id


async def test_pinned_transport_never_changes(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    assert await w.orch.set_transport(link, "wsmux", pin=True)
    w.net.block(w.i1, w.k1, "wsmux")
    await w.settle(3)
    assert link.transport == "wsmux"
    assert w.dom.iran_id == w.i2.id


async def test_dns_failure_is_reported_and_retried(world):
    w = world
    await connected(w)
    FakeDNS.fail = True
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.iran_id == w.i1.id
    assert w.said("ناموفق بود")
    FakeDNS.fail = False
    await w.settle(1)
    assert w.dom.iran_id == w.i2.id


async def test_no_path_anywhere_marks_domain_broken(world):
    w = world
    await connected(w)
    w.net.dead.update({w.i1.id, w.i2.id})
    await w.settle(3)
    assert w.dom.status == "broken"
    assert w.said("رکورد تغییر نکرد")


async def test_unknown_record_ip_is_left_alone(world):
    w = world
    w.dom.current_ip = "203.0.113.7"
    await connected(w)
    await w.settle(1)
    assert w.dom.iran_id == "" and FakeDNS.calls == []
    assert w.said("هیچ‌کدام از سرورهای داخل ثبت‌شده نیست")


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
    assert w.store.links_between(w.i1.id, w.k1.id) == [x]  # the placeholder is gone
    assert w.said("تانل موجود «my-tunnel»")
    await w.settle(1)
    assert x.status == L_UP
    assert w.dom.iran_id == w.i1.id and w.dom.ports == ["443", "2096=2096"]
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
    w.dom.current_ip = w.i2.ip
    await w.orch.check_all()
    await w.settle(1)
    assert w.link(w.i1, w.k1).status == "pending"
    assert w.store.primary_of(w.dom).iran_name == "only-one"
    assert w.store.iran_order(w.dom) == [w.i2.id]


async def test_missing_port_gets_its_tunnel_built_then_domain_moves(world):
    w = world
    await connected(w)
    w.dom.kharej_id, w.dom.ports = "", ["443", "2053"]
    w.store.remove_link(w.link(w.i2, w.k2).id)  # auto_mesh offers it again
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    # the panel built I2-K2 first, and only then moved: both ports work on I2
    assert w.link(w.i2, w.k2).status == L_UP
    assert w.dom.iran_id == w.i2.id


async def test_primary_is_where_the_record_pointed_not_the_priority(world):
    """Equal priorities sort by name: that must never pull a domain away from
    the Iran server it already uses."""
    w = world
    w.i1.priority = w.i2.priority = 100
    w.i1.name, w.i2.name = "B-tehran", "A-shiraz"  # A sorts first
    await connected(w)
    assert w.dom.iran_id == w.i1.id and w.dom.primary_iran == w.i1.id
    w.age(3600)
    await w.settle(2)
    assert w.dom.iran_id == w.i1.id and FakeDNS.calls == []
    # an outage still fails over to the backup, and failback returns to the primary
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.iran_id == w.i2.id
    w.net.dead.discard(w.i1.id)
    await w.settle(2)
    w.age(601)
    await w.settle(1)
    assert w.dom.iran_id == w.i1.id
