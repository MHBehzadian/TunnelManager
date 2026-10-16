"""What keeps a panel pointed at live servers from disturbing them."""

from __future__ import annotations

from tests.conftest import FakeDNS
from tunnelmanager.backpack import check_script, listen_ports, parse_listening, parse_scan
from tunnelmanager.models import L_DEGRADED, L_DOWN, L_PENDING, L_UP, Link, Settings



def test_fresh_settings_are_safe():
    s = Settings()
    assert s.observe_only is True
    assert s.auto_mesh is False


async def test_observe_mode_reports_but_changes_nothing(world):
    w = world
    w.net.plant(w.i1, w.k1, "a", "tcpmux", 4000, ["443"])
    w.net.plant(w.i2, w.k1, "b", "wsmux", 4000, ["443"])
    w.store.settings.auto_mesh = False
    w.store.links.clear()
    await w.orch.check_all()
    await w.settle(1)
    w.store.settings.observe_only = True
    a = next(x for x in w.store.links.values() if x.iran_name == "a")
    # the record already pointed at I1: adopted without touching DNS
    w.dom.current_ip, w.dom.link_id = w.i1.ip, ""
    FakeDNS.calls.clear()
    await w.settle(1)
    assert w.dom.link_id == a.id and FakeDNS.calls == []

    calls_before = list(w.net.calls)
    w.net.block(w.i1, w.k1, "tcpmux")
    await w.settle(4)
    assert a.status == L_DOWN
    assert FakeDNS.calls == []  # no DNS change
    assert w.net.calls == calls_before  # no deploy, no restart, no rewrite
    assert w.dom.link_id == a.id
    proposals = [n for n in w.notes if "حالت نظارت" in n]
    assert len(proposals) == 1 and "تغییر می‌کرد" in proposals[0]
    # it heals by itself: reported once more, still nothing changed
    w.net.blocked.clear()
    await w.settle(2)
    assert a.status == L_UP and w.said("دوباره سالم است")
    assert FakeDNS.calls == [] and w.net.calls == calls_before


async def test_observe_mode_never_points_a_record_somewhere_new(world):
    w = world
    w.store.settings.observe_only = True
    await w.orch.check_all()
    for x in w.store.links.values():  # pretend they were all running
        x.status, x.transport, x.built = L_UP, "tcpmux", True
        w.net.deployed[x.id] = "tcpmux"
    w.dom.current_ip = "203.0.113.9"  # an IP the panel does not know
    await w.settle(2)
    assert FakeDNS.calls == []
    assert w.said("رکورد دست نخورد")


async def test_only_running_tunnels_are_adopted_and_their_units_kept(world):
    w = world
    w.net.plant(w.i1, w.k1, "live", "tcpmux", 4000, ["443"], unit="my-tunnel.service")
    w.net.plant(w.i2, w.k1, "old", "tcp", 4001, ["443"], active="inactive")
    await w.orch.check_all()
    adopted = {x.iran_name: x for x in w.store.links.values() if not x.managed}
    assert set(adopted) == {"live"}  # a stopped config is left alone
    assert adopted["live"].iran_unit == "my-tunnel.service" and adopted["live"].built
    assert "systemctl is-active my-tunnel.service" in check_script([adopted["live"]])


async def test_new_tunnel_is_not_built_on_a_port_already_in_use(world):
    w = world
    await w.orch.check_all()
    link = w.link(w.i1, w.k1)
    w.net.listen[w.i1.id] = {443}  # e.g. nginx, or another tunnel
    ok = await w.orch.discover(link)
    assert not ok and link.status == L_PENDING
    assert "443" in link.error
    assert not any(c[0] == "deploy" and c[1] == link.id for c in w.net.calls)
    assert w.said("ساخته نشد")


async def test_bulk_build_never_touches_working_or_wobbling_tunnels(world):
    w = world
    await w.orch.check_all()
    await w.orch.discover_all()
    a, b = w.link(w.i1, w.k1), w.link(w.i2, w.k1)
    a.status = L_DEGRADED
    w.net.calls.clear()
    await w.orch.discover_all()
    assert not any(c[1] in (a.id, b.id) for c in w.net.calls)


def test_scan_reads_the_unit_that_runs_each_config():
    out = """@@FILE t1 custom-name.service active
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcp"
@@FILE t2 - -
[client]
remote_addr = "1.2.3.4:3080"
transport = "tcp"
@@END
"""
    f1, f2 = parse_scan(out)
    assert (f1.unit, f1.active) == ("custom-name.service", "active")
    assert (f2.unit, f2.active) == ("", "")


def test_listening_parsers():
    out = "01BB\n0050\n\nlocal_address\n1F90\n"
    assert parse_listening(out) == {443, 80, 8080}
    assert listen_ports(["443", "8443=2096", "1.2.3.4:2053-2055=2053-2055", "127.0.0.1:61000=22"]) == {443, 8443, 2053, 2054, 2055, 61000}


def test_link_model_defaults():
    x = Link(iran_id="i", kharej_id="k", tunnel_port=1)
    assert x.built is False and x.iran_unit == ""
