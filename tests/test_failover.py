from __future__ import annotations

import pytest

from tunnelmanager.models import L_DOWN, L_SUSPENDED, L_UP, ONLINE, OFFLINE

pytestmark = pytest.mark.asyncio


async def connected(world):
    await world.orch.check_all()  # servers online
    await world.orch.discover_all()
    await world.settle(1)


async def test_discover_picks_fastest_working_transport(world):
    w = world
    w.net.block(w.i1, w.k1, "tcp")  # fastest one is filtered on this pair
    await connected(w)
    assert w.link(w.i1, w.k1).transport == "tcpmux"  # 40ms, next best
    assert w.link(w.i2, w.k1).transport == "tcp"  # 35ms
    assert all(x.status == L_UP for x in w.store.links.values())
    assert w.link(w.i1, w.k1).tests["tcp"]["ok"] is False
    # final deploy carries the kharej's forwarded ports
    assert w.net.iran_ports[w.link(w.i1, w.k1).id] == ["443", "8443=2096"]
    # the domain had no Iran server yet: it gets the preferred one
    assert w.dom.iran_id == w.i1.id
    assert ("a.example.com", w.i1.ip) in __import__("tests.conftest", fromlist=["FakeDNS"]).FakeDNS.calls


async def test_link_down_repairs_with_other_transport(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    first = link.transport
    w.net.block(w.i1, w.k1, first)  # DPI starts killing it
    await w.settle(3)
    assert link.status == L_UP
    assert link.transport != first
    assert w.dom.iran_id == w.i1.id  # no DNS move needed
    assert any("دوباره برقرار شد" in n for n in w.notes)


async def test_unrepairable_link_moves_domain_to_other_iran(world):
    w = world
    await connected(w)
    w.net.block(w.i1, w.k1, "tcpmux", "wsmux", "tcp", "quic")
    await w.settle(3)
    assert w.link(w.i1, w.k1).status == L_DOWN
    assert w.dom.iran_id == w.i2.id
    from tests.conftest import FakeDNS

    assert FakeDNS.records["a.example.com"] == w.i2.ip
    assert any("هیچ پروتکلی" in n for n in w.notes)
    assert any("تغییر کرد" in n for n in w.notes)


async def test_iran_down_moves_domain(world):
    w = world
    await connected(w)
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.i1.status == OFFLINE
    assert w.dom.iran_id == w.i2.id


async def test_kharej_down_takes_over_instead_of_moving_dns(world):
    w = world
    await connected(w)
    from tests.conftest import FakeDNS

    dns_calls = len(FakeDNS.calls)
    w.net.dead.add(w.k1.id)
    await w.settle(3)
    assert w.k1.status == OFFLINE
    assert w.store.takeover == {w.k1.id: w.k2.id}
    assert w.store.effective_kharej(w.k1.id) == w.k2.id
    # the Iran side of K2's tunnel now exposes K1's ports too
    ports = w.net.iran_ports[w.link(w.i1, w.k2).id]
    assert ports == ["2053", "443", "8443=2096"]
    assert w.link(w.i1, w.k1).status == L_SUSPENDED
    # domain keeps its Iran server: only the kharej changed
    assert w.dom.iran_id == w.i1.id
    assert w.dom.status == "ok"
    assert len(FakeDNS.calls) == dns_calls

    # K1 comes back: not immediately (flap guard)...
    w.net.dead.discard(w.k1.id)
    await w.settle(1)
    assert w.store.takeover == {w.k1.id: w.k2.id}
    # ...but once it has stayed up: ports go home, its tunnels are rebuilt
    w.orch.takeover_at[w.k1.id] -= 3600
    await w.settle(3)
    assert w.k1.status == ONLINE
    assert w.store.takeover == {}
    assert w.net.iran_ports[w.link(w.i1, w.k2).id] == ["2053"]
    assert w.link(w.i1, w.k1).status == L_UP


async def test_kharej_unreachable_but_tunnels_up_is_not_taken_over(world):
    """SSH from the panel to a kharej can fail while its tunnels still carry
    traffic (e.g. a firewall on the SSH port). That is not a dead kharej."""
    w = world
    await connected(w)
    real_ping = w.net.ping

    async def ping(s):
        if s.id == w.k1.id:
            from tunnelmanager.ssh import SSHError

            raise SSHError("ssh filtered")
        return await real_ping(s)

    w.net.ping = ping
    await w.settle(3)
    assert w.store.takeover == {}
    assert w.link(w.i1, w.k1).status == L_UP


async def test_pinned_link_is_only_restarted(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    ok = await w.orch.set_transport(link, "wsmux", pin=True)
    assert ok and link.transport == "wsmux" and link.pinned
    w.net.block(w.i1, w.k1, "wsmux")
    await w.settle(3)
    assert link.transport == "wsmux"  # never swapped behind the user's back
    assert w.dom.iran_id == w.i2.id  # but the domain still fails over


async def test_dns_failure_is_reported_and_retried(world):
    w = world
    await connected(w)
    from tests.conftest import FakeDNS

    FakeDNS.fail = True
    w.net.dead.add(w.i1.id)
    await w.settle(3)
    assert w.dom.iran_id == w.i1.id
    assert any("ناموفق" in n for n in w.notes)
    FakeDNS.fail = False
    await w.settle(1)
    assert w.dom.iran_id == w.i2.id


async def test_no_path_anywhere_marks_domain_broken(world):
    w = world
    await connected(w)
    w.net.dead.update({w.i1.id, w.i2.id})
    await w.settle(3)
    assert w.dom.status == "broken"
    assert any("هیچ سرور داخلی" in n for n in w.notes)
