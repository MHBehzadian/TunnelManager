"""What the panel learns beyond "is the tunnel up": users being turned away,
memory running out, the two ends on different releases, two tunnels fighting
over a port, and whether a downloaded release is the publisher's."""

from __future__ import annotations

import time

from tests.conftest import FakeNet
from tunnelmanager.backpack import parse_check, parse_host, verify_release
from tunnelmanager.models import IRAN, KHAREJ, L_DOWN, L_UP, Link, Server
from tunnelmanager.store import Store


async def connected(w):
    await w.orch.check_all()
    await w.orch.discover_all()
    await w.settle(1)


def host(avail=3000, total=5900, swap=4096, swap_free=4000, version="v2.0.0", ooms=()):
    return {"cpus": 4, "load": [1.0, 1.0, 1.0], "mem_total": total, "mem_avail": avail,
            "swap_total": swap, "swap_free": swap_free, "version": version, "ooms": list(ooms)}


# ------------------------------------------------------------------ parsing
def test_check_line_carries_turned_away_users():
    p = parse_check("@@a|active|true|1|4210|5|180\n@@b|active|true|1|4210|5\n")
    assert p["a"].ok and p["a"].dropped == 180
    assert p["b"].dropped == 0  # a line from an older script still parses
    bare = Link(iran_id="i", kharej_id="k", tunnel_port=1, transport="stealth", id="c")
    p = parse_check("@@c|active|true|-|0|4704|37\n", {"c": bare})
    assert p["c"].ok and not p["c"].verified and p["c"].dropped == 37


def test_host_report_parses_memory_and_oom_kills():
    out = """@@CPU 4
@@LOAD 3.17 3.75 3.96
MemTotal:        6081200 kB
MemAvailable:    2202008 kB
SwapTotal:             0 kB
SwapFree:              0 kB
@@BP v1.8.5
@@OOM
1795584979.123456 NexraIR kernel: Out of memory: Killed process 1027280 (backpack) total-vm:4406804kB, anon-rss:3107416kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:6284kB oom_score_adj:0
1795588885.000001 NexraIR kernel: Out of memory: Killed process 2166775 (xray) total-vm:2479620kB, anon-rss:1288660kB, file-rss:0kB
@@END
"""
    h = parse_host(out)
    assert h["cpus"] == 4 and h["load"] == [3.17, 3.75, 3.96]
    assert h["mem_total"] == 5939 and h["mem_avail"] == 2150 and h["swap_total"] == 0
    assert h["version"] == "v1.8.5"
    assert h["ooms"] == [
        {"ts": 1795584979, "pid": 1027280, "proc": "backpack", "rss_mb": 3035},
        {"ts": 1795588885, "pid": 2166775, "proc": "xray", "rss_mb": 1258},
    ]
    assert parse_host("") == {"ooms": []}  # a server that answered nothing useful


# ------------------------------------------------------------- the release
# github.com/AminMGMT/BackPack/releases/download/v1.8.5/SHA256SUMS and .sig
SUMS_185 = b"""6a0d2511f46e9c5726e6ce41768de6c15974d194c17211ddea5d70653201cc96  backpack_linux_386.tar.gz
e80c4da9bdcece9e7a82305e572fdfde9a395a68a985fdd835c1af8ff248b395  backpack_linux_amd64.tar.gz
9d9eaa951f8bd3f7b786be94916517c4ec900af0eeaac893b89d03d9867643f4  backpack_linux_arm64.tar.gz
1b224f8a7d1cf556b95aa119cf487bc602e942a16dd9a7b4386b367c22e832ea  backpack_linux_armv5.tar.gz
8d11df95a23e4ed4d49e3febe8ba3cbb6397a205856a546ae9642d6800dad973  backpack_linux_armv6.tar.gz
add4de9951d0ec2d4dfd92f8837f84c9c70f8607b106231b9c54eb9632c4504c  backpack_linux_armv7.tar.gz
c7afb84106a8b4f68f5bcd9bf0dd86edc4dea23e43942a4b7d8b619a9ba69492  backpack_linux_s390x.tar.gz
"""
SIG_185 = b"d/HVCCdAdmMNVUO2ff7019/aPbbDwSCsfcQ5bUD9ORE3/MR4/JztFC6FzHg45JlH5k8FGPF05bg0uVh6/gbQCw==\n"


def test_release_signature_is_checked_for_its_own_tag():
    assert verify_release("v1.8.5", SUMS_185, SIG_185)
    # a genuine older release served under a newer tag is a downgrade
    assert not verify_release("v2.0.0", SUMS_185, SIG_185)
    # one swapped archive and the list no longer matches its signature
    assert not verify_release("v1.8.5", SUMS_185.replace(b"e80c4d", b"e80c4e"), SIG_185)
    assert not verify_release("v1.8.5", SUMS_185, b"not a signature")
    assert not verify_release("v1.8.5", SUMS_185, b"")


# ------------------------------------------------------- turned-away users
async def test_tunnel_that_keeps_turning_users_away_counts_as_down_and_is_restarted(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    first = link.transport
    w.store.settings.observe_only = True  # look first: no repair yet
    w.net.drops[link.id] = 400  # connected, probe fine, but the queue is full
    await w.settle(2)
    assert link.status == L_DOWN and link.dropped == 400
    assert "turning users away: 400" in link.error
    assert w.said("قطع شد")
    # a stuck engine needs a restart, not another transport: the current one goes first
    w.net.drops[link.id] = 0
    w.store.settings.observe_only = False
    w.net.calls.clear()
    assert await w.orch.repair(link)
    assert w.net.calls[0][:3] == ("deploy", link.id, first)
    assert link.status == L_UP and link.transport == first


async def test_a_few_dropped_users_are_not_an_outage(world):
    w = world
    await connected(w)
    link = w.link(w.i1, w.k1)
    w.net.drops[link.id] = 5
    await w.settle(2)
    assert link.status == L_UP and link.dropped == 5


# ------------------------------------------------------------------ hosts
async def test_oom_kills_and_low_memory_are_reported_once(world):
    w = world
    await connected(w)
    t = int(time.time())
    w.net.hosts[w.i1.id] = host(avail=200, swap=0, swap_free=0, ooms=[{"ts": t - 60, "pid": 7, "proc": "backpack", "rss_mb": 3035}])
    w.orch.last_hosts = 0  # read on the next check, not after host_interval
    await w.orch.check_all()
    assert w.i1.host["mem_avail"] == 200 and w.i1.backpack_version == "v2.0.0"
    assert len(w.i1.ooms) == 1
    assert sum("I1 تمام شد" in n for n in w.notes) == 1
    assert w.said("backpack (3035 MB)") and w.said("swap ندارد")
    assert sum("رم آزاد سرور داخل I1 کم است" in n for n in w.notes) == 1
    # the same kill and the same shortage are not repeated
    w.orch.last_hosts = 0
    await w.orch.check_all()
    assert sum("I1 تمام شد" in n for n in w.notes) == 1
    assert sum("I1 کم است" in n for n in w.notes) == 1
    # a new kill is
    w.net.hosts[w.i1.id]["ooms"].append({"ts": t - 5, "pid": 9, "proc": "xray", "rss_mb": 1200})
    w.orch.last_hosts = 0
    await w.orch.check_all()
    assert sum("I1 تمام شد" in n for n in w.notes) == 2 and len(w.i1.ooms) == 2
    # memory back: said in the log, not sent to Telegram
    w.net.hosts[w.i1.id].update(mem_avail=4000)
    w.orch.last_hosts = 0
    await w.orch.check_all()
    assert any("دوباره کافی است" in e.message for e in w.store.events)
    assert not w.said("دوباره کافی است")
    st = w.store.snapshot()
    assert next(s for s in st["servers"] if s["id"] == w.i1.id)["mem_low"] is False


def test_low_memory_needs_swap_to_be_short_too():
    s = Server(name="S", role=IRAN, ip="1.1.1.1")
    s.host = host(avail=300, total=5900, swap=4096, swap_free=3000)
    assert not s.mem_low(10)  # swap still has room
    s.host = host(avail=300, total=5900, swap=4096, swap_free=200)
    assert s.mem_low(10)
    s.host = host(avail=300, total=5900, swap=0, swap_free=0)
    assert s.mem_low(10)
    s.host = host(avail=3000)
    assert not s.mem_low(10)
    s.host = {}
    assert not s.mem_low(10)  # never read


async def test_ends_on_different_releases_are_reported(world):
    w = world
    await connected(w)
    for s in (w.i1, w.i2, w.k1, w.k2):
        w.net.hosts[s.id] = host(version="v2.0.0")
    w.net.hosts[w.k1.id] = host(version="v1.8.5")  # updated everywhere but here
    w.orch.last_hosts = 0
    await w.orch.check_all()
    link = w.link(w.i1, w.k1)
    assert w.store.version_gap(link) == ("v2.0.0", "v1.8.5")
    assert w.store.version_gap(w.link(w.i1, w.k2)) is None
    def said():
        return sum("یکی نیست" in n and "K1 ⇄ I1" in n for n in w.notes)

    assert said() == 1 and w.said("خارج v1.8.5")
    assert sum("یکی نیست" in n for n in w.notes) == 2  # K1 ⇄ I1 and K1 ⇄ I2
    assert next(x for x in w.store.snapshot()["links"] if x["id"] == link.id)["version_gap"] == ["v2.0.0", "v1.8.5"]
    w.orch.last_hosts = 0
    await w.orch.check_all()
    assert said() == 1  # once
    w.net.hosts[w.k1.id] = host(version="v2.0.0")
    w.orch.last_hosts = 0
    await w.orch.check_all()
    assert w.store.version_gap(link) is None
    assert any("یکی شد" in e.message for e in w.store.events)


# ------------------------------------------------------------ port clashes
async def test_two_tunnels_on_one_port_are_reported_until_fixed(world):
    w = world
    await connected(w)
    a, b = w.link(w.i1, w.k1), w.link(w.i1, w.k2)
    b.ports = ["443", "2053"]  # edited on the server: both now list 443
    await w.orch.check_all()
    assert w.store.port_conflicts() == [{"iran_id": w.i1.id, "links": sorted([a.id, b.id]), "ports": [443]}]
    assert sum("پورت مشترک" in n for n in w.notes) == 1
    snap = {x["id"]: x for x in w.store.snapshot()["links"]}
    assert snap[a.id]["conflicts"] == [{"with": b.id, "ports": [443]}]
    await w.orch.check_all()
    assert sum("پورت مشترک" in n for n in w.notes) == 1
    b.ports = ["2053"]
    await w.orch.check_all()
    assert w.store.port_conflicts() == []
    assert any("برطرف شد" in e.message for e in w.store.events)


def test_handed_over_ports_are_not_a_clash():
    st = Store(None)
    i = Server(name="I", role=IRAN, ip="10.0.0.3")
    st.servers[i.id] = i
    a = Link(iran_id=i.id, kharej_id="k1", tunnel_port=1, ports=["443"], status=L_UP, transport="tcpmux")
    b = Link(iran_id=i.id, kharej_id="k2", tunnel_port=2, ports=["443=2096"], status=L_UP, transport="tcpmux")
    st.links = {a.id: a, b.id: b}
    assert st.port_conflicts()  # both listen on 443
    st.handover[a.id] = b.id  # a's ports now ride on b
    assert st.port_conflicts() == []
    # a tunnel on another Iran server may use the same port
    j = Server(name="J", role=IRAN, ip="10.0.0.4")
    st.servers[j.id] = j
    c = Link(iran_id=j.id, kharej_id="k1", tunnel_port=1, ports=["443"], status=L_UP, transport="tcpmux")
    st.links[c.id] = c
    assert st.port_conflicts() == []


def test_api_refuses_a_port_another_tunnel_on_the_server_has(tmp_path):
    import os

    from fastapi.testclient import TestClient

    from tunnelmanager.app import create_app

    os.environ["TM_NO_MONITOR"] = "1"
    with TestClient(create_app(tmp_path, driver=FakeNet())) as c:
        c.post("/api/setup", json={"username": "admin", "password": "secret1"})
        c.put("/api/settings", json={"auto_mesh": True})
        for name, role, ip in (("K1", KHAREJ, "10.0.0.1"), ("K2", KHAREJ, "10.0.0.2"), ("I", IRAN, "10.0.0.3"), ("J", IRAN, "10.0.0.4")):
            c.post("/api/servers", json={"name": name, "role": role, "ip": ip})
        st = c.app.state.store
        by = {(st.servers[x.iran_id].name, st.servers[x.kharej_id].name): x for x in st.links.values()}
        a, b = by[("I", "K1")], by[("I", "K2")]
        a.ports, a.status, a.transport = ["443", "2053"], L_UP, "tcpmux"
        r = c.put(f"/api/links/{b.id}", json={"ports": ["8443", "2053"]})
        assert r.status_code == 409 and "2053" in r.json()["detail"]
        assert b.ports == []
        assert c.put(f"/api/links/{b.id}", json={"ports": ["8443"]}).status_code == 200
        # editing a tunnel's own ports is never a clash with itself
        assert c.put(f"/api/links/{a.id}", json={"ports": ["443", "2053", "2083"]}).status_code == 200
        # copying K2's ports to all its tunnels skips the server where they clash
        by[("J", "K1")].ports = ["8443"]
        by[("J", "K1")].status, by[("J", "K1")].transport = L_UP, "tcpmux"
        assert c.put(f"/api/links/{b.id}", json={"ports": ["8443"], "apply_to_kharej": True}).status_code == 200
        assert by[("J", "K2")].ports == []  # J's 8443 belongs to K1's tunnel
        r = c.post("/api/links", json={"iran_id": a.iran_id, "kharej_id": b.kharej_id, "ports": ["443"]})
        assert r.status_code == 409


def test_scripts_read_the_journal(tmp_path):
    """The shell side: queue-full lines for the tunnel's unit, OOM kills from
    the kernel log (journalctl stood in for, as on a server)."""
    import os
    import subprocess

    from tunnelmanager.backpack import HOST_SCRIPT, check_script

    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "systemctl").write_text("#!/bin/sh\necho active\n")
    (fakebin / "journalctl").write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *"-u backpack-tm-a.service"*"--since -60s"*) for i in 1 2 3; do echo "x backpack[1]: [WARNING] forwarded port [::]:443: the queue is full, dropping a client from 5.6.7.8:1"; done; echo "x backpack[1]: [INFO] ok" ;;\n'
        '  *"-k"*"short-unix"*) echo "1795584979.123456 h kernel: Out of memory: Killed process 1027280 (backpack) total-vm:1kB, anon-rss:3107416kB, file-rss:0kB" ;;\n'
        "esac\n"
    )
    for f in fakebin.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
    link = Link(iran_id="i", kharej_id="k", tunnel_port=1, transport="stealth", id="a")
    out = subprocess.run(["bash", "-c", check_script([link])], capture_output=True, text=True, env=env, timeout=30).stdout
    assert parse_check(out, {"a": link})["a"].dropped == 3, out
    out = subprocess.run(["bash", "-c", HOST_SCRIPT], capture_output=True, text=True, env=env, timeout=30).stdout
    h = parse_host(out)
    assert h["ooms"] == [{"ts": 1795584979, "pid": 1027280, "proc": "backpack", "rss_mb": 3035}], out
    assert h["mem_total"] > 0
