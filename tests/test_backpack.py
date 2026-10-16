"""Config rendering, and the remote health scripts run against a real
BackPack engine on localhost (set TM_BACKPACK_BIN to the binary to enable)."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

import pytest

from tunnelmanager.backpack import (
    _ufw_allow,
    check_script,
    parse_check,
    parse_scan,
    parse_wait,
    render_client,
    render_server,
    render_unit,
    split_ports,
    validate_port_mapping,
    wait_script,
)
from tunnelmanager.models import IRAN, KHAREJ, Link, Server
from tunnelmanager.store import Store


def mk():
    k = Server(name="K", role=KHAREJ, ip="5.6.7.8", ssh_port=2222)
    i = Server(name="I", role=IRAN, ip="1.2.3.4")
    link = Link(iran_id=i.id, kharej_id=k.id, tunnel_port=3080, probe_port=61000, ports=["443", "8443=127.0.0.1:2096"])
    return k, i, link


def test_render_server_and_client_are_valid_toml():
    k, i, link = mk()
    srv = tomllib.loads(render_server(link, "tcpmux", link.ports, k))["server"]
    assert srv["bind_addr"] == "0.0.0.0:3080"
    assert srv["transport"] == "tcpmux"
    assert srv["token"] == link.token
    assert srv["ports"] == ["127.0.0.1:61000=127.0.0.1:2222", "443", "8443=127.0.0.1:2096"]
    cli = tomllib.loads(render_client(link, "tcpmux", i))["client"]
    assert cli["remote_addr"] == "1.2.3.4:3080"
    assert cli["token"] == link.token
    assert f"-c /etc/backpack/tm-{link.id}.toml" in render_unit(link.iran_name)


def test_adopted_tunnel_keeps_its_own_settings():
    k, i, link = mk()
    link.iran_name = "my-tunnel"
    link.probe_port = 0
    link.iran_base = {
        "bind_addr": "85.11.12.13:443", "transport": "tcp", "token": "old", "mux_con": 8,
        "heartbeat": 40, "naive": {"binary": "/usr/bin/naive", "listen": ":8443"},
    }
    link.kharej_base = {"remote_addr": "iran.example.com:443", "transport": "tcp", "token": "old", "connection_pool": 24}
    link.tunnel_port = 443
    srv = tomllib.loads(render_server(link, "wsmux", ["2053"], k))["server"]
    assert srv["bind_addr"] == "85.11.12.13:443"  # pinned address kept
    assert srv["transport"] == "wsmux" and srv["token"] == link.token
    assert srv["mux_con"] == 8 and srv["heartbeat"] == 40
    assert srv["naive"] == {"binary": "/usr/bin/naive", "listen": ":8443"}
    assert srv["ports"] == ["2053"]  # no probe yet
    cli = tomllib.loads(render_client(link, "wsmux", i))["client"]
    assert cli["remote_addr"] == "iran.example.com:443"  # their hostname, not our IP
    assert cli["connection_pool"] == 24


def test_scan_parsing_and_probe_detection():
    out = """@@FILE hetzner active
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcpmux"
token = "abc"
ports = ["127.0.0.1:61003=127.0.0.1:22", "443", "8443=2096"]

@@FILE broken-file failed
[server
@@FILE direct-one active
[direct]
role = "iran"
@@FILE kh inactive
[client]
remote_addr = "1.2.3.4:3080"
transport = "tcpmux"

@@END
"""
    found = parse_scan(out)
    assert [(f.name, f.role, f.active) for f in found] == [("hetzner", "server", "active"), ("kh", "client", "inactive")]
    srv, cli = found
    assert srv.port() == 3080 and srv.token == "abc" and cli.token == "backpack"
    assert cli.host() == "1.2.3.4"
    assert split_ports(srv.data["ports"]) == (["443", "8443=2096"], 61003)


def test_ipv6_remote_is_bracketed():
    k, i, link = mk()
    i.ip = "2001:db8::1"
    assert tomllib.loads(render_client(link, "ws", i))["client"]["remote_addr"] == "[2001:db8::1]:3080"


@pytest.mark.parametrize("bad", ["443; rm -rf /", "$(id)", "44 3", "", "a\nb"])
def test_port_mapping_validation(bad):
    with pytest.raises(ValueError):
        validate_port_mapping(bad)


def test_ufw_rules():
    out = _ufw_allow(["3080", "443", "127.0.0.1:61000=22", "1.2.3.4:8443=2096", "2053-2060"])
    assert "ufw allow 3080" in out and "ufw allow 443" in out and "ufw allow 8443" in out
    assert "ufw allow 2053:2060/tcp" in out
    assert "61000" not in out


def test_parsers():
    p = parse_check("noise\n@@l1|active|true|1|4210|1\n@@l2|failed||0|3000012|0\n")
    assert p["l1"].ok and p["l1"].latency_ms == 4.2 and p["l1"].connected is True
    assert not p["l2"].ok and p["l2"].active == "failed" and p["l2"].connected is None
    # no probe port: the engine's word, then the socket table
    tcp = Link(iran_id="i", kharej_id="k", tunnel_port=1, transport="tcpmux", id="a")
    kcp = Link(iran_id="i", kharej_id="k", tunnel_port=2, transport="kcp", id="b")
    links = {"a": tcp, "b": kcp}
    p = parse_check("@@a|active||-|0|2\n@@b|active||-|0|0\n", links)
    assert p["a"].ok and not p["a"].verified and p["b"].ok
    p = parse_check("@@a|active||-|0|0\n@@b|active|false|-|0|0\n", links)
    assert not p["a"].ok and not p["b"].ok
    w = parse_wait("OK 1830 4000 5000 3000\n")
    assert w.ok and w.latency_ms == 4.0 and w.connect_s == 1.83
    assert not parse_wait("FAIL\n").ok


def test_store_ports_and_handover_dedupe():
    st = Store(None)
    st.settings.auto_mesh = True
    k1 = Server(name="K1", role=KHAREJ, ip="10.0.0.1")
    k2 = Server(name="K2", role=KHAREJ, ip="10.0.0.2")
    i = Server(name="I", role=IRAN, ip="10.0.0.3")
    for s in (k1, k2, i):
        st.servers[s.id] = s
    st.ensure_links()
    l1, l2 = st.link_for(i.id, k1.id), st.link_for(i.id, k2.id)
    l1.ports, l2.ports = ["443", "8443"], ["443=2096", "2053"]
    ports = {l1.tunnel_port, l2.tunnel_port, l1.probe_port, l2.probe_port}
    assert len(ports) == 4  # nothing collides on the Iran server
    st.handover[l1.id] = l2.id
    # the carrier's own 443 mapping wins; K1's 8443 moves over
    assert st.link_ports(l2) == ["443=2096", "2053", "8443"]
    assert st.link_ports(l1) == []
    assert st.carrier(l1.id) == l2.id


def test_v01_state_migrates(tmp_path):
    import json

    old = {
        "servers": [
            {"id": "k", "name": "K", "role": "kharej", "ip": "1.1.1.1", "ports": ["443"], "accept_udp": True},
            {"id": "i", "name": "I", "role": "iran", "ip": "2.2.2.2"},
        ],
        "links": [{"id": "l", "iran_id": "i", "kharej_id": "k", "tunnel_port": 3080, "probe_port": 61000, "status": "suspended", "transport": "tcpmux"}],
        "domains": [{"id": "d", "fqdn": "a.x.com", "provider_id": "p", "kharej_id": "k", "iran_id": "i"}],
        "takeover": {"k": "k2"},
    }
    (tmp_path / "state.json").write_text(json.dumps(old))
    st = Store(tmp_path / "state.json")
    assert st.links["l"].ports == ["443"] and st.links["l"].accept_udp
    assert st.links["l"].status == "down"
    assert st.domains["d"].link_id == "l"
    assert st.links["l"].iran_name == "tm-l"


# ---------------------------------------------------------------- live
BIN = os.environ.get("TM_BACKPACK_BIN")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.skipif(not BIN or not Path(BIN).exists(), reason="TM_BACKPACK_BIN not set")
@pytest.mark.parametrize("transport", ["tcpmux", "wsmux", "kcp"])
def test_scripts_against_real_engine(tmp_path, transport):
    banner_port = _free_port()
    srv_sock = socket.socket()
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", banner_port))
    srv_sock.listen()

    def serve():
        while True:
            try:
                c, _ = srv_sock.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-test\r\n")
            c.close()

    threading.Thread(target=serve, daemon=True).start()

    k = Server(name="K", role=KHAREJ, ip="127.0.0.1", probe_target=f"127.0.0.1:{banner_port}")
    i = Server(name="I", role=IRAN, ip="127.0.0.1")
    link = Link(iran_id=i.id, kharej_id=k.id, tunnel_port=_free_port(), probe_port=_free_port())
    (tmp_path / "s.toml").write_text(render_server(link, transport, [], k))
    (tmp_path / "c.toml").write_text(render_client(link, transport, i))
    # the scripts call systemctl; give them a stand-in
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "systemctl").write_text("#!/bin/sh\necho active\n")
    (fakebin / "systemctl").chmod(0o755)
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}

    procs = [subprocess.Popen([BIN, "-c", str(tmp_path / n)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for n in ("s.toml", "c.toml")]
    try:
        out = subprocess.run(["bash", "-c", wait_script(link.probe_port, 15)], capture_output=True, text=True, env=env, timeout=60).stdout
        w = parse_wait(out)
        assert w.ok, out
        assert w.latency_ms is not None and w.latency_ms < 500
        out = subprocess.run(["bash", "-c", check_script([link])], capture_output=True, text=True, env=env, timeout=30).stdout
        p = parse_check(out)[link.id]
        assert p.ok and p.active == "active", out
        # an adopted tunnel without a probe port: inferred from the socket table
        bare = Link(iran_id=i.id, kharej_id=k.id, tunnel_port=link.tunnel_port, transport=transport, iran_name=link.iran_name)
        out = subprocess.run(["bash", "-c", check_script([bare])], capture_output=True, text=True, env=env, timeout=30).stdout
        assert parse_check(out, {bare.id: bare})[bare.id].ok, out
        # kill the kharej side: the probe must notice
        procs[1].terminate()
        procs[1].wait()
        time.sleep(1.5)
        out = subprocess.run(["bash", "-c", check_script([link])], capture_output=True, text=True, env=env, timeout=30).stdout
        assert not parse_check(out)[link.id].ok, out
    finally:
        for p in procs:
            p.terminate()
        srv_sock.close()
    assert sys.platform.startswith("linux")
