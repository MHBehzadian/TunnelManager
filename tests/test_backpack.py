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
    parse_wait,
    render_client,
    render_server,
    render_unit,
    validate_port_mapping,
    wait_script,
)
from tunnelmanager.models import IRAN, KHAREJ, Link, Server
from tunnelmanager.store import Store


def mk():
    k = Server(name="K", role=KHAREJ, ip="5.6.7.8", ports=["443", "8443=127.0.0.1:2096"], ssh_port=2222)
    i = Server(name="I", role=IRAN, ip="1.2.3.4")
    link = Link(iran_id=i.id, kharej_id=k.id, tunnel_port=3080, probe_port=61000)
    return k, i, link


def test_render_server_and_client_are_valid_toml():
    k, i, link = mk()
    srv = tomllib.loads(render_server(link, "tcpmux", k.ports, k))["server"]
    assert srv["bind_addr"] == "0.0.0.0:3080"
    assert srv["transport"] == "tcpmux"
    assert srv["token"] == link.token
    assert srv["ports"] == ["127.0.0.1:61000=127.0.0.1:2222", "443", "8443=127.0.0.1:2096"]
    cli = tomllib.loads(render_client(link, "tcpmux", i))["client"]
    assert cli["remote_addr"] == "1.2.3.4:3080"
    assert cli["token"] == link.token
    assert f"-c /etc/backpack/tm-{link.id}.toml" in render_unit(link)


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
    p = parse_check("noise\n@@l1|active|true|1|4210\n@@l2|failed||0|3000012\n")
    assert p["l1"].ok and p["l1"].latency_ms == 4.2 and p["l1"].connected is True
    assert not p["l2"].ok and p["l2"].active == "failed" and p["l2"].connected is None
    w = parse_wait("OK 1830 4000 5000 3000\n")
    assert w.ok and w.latency_ms == 4.0 and w.connect_s == 1.83
    assert not parse_wait("FAIL\n").ok


def test_store_ports_and_takeover_dedupe():
    st = Store(None)
    k1 = Server(name="K1", role=KHAREJ, ip="10.0.0.1", ports=["443", "8443"])
    k2 = Server(name="K2", role=KHAREJ, ip="10.0.0.2", ports=["443=2096", "2053"])
    i = Server(name="I", role=IRAN, ip="10.0.0.3")
    for s in (k1, k2, i):
        st.servers[s.id] = s
    st.ensure_links()
    l1, l2 = st.link_for(i.id, k1.id), st.link_for(i.id, k2.id)
    assert l1.tunnel_port != l2.tunnel_port and l1.probe_port != l2.probe_port
    st.takeover[k1.id] = k2.id
    # K2's own 443 mapping wins; K1's 8443 moves over
    assert st.link_ports(l2) == ["443=2096", "2053", "8443"]
    assert st.link_ports(l1) == []


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
