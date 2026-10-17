"""Ports a kharej sends on to another server: found, shown, never acted on."""

from __future__ import annotations

from tests.conftest import FakeDNS
from tunnelmanager.backpack import exits_script, kharej_dest, listen_ports, parse_exits
from tunnelmanager.models import L_UP

# captured from a real run of exits_script: socat with its target on the
# command line (18443), an iptables DNAT (18444), a plain local service
# (18445) and a socat whose target only shows in its connections (18446)
REAL = """@@NAT
-A OUTPUT -p tcp -m tcp --dport 18444 -j DNAT --to-destination 192.0.2.2:19000
\t\ttcp dport 18444 counter packets 0 bytes 0 dnat to 192.0.2.2:19000
@@PORT 18443
@@PID 646 socat
@@CMD socat TCP-LISTEN:18443,fork,reuseaddr TCP:192.0.2.2:19000
@@OUT
      1 192.0.2.2:19000
@@DISTINCT 1
@@PORT 18444
@@PORT 18445
@@PID 644 python3
@@CMD python3 -m http.server 18445
@@OUT
@@DISTINCT 0
@@PORT 18446
@@PID 648 socat
@@CMD socat TCP-LISTEN:18446,fork,reuseaddr SYSTEM:exec socat - TCP\\:192.0.2.2\\:19000
@@OUT
      1 192.0.2.2:19000
@@DISTINCT 1
@@REACH
192.0.2.2:19000 ok
192.0.2.2:19999 fail
@@END
"""


def test_parse_real_output():
    exits, reach = parse_exits(REAL, [18443, 18444, 18445, 18446])
    assert exits[18443] == {"method": "socat", "targets": ["192.0.2.2:19000"], "via": "socat", "inferred": False}
    assert exits[18444]["method"] == "iptables" and exits[18444]["targets"] == ["192.0.2.2:19000"]
    assert 18445 not in exits  # served right there
    assert exits[18446]["inferred"] and exits[18446]["targets"] == ["192.0.2.2:19000"]
    assert reach == {"192.0.2.2:19000": True, "192.0.2.2:19999": False}


def test_other_forwarders_and_services():
    out = """@@NAT
\t\ttcp dport { 80, 443 } dnat ip to 10.9.9.9
-A PREROUTING -p tcp -m multiport --dports 2053:2060 -j DNAT --to-destination 10.8.8.8
@@PORT 443
@@PORT 2055
@@PORT 8443
@@PID 10 gost
@@CMD gost -L tcp://:8443/10.1.1.1:8443 -F relay+tls://u:p@10.2.2.2:443
@@OUT
@@DISTINCT 0
@@PORT 9443
@@PID 11 realm
@@CMD realm -l 0.0.0.0:9443 -r 10.3.3.3:9443
@@OUT
@@DISTINCT 0
@@PORT 4443
@@PID 12 xray
@@CMD xray run -c /etc/xray.json
@@OUT
     40 142.250.1.1:443
     30 104.16.1.1:443
     20 151.101.1.1:443
     10 31.13.1.1:443
      9 17.1.1.1:443
@@DISTINCT 212
@@PORT 5443
@@PID 13 xray
@@CMD xray run -c /etc/relay.json
@@OUT
     55 10.4.4.4:8443
@@DISTINCT 1
@@REACH
@@END
"""
    exits, _ = parse_exits(out, [443, 2055, 8443, 9443, 4443, 5443])
    assert exits[443] == {"method": "nftables", "targets": ["10.9.9.9:443"], "via": "", "inferred": False}
    assert exits[2055]["targets"] == ["10.8.8.8:2055"]
    assert exits[8443]["targets"] == ["10.2.2.2:443"]  # chained: the forwarder is the exit
    assert exits[9443]["targets"] == ["10.3.3.3:9443"]
    assert 4443 not in exits  # xray browsing the internet for its users is not a forward
    assert exits[5443] == {"method": "xray", "targets": ["10.4.4.4:8443"], "via": "xray", "inferred": True}


def test_kharej_side_of_a_mapping():
    assert kharej_dest("443") == ("", 443)
    assert kharej_dest("8443=2096") == ("", 2096)
    assert kharej_dest("443=1.2.3.4:5201") == ("1.2.3.4", 5201)
    assert kharej_dest("127.0.0.2:443=127.0.0.1:22") == ("", 22)
    assert kharej_dest("443-600:5201") == ("", 5201)
    assert listen_ports(["443-445:5201"]) == {443, 444, 445}


def test_script_only_quotes_valid_targets():
    sh = exits_script([443], ["1.2.3.4:443", "x;reboot:1", "[2001:db8::1]:443"])
    assert "1.2.3.4:443" in sh and "reboot" not in sh and "[2001:db8::1]:443" in sh


async def test_exits_are_shown_and_reported_but_change_nothing(world):
    w = world
    k1, k2 = w.k1, w.k2
    for x in w.store.links.values():
        x.status, x.transport, x.built = L_UP, "tcpmux", True
        w.net.deployed[x.id] = "tcpmux"
    w.net.ip_of = {s.ip: s.id for s in w.store.servers.values()}
    w.net.fwd[k1.id] = {443: {"method": "iptables", "targets": [f"{k2.ip}:443"], "via": "", "inferred": False}}
    await w.settle(1)
    st = w.store
    assert st.servers[k1.id].exits["443"]["targets"] == [f"{k2.ip}:443"]
    e = st.exit_of(w.link(w.i1, k1), 443)
    assert e["targets"][0]["server_id"] == k2.id and e["method"] == "iptables"
    assert st.exit_of(w.link(w.i1, k1), 2096) is None  # 8443=2096 is served on K1 itself
    snap = st.snapshot()
    assert any("443" in x["exits"] for x in snap["links"])
    info = w.orch.domain_info(w.dom)
    assert info["routes"][0]["exit"]["targets"][0]["server_id"] == k2.id
    assert "↪K2" in w.orch.routes_text(w.dom, w.i1.id)

    # the exit stops answering: reported once, after fail_threshold rounds
    before = {x.id: (x.transport, x.status) for x in st.links.values()}
    w.net.dead.add(k2.id)
    for _ in range(3):
        w.orch.last_exits = 0
        await w.orch.check_exits()
    assert w.said("جواب نمی‌دهد") and sum("جواب نمی‌دهد" in n for n in w.notes) == 1
    assert st.servers[k1.id].exit_reach[f"{k2.ip}:443"]["ok"] is False
    w.net.dead.discard(k2.id)
    w.orch.last_exits = 0
    await w.orch.check_exits()
    assert w.said("دوباره در دسترس است")
    # nothing was touched for it
    assert FakeDNS.calls == [] and {x.id: (x.transport, x.status) for x in st.links.values()} == before
    assert w.dom.iran_id == w.i1.id


async def test_static_backpack_target_is_an_exit(world):
    w = world
    link = w.link(w.i1, w.k1)
    link.status, link.transport = L_UP, "tcpmux"
    link.ports = ["443=10.7.7.7:443"]
    e = w.store.exit_of(link, 443)
    assert e["method"] == "backpack" and e["targets"][0]["addr"] == "10.7.7.7:443"
    assert w.store.kharej_ports(w.k1.id) == ([], ["10.7.7.7:443"])
