"""Demo mode: a simulated network so the panel can be explored (and its
failover watched) without real servers. ``python -m tunnelmanager demo``"""

from __future__ import annotations

import asyncio
import logging
import random

from .backpack import Driver, Found, Probe
from .models import IRAN, KHAREJ, DNSProvider, Domain, Server
from .ssh import SSHError
from .store import Store

log = logging.getLogger(__name__)


class SimNet(Driver):
    """A simulated network: servers can die, transports can be blocked per
    pair, paths can flap, and every transport has a latency. ``existing``
    holds tunnels "already running" on servers, for scan() to find."""

    LAT = {"tcpmux": 40, "wsmux": 55, "tcp": 35, "ws": 60, "stealth": 50, "kcp": 70, "quic": 45}

    def __init__(self, jitter: bool = False):
        self.jitter = jitter
        self.dead: set[str] = set()
        self.blocked: set[tuple[str, str, str]] = set()  # (iran, kharej, transport)
        self.flaky: dict[tuple[str, str], float] = {}  # (iran, kharej) -> failure probability
        self.deployed: dict[str, str] = {}  # link id -> transport
        self.iran_ports: dict[str, list[str]] = {}  # link id -> ports on the Iran side
        self.stopped: set[str] = set()
        self.existing: dict[str, list[Found]] = {}
        self.listen: dict[str, set[int]] = {}  # server id -> ports already in use
        self.fwd: dict[str, dict[int, dict]] = {}  # kharej id -> port -> where it is sent on
        self.ip_of: dict[str, str] = {}  # ip -> server id, so exits to a dead server fail
        self.calls: list[tuple] = []
        self.rnd = random.Random(1)

    def block(self, iran: Server, kharej: Server, *transports: str):
        for t in transports:
            self.blocked.add((iran.id, kharej.id, t))

    def works(self, link, transport: str | None = None) -> bool:
        t = transport or self.deployed.get(link.id) or link.transport
        return (
            bool(t)
            and link.id not in self.stopped
            and link.iran_id not in self.dead
            and link.kharej_id not in self.dead
            and (link.iran_id, link.kharej_id, t) not in self.blocked
            and self.rnd.random() >= self.flaky.get((link.iran_id, link.kharej_id), 0)
        )

    def lat(self, t, link=None) -> float:
        base = self.LAT.get(t, 50)
        if not self.jitter:
            return base
        # a stable per-pair, per-transport character, plus a little noise
        if link is not None:
            base *= random.Random(f"{link.iran_id}{link.kharej_id}{t}").uniform(0.6, 2.2)
        return round(base * random.uniform(0.9, 1.25), 1)

    async def ping(self, s):
        if s.id in self.dead:
            raise SSHError(f"{s.name} unreachable")
        return 5.0

    async def ensure_installed(self, s, install=True):
        if s.id in self.dead:
            raise SSHError("down")
        return "v1.9.0"

    async def deploy(self, link, iran, kharej, transport, ports):
        if iran.id in self.dead:
            raise SSHError("iran down")
        self.calls.append(("deploy", link.id, transport, tuple(ports)))
        self.deployed[link.id] = transport
        self.iran_ports[link.id] = list(ports)
        self.stopped.discard(link.id)

    async def deploy_iran(self, link, iran, kharej, ports):
        if iran.id in self.dead:
            raise SSHError("iran down")
        self.calls.append(("deploy_iran", link.id, tuple(ports)))
        self.iran_ports[link.id] = list(ports)
        self.stopped.discard(link.id)

    async def stop(self, link, iran, kharej):
        self.calls.append(("stop", link.id))
        self.stopped.add(link.id)

    async def remove(self, link, iran, kharej):
        self.calls.append(("remove", link.id))

    async def check(self, iran, links):
        if iran.id in self.dead:
            raise SSHError("down")
        out = {}
        for x in links:
            ok = self.works(x)
            t = self.deployed.get(x.id) or x.transport
            out[x.id] = Probe(ok=ok, active="active", latency_ms=self.lat(t, x) if ok else None, verified=bool(x.probe_port))
        return out

    async def wait_up(self, link, iran, timeout):
        t = self.deployed.get(link.id)
        if self.works(link, t):
            return Probe(ok=True, latency_ms=self.lat(t, link), connect_s=round(random.uniform(0.6, 3.5), 2) if self.jitter else 1.0)
        return Probe(ok=False, error="timeout")

    async def scan(self, s):
        if s.id in self.dead:
            raise SSHError("down")
        return list(self.existing.get(s.id, []))

    async def listening(self, s):
        return set(self.listen.get(s.id, set()))

    async def exits(self, s, ports, targets):
        if s.id in self.dead:
            raise SSHError(f"{s.name} unreachable")
        found = {p: dict(h) for p, h in self.fwd.get(s.id, {}).items() if p in ports}
        reach = {t: self.ip_of.get(t.rsplit(":", 1)[0], "") not in self.dead for t in targets}
        return found, reach

    def plant(self, iran: Server, kharej: Server, name: str, transport: str, port: int, ports: list[str],
              token: str = "secret", active: str = "active", unit: str = ""):
        """Pretend a tunnel was set up by hand before the panel existed."""
        unit = unit or f"backpack-{name}.service"
        self.existing.setdefault(iran.id, []).append(
            Found(name=name, role="server", active=active, unit=unit, data={
                "bind_addr": f"0.0.0.0:{port}", "transport": transport, "token": token, "ports": list(ports),
                "mux_con": 8, "heartbeat": 40,
            })
        )
        self.existing.setdefault(kharej.id, []).append(
            Found(name=name, role="client", active=active, unit=unit, data={
                "remote_addr": f"{iran.ip}:{port}", "transport": transport, "token": token, "connection_pool": 8,
            })
        )


class SimDNS:
    records: dict[str, str] = {}
    calls: list[tuple[str, str]] = []
    fail = False

    def __init__(self, provider, proxy=None):
        self.p = provider

    async def set_a(self, fqdn, ip, ttl=60):
        if SimDNS.fail:
            raise RuntimeError("dns api down")
        SimDNS.records[fqdn] = ip
        SimDNS.calls.append((fqdn, ip))

    async def get_a(self, fqdn):
        return [SimDNS.records[fqdn]] if fqdn in SimDNS.records else []

    async def verify(self):
        return f"zone {self.p.zone} (demo)"


async def sim_resolver(fqdn, resolvers, proxy=None):
    """Public resolvers that catch up with the record a while after it changed."""
    ip = SimDNS.records.get(fqdn)
    return {r: ([ip] if ip and random.random() < 0.5 else ["0.0.0.0"]) for r in resolvers[:1]}


def seed(store: Store, net: SimNet) -> None:
    st = store
    if not st.servers:
        st.settings.check_interval = 10
        st.settings.fail_threshold = 2
        st.settings.test_timeout = 5
        st.settings.failback_after = 120
        st.settings.flap_window = 180
        st.settings.scan_interval = 60
        st.settings.observe_only = False  # the demo is there to watch failover happen
        st.settings.auto_mesh = True
        for name, ip, prio in (("Hetzner-DE", "65.21.10.4", 1), ("OVH-FR", "51.75.33.9", 2), ("Contabo-NL", "185.2.4.77", 3)):
            s = Server(name=name, role=KHAREJ, ip=ip, priority=prio)
            st.servers[s.id] = s
        for name, ip, prio in (("Tehran-AsiaTech", "185.8.172.10", 1), ("Shiraz-ParsOnline", "91.98.30.21", 2), ("Mashhad-Afranet", "79.175.140.5", 3)):
            s = Server(name=name, role=IRAN, ip=ip, priority=prio)
            st.servers[s.id] = s
        cf = DNSProvider(name="Cloudflare", kind="cloudflare", api_token="demo", zone="example.com")
        ar = DNSProvider(name="Arvan", kind="arvan", api_token="demo", zone="example.ir")
        st.providers[cf.id], st.providers[ar.id] = cf, ar
        kh, ir = st.kharejs(), st.irans()
        # records as they are today: each points at one Iran server
        for fqdn, prov, k, ports, iran in (
            ("vpn.example.ir", ar, kh[0], [], ir[0]),
            ("cdn.example.ir", ar, kh[1], [], ir[2]),
            ("game.example.com", cf, kh[2], [], ir[1]),
            # one domain, two ports, two kharejs: 443 -> Hetzner, 2053 -> OVH
            ("multi.example.ir", ar, None, ["443", "2053"], ir[0]),
        ):
            d = Domain(fqdn=fqdn, provider_id=prov.id, kharej_id=k.id if k else "", ports=ports, current_ip=iran.ip)
            st.domains[d.id] = d
            SimDNS.records[fqdn] = iran.ip
        st.save()
    kh, ir = st.kharejs(), st.irans()
    if len(kh) >= 3 and len(ir) >= 3:
        # tunnels "set up by hand" before the panel: the first scan adopts them
        net.plant(ir[0], kh[0], "hetzner-teh", "tcpmux", 3080, ["443", "8443=2096"])
        net.plant(ir[1], kh[0], "hetzner-shz", "wsmux", 3080, ["443", "8443=2096"])
        net.plant(ir[0], kh[1], "ovh-teh", "tcp", 3081, ["2053", "2083"])
        net.plant(ir[2], kh[1], "ovh-mhd", "quic", 3080, ["2053", "2083"])
        net.plant(ir[1], kh[2], "contabo-shz", "kcp", 3081, ["2087"])
        net.plant(ir[1], kh[1], "ovh-shz", "tcpmux", 3082, ["2053", "2083"])
        net.plant(ir[2], kh[2], "contabo-mhd", "wsmux", 3081, ["2087"])
        # some ports leave from another server than the tunnel's kharej
        net.ip_of = {s.ip: s.id for s in st.servers.values()}
        net.fwd[kh[0].id] = {443: {"method": "iptables", "targets": [f"{kh[2].ip}:443"], "via": "", "inferred": False}}
        net.fwd[kh[1].id] = {2083: {"method": "gost", "targets": ["203.0.113.50:2083"], "via": "gost", "inferred": False}}


async def chaos(orch, net: SimNet) -> None:
    """Break something every so often so the failover can be watched."""
    st = orch.store
    rnd = random.Random(7)
    await asyncio.sleep(4)
    # DPI in the demo "Iran": some transports never work on some pairs
    for i in st.irans():
        for k in st.kharejs():
            for t in ("tcp", "ws", "kcp"):
                if rnd.random() < 0.3:
                    net.blocked.add((i.id, k.id, t))
    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(random.uniform(45, 80))
        roll = random.random()
        active = [st.links.get(st.carrier(d.link_id)) for d in st.domains.values() if d.link_id]
        active = [x for x in active if x and x.transport]
        if roll < 0.3 and active:
            x = random.choice(active)
            net.flaky[(x.iran_id, x.kharej_id)] = 0.5
            log.info("chaos: path %s starts flapping", x.id)
            loop.call_later(200, net.flaky.pop, (x.iran_id, x.kharej_id), None)
        elif roll < 0.55 and active:
            x = random.choice(active)
            key = (x.iran_id, x.kharej_id, x.transport)
            net.blocked.add(key)
            log.info("chaos: blocking %s on %s", x.transport, x.id)
            loop.call_later(240, net.blocked.discard, key)
        else:
            role = IRAN if roll < 0.85 else KHAREJ
            victims = [s for s in st.by_role(role) if s.id not in net.dead]
            if len(victims) > 1:
                v = random.choice(victims)
                net.dead.add(v.id)
                log.info("chaos: %s goes dark", v.name)
                loop.call_later(random.uniform(60, 120), net.dead.discard, v.id)
