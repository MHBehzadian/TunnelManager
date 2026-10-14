"""Demo mode: a simulated network so the panel can be explored (and its
failover watched) without real servers. ``python -m tunnelmanager demo``"""

from __future__ import annotations

import asyncio
import logging
import random

from .backpack import Driver, Probe
from .models import IRAN, KHAREJ, DNSProvider, Domain, Server
from .ssh import SSHError
from .store import Store

log = logging.getLogger(__name__)


class SimNet(Driver):
    """A simulated network: servers can die, transports can be blocked per
    pair, and every transport has a latency."""

    LAT = {"tcpmux": 40, "wsmux": 55, "tcp": 35, "ws": 60, "stealth": 50, "kcp": 70, "quic": 45}

    def __init__(self, jitter: bool = False):
        self.jitter = jitter
        self.dead: set[str] = set()
        self.blocked: set[tuple[str, str, str]] = set()  # (iran, kharej, transport)
        self.deployed: dict[str, str] = {}  # link id -> transport
        self.iran_ports: dict[str, list[str]] = {}  # link id -> ports on the Iran side
        self.stopped: set[str] = set()
        self.calls: list[tuple] = []

    def block(self, iran: Server, kharej: Server, *transports: str):
        for t in transports:
            self.blocked.add((iran.id, kharej.id, t))

    def works(self, link, transport: str | None = None) -> bool:
        t = transport or self.deployed.get(link.id)
        return (
            t is not None
            and link.id not in self.stopped
            and link.iran_id not in self.dead
            and link.kharej_id not in self.dead
            and (link.iran_id, link.kharej_id, t) not in self.blocked
        )

    def lat(self, t, link=None) -> float:
        base = self.LAT.get(t, 50)
        if not self.jitter:
            return base
        # a stable per-pair, per-transport character, plus a little noise
        if link is not None:
            base *= random.Random(f"{link.id}{t}").uniform(0.6, 2.2)
        return round(base * random.uniform(0.9, 1.25), 1)

    async def ping(self, s):
        if s.id in self.dead:
            raise SSHError(f"{s.name} unreachable")
        return 5.0

    async def ensure_installed(self, s, install=True):
        if s.id in self.dead:
            raise SSHError("down")
        return "v-test"

    async def deploy(self, link, iran, kharej, transport, ports):
        if iran.id in self.dead:
            raise SSHError("iran down")
        self.calls.append(("deploy", link.id, transport, tuple(ports)))
        self.deployed[link.id] = transport
        self.iran_ports[link.id] = list(ports)
        self.stopped.discard(link.id)

    async def deploy_iran(self, link, iran, kharej, ports):
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
            out[x.id] = Probe(ok=ok, active="active", latency_ms=self.lat(self.deployed.get(x.id), x) if ok else None)
        return out

    async def wait_up(self, link, iran, timeout):
        t = self.deployed.get(link.id)
        if self.works(link, t):
            return Probe(ok=True, latency_ms=self.lat(t, link), connect_s=round(random.uniform(0.6, 3.5), 2) if self.jitter else 1.0)
        return Probe(ok=False, error="timeout")


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


def seed(store: Store) -> None:
    if store.servers:
        return
    st = store
    st.settings.check_interval = 10
    st.settings.fail_threshold = 2
    st.settings.test_timeout = 5
    for name, ip, ports, prio in (
        ("Hetzner-DE", "65.21.10.4", ["443", "8443=2096"], 1),
        ("OVH-FR", "51.75.33.9", ["2053", "2083"], 2),
        ("Contabo-NL", "185.2.4.77", ["2087"], 3),
    ):
        s = Server(name=name, role=KHAREJ, ip=ip, ports=ports, priority=prio)
        st.servers[s.id] = s
    for name, ip, prio in (("Tehran-AsiaTech", "185.8.172.10", 1), ("Shiraz-ParsOnline", "91.98.30.21", 2), ("Mashhad-Afranet", "79.175.140.5", 3), ("Tabriz-Shatel", "5.160.218.40", 4)):
        s = Server(name=name, role=IRAN, ip=ip, priority=prio)
        st.servers[s.id] = s
    st.ensure_links()
    cf = DNSProvider(name="Cloudflare", kind="cloudflare", api_token="demo", zone="example.com")
    ar = DNSProvider(name="Arvan", kind="arvan", api_token="demo", zone="example.ir")
    st.providers[cf.id], st.providers[ar.id] = cf, ar
    kh = st.kharejs()
    for fqdn, prov, k in (
        ("vpn.example.com", cf, kh[0]), ("panel.example.com", cf, kh[0]), ("cdn.example.ir", ar, kh[1]),
        ("game.example.ir", ar, kh[2]), ("api.example.com", cf, kh[1]),
    ):
        d = Domain(fqdn=fqdn, provider_id=prov.id, kharej_id=k.id)
        st.domains[d.id] = d
    # a path that is filtered in "Iran" for the fastest transports
    st.save()


async def chaos(orch, net: SimNet) -> None:
    """Break something every so often so the failover can be watched."""
    st = orch.store
    # DPI in the demo "Iran": some transports never work on some pairs
    rnd = random.Random(7)
    for x in st.links.values():
        for t in ("tcp", "ws", "tcpmux", "kcp"):
            if rnd.random() < 0.3:
                net.blocked.add((x.iran_id, x.kharej_id, t))
    await asyncio.sleep(3)
    if not any(x.transport for x in st.links.values()):
        await orch.discover_all()
    while True:
        await asyncio.sleep(random.uniform(40, 70))
        roll = random.random()
        if roll < 0.45:
            active = [st.link_for(d.iran_id, st.effective_kharej(d.kharej_id)) for d in st.domains.values()]
            active = [x for x in active if x and x.transport]
            if active:
                x = random.choice(active)
                net.blocked.add((x.iran_id, x.kharej_id, x.transport))
                log.info("chaos: blocking %s on %s", x.transport, x.id)
                asyncio.get_running_loop().call_later(240, net.blocked.discard, (x.iran_id, x.kharej_id, x.transport))
        else:
            role = IRAN if roll < 0.75 else KHAREJ
            victims = [s for s in st.by_role(role) if s.id not in net.dead]
            if len(victims) > 1:
                v = random.choice(victims)
                net.dead.add(v.id)
                log.info("chaos: %s goes dark", v.name)
                asyncio.get_running_loop().call_later(random.uniform(60, 120), net.dead.discard, v.id)
