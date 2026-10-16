from __future__ import annotations

import asyncio

import pytest

from tunnelmanager.demo import SimDNS as FakeDNS
from tunnelmanager.demo import SimNet as FakeNet
from tunnelmanager.models import IRAN, KHAREJ, DNSProvider, Domain, Server
from tunnelmanager.orchestrator import Orchestrator
from tunnelmanager.store import Store

__all__ = ["FakeDNS", "FakeNet", "World"]


class World:
    def __init__(self):
        FakeDNS.records, FakeDNS.calls, FakeDNS.fail = {}, [], False
        self.store = Store(None)
        st = self.store
        st.settings.fail_threshold = 2
        st.settings.observe_only = False
        st.settings.auto_mesh = True
        st.settings.candidate_transports = ["tcpmux", "wsmux", "tcp", "quic"]
        self.k1 = Server(name="K1", role=KHAREJ, ip="10.0.1.1", priority=1)
        self.k2 = Server(name="K2", role=KHAREJ, ip="10.0.1.2", priority=2)
        self.i1 = Server(name="I1", role=IRAN, ip="10.0.2.1", priority=1)
        self.i2 = Server(name="I2", role=IRAN, ip="10.0.2.2", priority=2)
        for s in (self.k1, self.k2, self.i1, self.i2):
            st.servers[s.id] = s
        st.ensure_links()
        for x in st.links.values():
            x.ports = ["443", "8443=2096"] if x.kharej_id == self.k1.id else ["2053"]
        self.prov = DNSProvider(name="ar", kind="arvan", api_token="x", zone="example.ir")
        st.providers[self.prov.id] = self.prov
        self.dom = Domain(fqdn="a.example.ir", provider_id=self.prov.id, kharej_id=self.k1.id)
        st.domains[self.dom.id] = self.dom
        self.net = FakeNet()
        self.notes: list[str] = []
        self.answers: dict[str, list[str]] = {}

        async def resolver(fqdn, resolvers, proxy=None):
            return {"r1": self.answers.get(fqdn, [])}

        self.orch = Orchestrator(st, self.net, FakeDNS, notify=self.notes.append, resolver=resolver)

    def link(self, iran, kharej):
        return self.store.link_for(iran.id, kharej.id)

    def age(self, seconds: float):
        """Pretend everything happened `seconds` earlier."""
        for x in self.store.links.values():
            x.last_fail -= seconds if x.last_fail else 0
            x.up_since -= seconds if x.up_since else 0
            x.flaps = [t - seconds for t in x.flaps]
        for d in self.store.domains.values():
            d.last_switch -= seconds if d.last_switch else 0

    async def settle(self, rounds: int = 3):
        """Run check cycles and let spawned repairs finish."""
        for _ in range(rounds):
            await self.orch.check_all()
            while self.orch.tasks:
                await asyncio.gather(*list(self.orch.tasks), return_exceptions=True)

    def said(self, text: str) -> bool:
        return any(text in n for n in self.notes)


@pytest.fixture
def world():
    return World()
