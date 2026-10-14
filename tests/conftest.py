from __future__ import annotations

import pytest

from tunnelmanager.models import IRAN, KHAREJ, DNSProvider, Domain, Server
from tunnelmanager.orchestrator import Orchestrator
from tunnelmanager.demo import SimDNS as FakeDNS
from tunnelmanager.demo import SimNet as FakeNet
from tunnelmanager.store import Store


class World:
    def __init__(self):
        FakeDNS.records, FakeDNS.calls, FakeDNS.fail = {}, [], False
        self.store = Store(None)
        st = self.store
        st.settings.fail_threshold = 2
        st.settings.candidate_transports = ["tcpmux", "wsmux", "tcp", "quic"]
        self.k1 = Server(name="K1", role=KHAREJ, ip="10.0.1.1", ports=["443", "8443=2096"], priority=1)
        self.k2 = Server(name="K2", role=KHAREJ, ip="10.0.1.2", ports=["2053"], priority=2)
        self.i1 = Server(name="I1", role=IRAN, ip="10.0.2.1", priority=1)
        self.i2 = Server(name="I2", role=IRAN, ip="10.0.2.2", priority=2)
        for s in (self.k1, self.k2, self.i1, self.i2):
            st.servers[s.id] = s
        st.ensure_links()
        self.prov = DNSProvider(name="cf", kind="cloudflare", api_token="x", zone="example.com")
        st.providers[self.prov.id] = self.prov
        self.dom = Domain(fqdn="a.example.com", provider_id=self.prov.id, kharej_id=self.k1.id)
        st.domains[self.dom.id] = self.dom
        self.net = FakeNet()
        self.notes: list[str] = []
        self.orch = Orchestrator(st, self.net, FakeDNS, notify=self.notes.append)

    def link(self, iran, kharej):
        return self.store.link_for(iran.id, kharej.id)

    async def settle(self, rounds: int = 3):
        """Run check cycles and let spawned repairs finish."""
        import asyncio

        for _ in range(rounds):
            await self.orch.check_all()
            while self.orch.tasks:
                await asyncio.gather(*list(self.orch.tasks), return_exceptions=True)


@pytest.fixture
def world():
    return World()
