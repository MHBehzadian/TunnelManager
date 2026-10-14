from __future__ import annotations

import httpx

from ..models import DNSProvider


class DNSError(Exception):
    pass


class DNSClient:
    def __init__(self, provider: DNSProvider, proxy: str | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self.p = provider
        self.proxy = proxy or None
        self.transport = transport  # tests inject a MockTransport

    def http(self, **kw) -> httpx.AsyncClient:
        if self.transport is not None:
            return httpx.AsyncClient(transport=self.transport, timeout=20, **kw)
        return httpx.AsyncClient(timeout=20, proxy=self.proxy, **kw)

    def relative(self, fqdn: str) -> str:
        """Record name relative to the zone ("@" for the apex)."""
        fqdn = fqdn.rstrip(".").lower()
        zone = self.p.zone.rstrip(".").lower()
        if fqdn == zone:
            return "@"
        if not fqdn.endswith("." + zone):
            raise DNSError(f"{fqdn} is not inside zone {zone}")
        return fqdn[: -len(zone) - 1]

    async def get_a(self, fqdn: str) -> list[str]:
        raise NotImplementedError

    async def set_a(self, fqdn: str, ip: str, ttl: int = 60) -> None:
        raise NotImplementedError

    async def verify(self) -> str:
        """Check the credentials and zone; returns a short description."""
        raise NotImplementedError
