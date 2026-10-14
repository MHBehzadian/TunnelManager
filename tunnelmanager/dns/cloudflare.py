"""Cloudflare DNS (API v4, API token with Zone:DNS:Edit)."""

from __future__ import annotations

from .base import DNSClient, DNSError

API = "https://api.cloudflare.com/client/v4"


class CloudflareDNS(DNSClient):
    _zone_id: str | None = None

    def _c(self):
        return self.http(base_url=API, headers={"Authorization": f"Bearer {self.p.api_token}"})

    @staticmethod
    def _unwrap(r):
        try:
            body = r.json()
        except ValueError:
            raise DNSError(f"cloudflare: HTTP {r.status_code}") from None
        if not body.get("success"):
            errs = "; ".join(e.get("message", "") for e in body.get("errors", [])) or f"HTTP {r.status_code}"
            raise DNSError(f"cloudflare: {errs}")
        return body["result"]

    async def zone_id(self, c) -> str:
        if self._zone_id:
            return self._zone_id
        res = self._unwrap(await c.get("/zones", params={"name": self.p.zone.rstrip(".")}))
        if not res:
            raise DNSError(f"cloudflare: zone {self.p.zone} not found for this token")
        self._zone_id = res[0]["id"]
        return self._zone_id

    async def _records(self, c, zid: str, fqdn: str) -> list[dict]:
        return self._unwrap(
            await c.get(f"/zones/{zid}/dns_records", params={"type": "A", "name": fqdn.rstrip(".")})
        )

    async def get_a(self, fqdn: str) -> list[str]:
        async with self._c() as c:
            zid = await self.zone_id(c)
            return [r["content"] for r in await self._records(c, zid, fqdn)]

    async def set_a(self, fqdn: str, ip: str, ttl: int = 60) -> None:
        self.relative(fqdn)  # zone check
        body = {
            "type": "A",
            "name": fqdn.rstrip("."),
            "content": ip,
            "ttl": 1 if self.p.proxied else max(60, ttl),
            "proxied": bool(self.p.proxied),
        }
        async with self._c() as c:
            zid = await self.zone_id(c)
            recs = await self._records(c, zid, fqdn)
            if not recs:
                self._unwrap(await c.post(f"/zones/{zid}/dns_records", json=body))
                return
            self._unwrap(await c.put(f"/zones/{zid}/dns_records/{recs[0]['id']}", json=body))
            # one A record per name: a stale second record would keep sending
            # half the users to the dead server
            for extra in recs[1:]:
                self._unwrap(await c.delete(f"/zones/{zid}/dns_records/{extra['id']}"))

    async def verify(self) -> str:
        async with self._c() as c:
            zid = await self.zone_id(c)
        return f"zone {self.p.zone} ({zid[:8]}…)"
