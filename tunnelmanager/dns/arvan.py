"""ArvanCloud DNS (CDN API 4.0, machine user API key)."""

from __future__ import annotations

from .base import DNSClient, DNSError

API = "https://napi.arvancloud.ir/cdn/4.0"


class ArvanDNS(DNSClient):
    def _c(self):
        key = self.p.api_token.strip()
        if not key.lower().startswith("apikey "):
            key = f"Apikey {key}"
        return self.http(base_url=API, headers={"Authorization": key, "Accept": "application/json"})

    @staticmethod
    def _json(r):
        if r.status_code >= 400:
            try:
                msg = r.json().get("message") or r.text
            except ValueError:
                msg = r.text
            raise DNSError(f"arvan: HTTP {r.status_code}: {str(msg)[:200]}")
        return r.json()

    @property
    def _base(self) -> str:
        return f"/domains/{self.p.zone.rstrip('.')}/dns-records"

    async def _records(self, c, fqdn: str) -> list[dict]:
        name = self.relative(fqdn)
        out, page = [], 1
        while True:
            body = self._json(await c.get(self._base, params={"search": name, "page": page, "per_page": 100}))
            for r in body.get("data", []):
                if str(r.get("type", "")).lower() == "a" and r.get("name") == name:
                    out.append(r)
            meta = body.get("meta") or {}
            if page >= int(meta.get("last_page") or 1):
                return out
            page += 1

    async def get_a(self, fqdn: str) -> list[str]:
        async with self._c() as c:
            recs = await self._records(c, fqdn)
        return [v.get("ip") for r in recs for v in (r.get("value") or []) if v.get("ip")]

    async def set_a(self, fqdn: str, ip: str, ttl: int = 60) -> None:
        name = self.relative(fqdn)
        body = {
            "type": "a",
            "name": name,
            "value": [{"ip": ip, "port": None, "weight": 100, "country": ""}],
            "ttl": max(120, ttl),  # Arvan's minimum
            "cloud": bool(self.p.proxied),
            "upstream_https": "default",
            "ip_filter_mode": {"count": "single", "order": "none", "geo_filter": "none"},
        }
        async with self._c() as c:
            recs = await self._records(c, fqdn)
            if not recs:
                self._json(await c.post(self._base, json=body))
                return
            self._json(await c.put(f"{self._base}/{recs[0]['id']}", json=body))
            for extra in recs[1:]:
                self._json(await c.delete(f"{self._base}/{extra['id']}"))

    async def verify(self) -> str:
        async with self._c() as c:
            self._json(await c.get(self._base, params={"per_page": 1}))
        return f"zone {self.p.zone}"
