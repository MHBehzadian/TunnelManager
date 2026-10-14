"""Ask public resolvers (DNS-over-HTTPS, JSON API) what a name points at, to
tell when a record change has actually reached users."""

from __future__ import annotations

import asyncio

import httpx


async def _one(c: httpx.AsyncClient, url: str, fqdn: str) -> list[str] | None:
    try:
        r = await c.get(url, params={"name": fqdn, "type": "A"}, headers={"accept": "application/dns-json"})
        body = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    return [a["data"] for a in body.get("Answer", []) if a.get("type") == 1]


async def resolve_a(fqdn: str, resolvers: list[str], proxy: str | None = None) -> dict[str, list[str] | None]:
    """resolver url -> A records (None when that resolver could not be asked)."""
    async with httpx.AsyncClient(timeout=8, proxy=proxy or None) as c:
        answers = await asyncio.gather(*(_one(c, u, fqdn) for u in resolvers))
    return dict(zip(resolvers, answers, strict=True))
