"""DNS providers. Each exposes get_a(fqdn) and set_a(fqdn, ip, ttl)."""

from __future__ import annotations

from ..models import DNSProvider
from .arvan import ArvanDNS
from .base import DNSError, DNSClient
from .cloudflare import CloudflareDNS

KINDS = {"cloudflare": CloudflareDNS, "arvan": ArvanDNS}


def client_for(p: DNSProvider, proxy: str | None = None) -> DNSClient:
    try:
        cls = KINDS[p.kind]
    except KeyError:
        raise DNSError(f"unknown DNS provider kind {p.kind!r}") from None
    return cls(p, proxy=proxy)


__all__ = ["DNSClient", "DNSError", "client_for", "KINDS"]
