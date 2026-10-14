from __future__ import annotations

import json

import httpx
import pytest

from tunnelmanager.dns import DNSError
from tunnelmanager.dns.arvan import ArvanDNS
from tunnelmanager.dns.cloudflare import CloudflareDNS
from tunnelmanager.models import DNSProvider

pytestmark = pytest.mark.asyncio


def cf_api(records):
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, req.content and json.loads(req.content)))
        assert req.headers["authorization"] == "Bearer tok"
        if req.url.path == "/client/v4/zones":
            return httpx.Response(200, json={"success": True, "result": [{"id": "z1"}]})
        if req.url.path == "/client/v4/zones/z1/dns_records" and req.method == "GET":
            name = req.url.params["name"]
            return httpx.Response(200, json={"success": True, "result": [r for r in records if r["name"] == name]})
        return httpx.Response(200, json={"success": True, "result": {}})

    return httpx.MockTransport(handler), seen


async def test_cloudflare_updates_and_removes_duplicates():
    records = [
        {"id": "r1", "name": "a.example.com", "content": "1.1.1.1"},
        {"id": "r2", "name": "a.example.com", "content": "2.2.2.2"},
    ]
    t, seen = cf_api(records)
    c = CloudflareDNS(DNSProvider(name="cf", kind="cloudflare", api_token="tok", zone="example.com"), transport=t)
    assert await c.get_a("a.example.com") == ["1.1.1.1", "2.2.2.2"]
    await c.set_a("a.example.com", "9.9.9.9", 60)
    puts = [s for s in seen if s[0] == "PUT"]
    assert puts[0][1].endswith("/dns_records/r1")
    assert puts[0][2] == {"type": "A", "name": "a.example.com", "content": "9.9.9.9", "ttl": 60, "proxied": False}
    assert [p for m, p, _ in seen if m == "DELETE"] == ["/client/v4/zones/z1/dns_records/r2"]


async def test_cloudflare_creates_missing_record_and_reports_errors():
    t, seen = cf_api([])
    c = CloudflareDNS(DNSProvider(name="cf", kind="cloudflare", api_token="tok", zone="example.com"), transport=t)
    await c.set_a("new.example.com", "9.9.9.9")
    assert any(m == "POST" for m, _, _ in seen)

    def bad(req):
        return httpx.Response(403, json={"success": False, "errors": [{"message": "Authentication error"}]})

    c = CloudflareDNS(DNSProvider(name="cf", kind="cloudflare", api_token="tok", zone="example.com"), transport=httpx.MockTransport(bad))
    with pytest.raises(DNSError, match="Authentication error"):
        await c.set_a("a.example.com", "1.1.1.1")


async def test_zone_check():
    c = CloudflareDNS(DNSProvider(name="cf", kind="cloudflare", api_token="tok", zone="example.com"))
    assert c.relative("example.com") == "@"
    assert c.relative("a.b.example.com.") == "a.b"
    with pytest.raises(DNSError):
        c.relative("evil.com")


async def test_arvan_update_existing_record():
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, req.content and json.loads(req.content)))
        assert req.headers["authorization"] == "Apikey secret"
        if req.method == "GET":
            assert req.url.params["search"] == "vpn"
            return httpx.Response(200, json={
                "data": [
                    {"id": "x1", "type": "a", "name": "vpn", "value": [{"ip": "1.1.1.1"}]},
                    {"id": "x2", "type": "cname", "name": "vpn2", "value": {"host": "a"}},
                ],
                "meta": {"last_page": 1},
            })
        return httpx.Response(200, json={"data": {}})

    c = ArvanDNS(DNSProvider(name="ar", kind="arvan", api_token="secret", zone="example.ir"), transport=httpx.MockTransport(handler))
    assert await c.get_a("vpn.example.ir") == ["1.1.1.1"]
    await c.set_a("vpn.example.ir", "5.5.5.5", 60)
    put = [s for s in seen if s[0] == "PUT"][0]
    assert put[1] == "/cdn/4.0/domains/example.ir/dns-records/x1"
    assert put[2]["value"][0]["ip"] == "5.5.5.5"
    assert put[2]["type"] == "a" and put[2]["name"] == "vpn" and put[2]["ttl"] == 120


async def test_arvan_creates_apex_record():
    seen = []

    def handler(req):
        seen.append((req.method, req.content and json.loads(req.content)))
        if req.method == "GET":
            return httpx.Response(200, json={"data": [], "meta": {"last_page": 1}})
        return httpx.Response(201, json={"data": {}})

    c = ArvanDNS(DNSProvider(name="ar", kind="arvan", api_token="Apikey k", zone="example.ir"), transport=httpx.MockTransport(handler))
    await c.set_a("example.ir", "5.5.5.5")
    post = [s for s in seen if s[0] == "POST"][0]
    assert post[1]["name"] == "@"
