from __future__ import annotations

import os

from fastapi.testclient import TestClient

from tests.conftest import FakeNet
from tunnelmanager.app import create_app


def client(tmp_path):
    os.environ["TM_NO_MONITOR"] = "1"
    app = create_app(tmp_path, driver=FakeNet())
    return TestClient(app)


def test_setup_login_and_crud(tmp_path):
    with client(tmp_path) as c:
        assert c.get("/api/session").json()["configured"] is False
        assert c.get("/api/state").status_code == 401
        assert c.post("/api/setup", json={"username": "admin", "password": "secret1"}).status_code == 200
        assert c.post("/api/setup", json={"username": "x", "password": "secret2"}).status_code == 409
        assert c.get("/api/state").status_code == 200

        k = c.post("/api/servers", json={"name": "K", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "pw", "ports": ["443\n8443=2096"]}).json()
        assert k["server"]["ports"] == ["443", "8443=2096"]
        assert k["server"]["ssh_password"] == "••••"
        r = c.post("/api/servers", json={"name": "I", "role": "iran", "ip": "10.0.0.2"})
        assert r.json()["links_created"] == 1
        bad = c.post("/api/servers", json={"name": "X", "role": "iran", "ip": "not-an-ip"})
        assert bad.status_code == 422
        inj = c.post("/api/servers", json={"name": "X", "role": "kharej", "ip": "10.0.0.9", "ports": ["443;reboot"]})
        assert inj.status_code == 422

        # editing with the mask keeps the stored secret
        sid = k["server"]["id"]
        c.put(f"/api/servers/{sid}", json={"name": "K2", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "••••", "ports": ["443"]})
        assert c.app.state.store.servers[sid].ssh_password == "pw"
        assert c.app.state.store.servers[sid].name == "K2"

        p = c.post("/api/providers", json={"name": "cf", "kind": "cloudflare", "api_token": "tok", "zone": "Example.com."}).json()["provider"]
        assert p["zone"] == "example.com" and p["api_token"] == "••••"
        d = c.post("/api/domains", json={"fqdn": "a.example.com", "provider_id": p["id"], "kharej_id": sid})
        assert d.status_code == 200
        out = c.post("/api/domains", json={"fqdn": "a.other.com", "provider_id": p["id"], "kharej_id": sid})
        assert out.status_code == 400

        st = c.get("/api/state").json()
        assert len(st["servers"]) == 2 and len(st["links"]) == 1 and len(st["domains"]) == 1
        assert all(x["token"] == "" for x in st["links"])  # secrets never leave the panel
        assert c.delete(f"/api/servers/{sid}").status_code == 409  # domain still uses it

        s = c.put("/api/settings", json={"check_interval": 3, "candidate_transports": ["tcpmux", "quic"], "telegram": {"bot_token": "123:abc", "chat_ids": ["1", " "]}}).json()
        assert s["check_interval"] == 10 and s["telegram"]["bot_token"] == "••••" and s["telegram"]["chat_ids"] == ["1"]
        assert c.app.state.store.settings.tg().bot_token == "123:abc"
        assert c.put("/api/settings", json={"candidate_transports": ["bogus"]}).status_code == 400

        assert c.get("/").status_code == 200
        c.post("/api/logout")
        c.cookies.clear()
        assert c.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401
        assert c.post("/api/login", json={"username": "admin", "password": "secret1"}).status_code == 200

    # state survives a restart
    with client(tmp_path) as c:
        c.post("/api/login", json={"username": "admin", "password": "secret1"})
        assert len(c.get("/api/state").json()["servers"]) == 2
