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
        assert c.get("/api/settings").json()["observe_only"] is True  # safe by default
        assert c.put("/api/settings", json={"auto_mesh": True}).status_code == 200

        k = c.post("/api/servers", json={"name": "K", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "pw"}).json()
        assert k["server"]["ssh_password"] == "••••"
        assert c.post("/api/servers", json={"name": "I", "role": "iran", "ip": "10.0.0.2"}).status_code == 200
        assert c.post("/api/servers", json={"name": "X", "role": "iran", "ip": "not-an-ip"}).status_code == 422
        sid = k["server"]["id"]

        # editing with the mask keeps the stored secret
        c.put(f"/api/servers/{sid}", json={"name": "K2", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "••••"})
        store = c.app.state.store
        assert store.servers[sid].ssh_password == "pw" and store.servers[sid].name == "K2"

        # a pair gets an (unbuilt) tunnel; ports are set on it, Iran side
        st = c.get("/api/state").json()
        assert len(st["links"]) == 1
        lid = st["links"][0]["id"]
        assert c.put(f"/api/links/{lid}", json={"ports": ["443\n8443=2096"], "label": "main"}).status_code == 200
        assert store.links[lid].ports == ["443", "8443=2096"]
        assert c.put(f"/api/links/{lid}", json={"ports": ["443;reboot"]}).status_code == 422
        assert c.put(f"/api/links/{lid}", json={"allowed": ["bogus"]}).status_code == 422

        p = c.post("/api/providers", json={"name": "ar", "kind": "arvan", "api_token": "tok", "zone": "Example.ir."}).json()["provider"]
        assert p["zone"] == "example.ir" and p["api_token"] == "••••"
        d = c.post("/api/domains", json={"fqdn": "a.example.ir", "provider_id": p["id"], "kharej_id": sid})
        assert d.status_code == 200
        did = d.json()["domain"]["id"]
        assert c.post("/api/domains", json={"fqdn": "a.other.com", "provider_id": p["id"], "kharej_id": sid}).status_code == 400
        assert c.post("/api/domains", json={"fqdn": "b.example.ir", "provider_id": p["id"], "ports": ["443;x"]}).status_code == 422
        assert c.put(f"/api/domains/{did}", json={"fqdn": "a.example.ir", "provider_id": p["id"], "group": [lid]}).status_code == 200
        assert store.domains[did].group == [lid]

        st = c.get("/api/state").json()
        assert all(x["token"] == "" and "iran_base" not in x for x in st["links"])  # secrets never leave
        assert st["domains"][0]["effective_group"] == [lid]
        assert c.delete(f"/api/servers/{sid}").status_code == 409  # a domain still uses it

        # canvas layout persists
        assert c.put("/api/layout", json={"positions": {sid: [10, 20], "nope": [1, 1]}}).status_code == 200
        assert c.get("/api/state").json()["layout"] == {sid: [10.0, 20.0]}

        s = c.put("/api/settings", json={"check_interval": 3, "failback_after": 600, "candidate_transports": ["tcpmux", "quic"], "telegram": {"bot_token": "123:abc", "chat_ids": ["1", " "]}}).json()
        assert s["check_interval"] == 10 and s["telegram"]["bot_token"] == "••••" and s["telegram"]["chat_ids"] == ["1"]
        assert store.settings.tg().bot_token == "123:abc" and store.settings.failback_after == 600
        assert c.put("/api/settings", json={"candidate_transports": ["bogus"]}).status_code == 400

        assert c.get("/").status_code == 200
        c.post("/api/logout")
        c.cookies.clear()
        assert c.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401
        assert c.post("/api/login", json={"username": "admin", "password": "secret1"}).status_code == 200

    # state survives a restart
    with client(tmp_path) as c:
        c.post("/api/login", json={"username": "admin", "password": "secret1"})
        st = c.get("/api/state").json()
        assert len(st["servers"]) == 2 and st["links"][0]["ports"] == ["443", "8443=2096"]
