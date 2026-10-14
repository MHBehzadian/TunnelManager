"""FastAPI application: REST API, live WebSocket feed and the dashboard."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import __version__
from .auth import COOKIE, SESSION_TTL, Auth
from .backpack import Driver, SSHDriver, validate_port_mapping
from .dns import KINDS, client_for
from .models import (
    ALL_TRANSPORTS,
    IRAN,
    KHAREJ,
    ONLINE,
    DNSProvider,
    Domain,
    Server,
    Settings,
    Telegram,
)
from .orchestrator import Orchestrator
from .ssh import SSHError, SSHPool
from .store import Store
from .telegram import TelegramBot

log = logging.getLogger("tunnelmanager")
STATIC = Path(__file__).parent / "static"


# ---------------------------------------------------------------- inputs
class ServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    role: str
    ip: str
    ssh_port: int = Field(22, ge=1, le=65535)
    ssh_user: str = "root"
    ssh_password: str | None = None  # None/"••••" = keep the stored one
    ssh_key: str | None = None
    priority: int = 100
    enabled: bool = True
    ports: list[str] = []
    accept_udp: bool = False
    probe_target: str = ""

    @field_validator("role")
    @classmethod
    def _role(cls, v):
        if v not in (IRAN, KHAREJ):
            raise ValueError("role must be iran or kharej")
        return v

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        v = v.strip()
        ipaddress.ip_address(v)  # A records need an IP, not a hostname
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        out = []
        for item in v:
            for p in str(item).replace("\n", ",").split(","):
                if p.strip():
                    out.append(validate_port_mapping(p))
        return out


class ProviderIn(BaseModel):
    name: str = Field(min_length=1)
    kind: str
    api_token: str | None = None
    zone: str = Field(min_length=3)
    proxied: bool = False

    @field_validator("kind")
    @classmethod
    def _kind(cls, v):
        if v not in KINDS:
            raise ValueError(f"kind must be one of {list(KINDS)}")
        return v


class DomainIn(BaseModel):
    fqdn: str = Field(min_length=3)
    provider_id: str
    kharej_id: str
    iran_id: str = ""
    ttl: int = 60
    auto_failover: bool = True


class TransportIn(BaseModel):
    transport: str
    pin: bool = True


class SwitchIn(BaseModel):
    iran_id: str


class TakeoverIn(BaseModel):
    target_id: str | None = None


class DiscoverIn(BaseModel):
    link_ids: list[str] | None = None


class LoginIn(BaseModel):
    username: str
    password: str


class SetupIn(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=6)


MASK = "••••"


def keep_secret(new: str | None, old: str) -> str:
    return old if new is None or new == MASK else new


# ------------------------------------------------------------------ app
class Hub:
    """Live WebSocket clients."""

    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def send(self, msg: dict) -> None:
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


def create_app(data_dir: str | Path | None = None, driver: Driver | None = None, demo: bool = False) -> FastAPI:
    data = Path(data_dir or os.environ.get("TM_DATA_DIR", "data")).resolve()
    data.mkdir(parents=True, exist_ok=True)
    store = Store(data / "state.json")
    auth = Auth(data / "auth.json")
    hub = Hub()
    pool = SSHPool()
    bot = TelegramBot(lambda: store.settings.tg())
    if demo:
        from .demo import SimDNS, SimNet, seed

        seed(store)
        driver = SimNet(jitter=True)
        dns_factory = SimDNS
    else:
        driver = driver or SSHDriver(pool, data / "cache", store.settings.backpack_release)

        def dns_factory(p: DNSProvider):
            return client_for(p, proxy=os.environ.get("TM_DNS_PROXY") or None)

    orch = Orchestrator(store, driver, dns_factory, notify=bot.notify, broadcast=hub.send)
    bot.handler = orch.bot_command
    monitor_enabled = os.environ.get("TM_NO_MONITOR") != "1"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        bot.start()
        tasks = [asyncio.create_task(orch.run())] if monitor_enabled else []
        if demo:
            from .demo import chaos

            tasks.append(asyncio.create_task(chaos(orch, driver)))
        await orch.emit("info", "panel", f"پنل TunnelManager {__version__} راه‌اندازی شد" + (" (حالت دمو)" if demo else ""), notify=True)
        yield
        for task in tasks:
            task.cancel()
        await bot.stop()
        await pool.close()
        store.save()

    app = FastAPI(title="TunnelManager", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.store, app.state.orch, app.state.auth, app.state.bot = store, orch, auth, bot

    def need_auth(request: Request) -> None:
        if not auth.verify(request.cookies.get(COOKIE)):
            raise HTTPException(401, "login required")

    A = [Depends(need_auth)]

    def get(coll: dict, key: str):
        obj = coll.get(key)
        if obj is None:
            raise HTTPException(404, "not found")
        return obj

    # ---- auth --------------------------------------------------------
    @app.get("/api/session")
    async def session(request: Request):
        return {
            "configured": auth.configured,
            "logged_in": auth.verify(request.cookies.get(COOKIE)),
            "username": auth.username if auth.configured else "",
            "version": __version__,
        }

    def set_cookie(resp: Response, request: Request) -> None:
        secure = request.url.scheme == "https"
        resp.set_cookie(COOKIE, auth.issue(), max_age=SESSION_TTL, httponly=True, samesite="strict", secure=secure)

    @app.post("/api/setup")
    async def setup(body: SetupIn, request: Request, response: Response):
        if auth.configured:
            raise HTTPException(409, "already configured")
        auth.set_password(body.username, body.password)
        set_cookie(response, request)
        return {"ok": True}

    @app.post("/api/login")
    async def login(body: LoginIn, request: Request, response: Response):
        if not auth.check(body.username, body.password):
            await asyncio.sleep(1)
            raise HTTPException(401, "نام کاربری یا رمز عبور اشتباه است")
        set_cookie(response, request)
        return {"ok": True}

    @app.post("/api/logout")
    async def logout(response: Response):
        response.delete_cookie(COOKIE)
        return {"ok": True}

    # ---- state -------------------------------------------------------
    def full_state() -> dict[str, Any]:
        st = store.snapshot()
        settings = store.settings.to_dict()
        tg = store.settings.tg()
        settings["telegram"] = {**tg.to_dict(), "bot_token": MASK if tg.bot_token else ""}
        return {
            **st,
            "settings": settings,
            "busy": sorted(orch.busy),
            "last_check": orch.last_check,
            "transports": ALL_TRANSPORTS,
            "version": __version__,
            "now": time.time(),
        }

    @app.get("/api/state", dependencies=A)
    async def state():
        return {**full_state(), "events": [e.to_dict() for e in store.events[-200:]]}

    # push the full state (with meta) instead of the bare snapshot
    async def broadcast(msg: dict) -> None:
        if msg.get("type") == "state":
            msg = {"type": "state", "state": full_state()}
        await hub.send(msg)

    orch.broadcast = broadcast

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        if not auth.verify(websocket.cookies.get(COOKIE)):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        hub.clients.add(websocket)
        try:
            await websocket.send_json({"type": "state", "state": full_state()})
            while True:
                await websocket.receive_text()  # keepalive pings from the page
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(websocket)

    # ---- servers -----------------------------------------------------
    @app.post("/api/servers", dependencies=A)
    async def add_server(body: ServerIn):
        if any(s.ip == body.ip and s.role == body.role for s in store.servers.values()):
            raise HTTPException(409, "این آی‌پی قبلا اضافه شده")
        srv = Server(**{**body.model_dump(), "ssh_password": body.ssh_password or "", "ssh_key": body.ssh_key or ""})
        if srv.role == IRAN:
            srv.ports = []
        store.servers[srv.id] = srv
        created = store.ensure_links()
        await orch.emit("info", "server", f"سرور {'داخل' if srv.role == IRAN else 'خارج'} {srv.name} ({srv.ip}) اضافه شد", notify=False, server=srv.id)
        orch.spawn(probe_server(srv))
        return {"server": srv.public(), "links_created": len(created)}

    async def probe_server(srv: Server) -> None:
        try:
            srv.ssh_latency_ms = round(await driver.ping(srv), 1)
            srv.status, srv.fail_count, srv.last_seen, srv.error = ONLINE, 0, time.time(), ""
        except (SSHError, OSError) as e:
            srv.status, srv.error = "offline", str(e)
        await orch.changed()

    @app.put("/api/servers/{sid}", dependencies=A)
    async def edit_server(sid: str, body: ServerIn):
        srv = get(store.servers, sid)
        old_ports = list(srv.ports)
        old_conn = (srv.ip, srv.ssh_port, srv.ssh_user)
        upd = body.model_dump()
        upd["ssh_password"] = keep_secret(body.ssh_password, srv.ssh_password)
        upd["ssh_key"] = keep_secret(body.ssh_key, srv.ssh_key)
        upd["role"] = srv.role  # role is fixed: links depend on it
        for k, v in upd.items():
            setattr(srv, k, v)
        if (srv.ip, srv.ssh_port, srv.ssh_user) != old_conn:
            pool.drop(srv.id)
            srv.backpack_version = ""
        await orch.changed()
        if srv.role == KHAREJ and srv.ports != old_ports:
            orch.spawn(orch.ports_changed(srv.id))
        orch.spawn(probe_server(srv))
        return {"server": srv.public()}

    @app.delete("/api/servers/{sid}", dependencies=A)
    async def del_server(sid: str):
        srv = get(store.servers, sid)
        if any(d.kharej_id == sid for d in store.domains.values()):
            raise HTTPException(409, "اول دامنه‌های متصل به این سرور را حذف یا جابه‌جا کنید")
        links = store.remove_server(sid)
        await orch.emit("warning", "server", f"سرور {srv.name} حذف شد", notify=False)
        orch.spawn(orch.remove_links(links))
        pool.drop(sid)
        return {"ok": True}

    @app.post("/api/servers/{sid}/install", dependencies=A)
    async def install(sid: str):
        srv = get(store.servers, sid)
        try:
            srv.backpack_version = ""
            srv.backpack_version = await driver.ensure_installed(srv, True)
        except Exception as e:
            raise HTTPException(502, str(e))
        await orch.changed()
        return {"version": srv.backpack_version}

    @app.post("/api/servers/{sid}/test", dependencies=A)
    async def test_server(sid: str):
        srv = get(store.servers, sid)
        await probe_server(srv)
        return {"status": srv.status, "latency_ms": srv.ssh_latency_ms, "error": srv.error}

    # ---- kharej failover ----------------------------------------------
    @app.post("/api/kharej/{sid}/takeover", dependencies=A)
    async def takeover(sid: str, body: TakeoverIn):
        srv = get(store.servers, sid)
        if srv.role != KHAREJ:
            raise HTTPException(400, "only kharej servers")
        target = store.servers.get(body.target_id) if body.target_id else None
        ok = await orch.takeover(srv, target)
        return {"ok": ok}

    @app.post("/api/kharej/{sid}/release", dependencies=A)
    async def release(sid: str):
        srv = get(store.servers, sid)
        if sid not in store.takeover:
            raise HTTPException(400, "not taken over")
        await orch.release(srv)
        return {"ok": True}

    # ---- links -------------------------------------------------------
    @app.post("/api/discover", dependencies=A)
    async def discover(body: DiscoverIn):
        orch.spawn(orch.discover_all(body.link_ids))
        return {"started": True}

    @app.post("/api/links/{lid}/transport", dependencies=A)
    async def set_transport(lid: str, body: TransportIn):
        link = get(store.links, lid)
        if body.transport not in ALL_TRANSPORTS:
            raise HTTPException(400, "unknown transport")
        if lid in orch.busy:
            raise HTTPException(409, "عملیات دیگری روی این تانل در جریان است")
        orch.spawn(orch.set_transport(link, body.transport, body.pin))
        return {"started": True}

    @app.post("/api/links/{lid}/retest", dependencies=A)
    async def retest(lid: str):
        link = get(store.links, lid)
        if lid in orch.busy:
            raise HTTPException(409, "عملیات دیگری روی این تانل در جریان است")
        orch.spawn(orch.discover(link))
        return {"started": True}

    @app.post("/api/links/{lid}/pin", dependencies=A)
    async def pin(lid: str, body: dict):
        link = get(store.links, lid)
        link.pinned = bool(body.get("pinned"))
        await orch.changed()
        return {"pinned": link.pinned}

    @app.post("/api/check", dependencies=A)
    async def check_now():
        orch.wake()
        return {"ok": True}

    # ---- DNS providers -------------------------------------------------
    @app.post("/api/providers", dependencies=A)
    async def add_provider(body: ProviderIn):
        p = DNSProvider(name=body.name, kind=body.kind, api_token=body.api_token or "", zone=body.zone.strip().rstrip(".").lower(), proxied=body.proxied)
        store.providers[p.id] = p
        await orch.changed()
        return {"provider": p.public()}

    @app.put("/api/providers/{pid}", dependencies=A)
    async def edit_provider(pid: str, body: ProviderIn):
        p = get(store.providers, pid)
        p.name, p.kind, p.zone, p.proxied = body.name, body.kind, body.zone.strip().rstrip(".").lower(), body.proxied
        p.api_token = keep_secret(body.api_token, p.api_token)
        await orch.changed()
        return {"provider": p.public()}

    @app.delete("/api/providers/{pid}", dependencies=A)
    async def del_provider(pid: str):
        get(store.providers, pid)
        if any(d.provider_id == pid for d in store.domains.values()):
            raise HTTPException(409, "دامنه‌هایی از این حساب استفاده می‌کنند")
        del store.providers[pid]
        await orch.changed()
        return {"ok": True}

    @app.post("/api/providers/{pid}/verify", dependencies=A)
    async def verify_provider(pid: str):
        p = get(store.providers, pid)
        try:
            return {"ok": True, "detail": await dns_factory(p).verify()}
        except Exception as e:
            raise HTTPException(502, str(e))

    # ---- domains -----------------------------------------------------
    async def adopt_record(d: Domain) -> None:
        """Read the live A record; if it already points at one of our Iran
        servers, take that as the starting point instead of changing DNS."""
        p = store.providers.get(d.provider_id)
        if not p:
            return
        try:
            ips = await dns_factory(p).get_a(d.fqdn)
        except Exception as e:
            d.error = f"DNS read: {e}"
            await orch.changed()
            return
        d.current_ip = ips[0] if ips else ""
        if not d.iran_id:
            match = next((s for s in store.irans() if s.ip in ips), None)
            if match:
                d.iran_id = match.id
        await orch.changed()
        orch.wake()

    def check_domain(body: DomainIn) -> None:
        p = get(store.providers, body.provider_id)
        k = get(store.servers, body.kharej_id)
        if k.role != KHAREJ:
            raise HTTPException(400, "kharej_id must be a kharej server")
        if body.iran_id and get(store.servers, body.iran_id).role != IRAN:
            raise HTTPException(400, "iran_id must be an Iran server")
        try:
            client_for(p).relative(body.fqdn)
        except Exception as e:
            raise HTTPException(400, str(e))

    @app.post("/api/domains", dependencies=A)
    async def add_domain(body: DomainIn):
        check_domain(body)
        d = Domain(**body.model_dump())
        d.fqdn = d.fqdn.strip().rstrip(".").lower()
        store.domains[d.id] = d
        await orch.emit("info", "domain", f"دامنه {d.fqdn} اضافه شد", notify=False, domain=d.id)
        orch.spawn(adopt_record(d))
        return {"domain": d.to_dict()}

    @app.put("/api/domains/{did}", dependencies=A)
    async def edit_domain(did: str, body: DomainIn):
        d = get(store.domains, did)
        check_domain(body)
        d.fqdn = body.fqdn.strip().rstrip(".").lower()
        d.provider_id, d.kharej_id, d.ttl, d.auto_failover = body.provider_id, body.kharej_id, body.ttl, body.auto_failover
        await orch.changed()
        orch.wake()
        return {"domain": d.to_dict()}

    @app.delete("/api/domains/{did}", dependencies=A)
    async def del_domain(did: str):
        get(store.domains, did)
        del store.domains[did]
        await orch.changed()
        return {"ok": True}

    @app.post("/api/domains/{did}/switch", dependencies=A)
    async def switch(did: str, body: SwitchIn):
        d = get(store.domains, did)
        iran = get(store.servers, body.iran_id)
        if iran.role != IRAN:
            raise HTTPException(400, "not an Iran server")
        ok = await orch.switch_domain(d, iran, "")
        if not ok:
            raise HTTPException(502, d.error or "DNS update failed")
        await orch.changed()
        orch.wake()
        return {"ok": True}

    @app.post("/api/domains/{did}/sync", dependencies=A)
    async def sync(did: str):
        d = get(store.domains, did)
        await adopt_record(d)
        return {"current_ip": d.current_ip, "error": d.error}

    # ---- settings ----------------------------------------------------
    @app.get("/api/settings", dependencies=A)
    async def get_settings():
        return full_state()["settings"]

    @app.put("/api/settings", dependencies=A)
    async def put_settings(body: dict):
        cur = store.settings.to_dict()
        tg_in = body.pop("telegram", None)
        cur.update({k: v for k, v in body.items() if k in cur})
        new = Settings.from_dict(cur)
        bad = [t for t in new.candidate_transports if t not in ALL_TRANSPORTS]
        if bad or not new.candidate_transports:
            raise HTTPException(400, f"invalid transports: {bad}")
        new.check_interval = max(10, int(new.check_interval))
        new.fail_threshold = max(1, int(new.fail_threshold))
        new.test_timeout = max(5, int(new.test_timeout))
        if tg_in is not None:
            old = store.settings.tg()
            tg = Telegram.from_dict({**old.to_dict(), **tg_in})
            tg.bot_token = keep_secret(tg_in.get("bot_token"), old.bot_token)
            tg.chat_ids = [str(c).strip() for c in tg.chat_ids if str(c).strip()]
            new.telegram = tg.to_dict()
        store.settings = new
        if isinstance(driver, SSHDriver):
            driver.release = new.backpack_release or "latest"
        await orch.changed()
        return full_state()["settings"]

    @app.post("/api/telegram/test", dependencies=A)
    async def tg_test():
        try:
            await bot.test(store.settings.tg())
        except Exception as e:
            raise HTTPException(502, str(e))
        return {"ok": True}

    # ---- static UI -----------------------------------------------------
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    return app

