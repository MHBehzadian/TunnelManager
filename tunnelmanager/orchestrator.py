"""The brain: discovery, adoption, health checks and the failover policy.

Failover policy
---------------
Every domain has a *failover group*: the tunnels it may use, in order of
preference. The first is the primary. The domain's A record points at the
Iran server of the tunnel it currently uses; all the other tunnels in the
group stay connected as hot standbys.

1. The current tunnel is down, its Iran server is down, or it keeps dropping
   (flapping) -> move the domain to the first healthy tunnel in its group,
   immediately:
   * on another Iran server: change the A record (Cloudflare / Arvan), then
     watch public resolvers and report when the new server is actually
     behind the domain;
   * on the same Iran server (e.g. to another kharej, or a spare tunnel on
     another transport): hand the forwarded ports over to it, no DNS change.
2. Broken tunnels whose two servers are reachable are rebuilt in the
   background with other transports.
3. Once the primary has been healthy for ``failback_after`` seconds (10 min)
   without a single drop, traffic returns to it. Nothing moves without a
   reason: never away from a working tunnel, never back onto one that
   dropped recently.

Every step is reported to Telegram.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Awaitable, Callable

from .backpack import DeployError, Driver, Found, Probe, listen_ports, split_ports, unit_name
from .dns import DNSClient
from .dns.resolve import resolve_a
from .models import (
    IRAN,
    KHAREJ,
    L_DEGRADED,
    L_DOWN,
    L_PENDING,
    L_TESTING,
    L_UP,
    OFFLINE,
    ONLINE,
    Domain,
    Event,
    Link,
    Server,
    TestResult,
)
from .ssh import SSHError
from .store import Store, first_port
from .telegram import ICON, esc

log = logging.getLogger(__name__)

REPAIR_BACKOFF = 300  # seconds before a failed repair is retried
PROPAGATION_GIVE_UP = 3600


def fmt_dur(seconds: float) -> str:
    s = int(seconds)
    if s < 90:
        return f"{s} ثانیه"
    if s < 5400:
        return f"{round(s / 60)} دقیقه"
    return f"{s / 3600:.1f} ساعت"


class Orchestrator:
    def __init__(
        self,
        store: Store,
        driver: Driver,
        dns_factory: Callable[..., DNSClient],
        notify: Callable[[str], None] = lambda text: None,
        broadcast: Callable[[dict], Awaitable[None]] | None = None,
        resolver: Callable[..., Awaitable[dict]] | None = None,
    ):
        self.store = store
        self.driver = driver
        self.dns_factory = dns_factory
        self.notify = notify
        self.broadcast = broadcast
        self.resolver = resolver or resolve_a
        self.busy: set[str] = set()  # link ids with an operation in flight
        self.repair_after: dict[str, float] = {}
        self.last_probe: dict[str, Probe] = {}
        self.prev_ok: dict[str, bool] = {}
        self.flap_reported: set[str] = set()
        self.suggested: dict[str, str] = {}  # observe mode: domain id -> what was proposed
        self.last_read: dict[str, float] = {}  # domain id -> when its record was last read
        self.tasks: set[asyncio.Task] = set()
        self._check_lock = asyncio.Lock()
        self._dns_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self.last_check: float = 0
        self.last_scan: float = 0

    # ------------------------------------------------------------------ util
    @property
    def s(self):
        return self.store.settings

    def name(self, sid: str) -> str:
        srv = self.store.servers.get(sid)
        return srv.name if srv else sid

    def link_label(self, link: Link | None) -> str:
        if link is None:
            return "—"
        tag = f" «{link.label}»" if link.label else ""
        return f"{self.name(link.kharej_id)} ⇄ {self.name(link.iran_id)}{tag}"

    async def emit(self, level: str, kind: str, message: str, notify: bool = True, **refs: str) -> Event:
        ev = Event(level=level, kind=kind, message=message, refs=refs)
        self.store.events.append(ev)
        del self.store.events[:-1000]
        log.info("[%s] %s", level, message)
        if notify:
            self.notify(f"{ICON.get(level, '')} {esc(message)}")
        self.store.save()
        await self.push({"type": "event", "event": ev.to_dict()})
        await self.push()  # the event usually comes with a state change
        return ev

    async def push(self, msg: dict | None = None) -> None:
        if self.broadcast:
            try:
                await self.broadcast(msg or {"type": "state", "state": self.store.snapshot()})
            except Exception:  # a websocket hiccup must never stop the monitor
                log.exception("broadcast failed")

    async def changed(self) -> None:
        self.store.save()
        await self.push()

    def spawn(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self.tasks.add(t)

        def done(task: asyncio.Task) -> None:
            self.tasks.discard(task)
            if not task.cancelled() and task.exception():
                log.error("background task failed", exc_info=task.exception())

        t.add_done_callback(done)
        return t

    def pair(self, link: Link) -> tuple[Server | None, Server | None]:
        return self.store.servers.get(link.iran_id), self.store.servers.get(link.kharej_id)

    def usable(self, srv: Server | None) -> bool:
        return bool(srv and srv.enabled and srv.status == ONLINE)

    def is_down(self, srv: Server | None) -> bool:
        return bool(srv and srv.status == OFFLINE and srv.fail_count >= self.s.fail_threshold)

    def flapping(self, link: Link) -> bool:
        return link.flapping(self.s.flap_window, self.s.flap_count)

    def healthy(self, link: Link | None) -> bool:
        if link is None or link.status != L_UP or link.id in self.busy:
            return False
        iran, _ = self.pair(link)
        return self.usable(iran) and not self.flapping(link)

    def stable(self, link: Link | None) -> bool:
        """Healthy, and not a single drop for failback_after seconds."""
        if not self.healthy(link):
            return False
        assert link
        t = time.time()
        return t - link.last_fail >= self.s.failback_after and t - link.up_since >= self.s.failback_after

    def broken(self, link: Link) -> str:
        """Why a link must not carry traffic now ("" if it may)."""
        iran, _ = self.pair(link)
        if iran is None or self.is_down(iran):
            return f"سرور داخل {self.name(link.iran_id)} در دسترس نیست"
        if link.status in (L_DOWN, L_PENDING):
            return f"تانل {self.link_label(link)} قطع است"
        if self.flapping(link):
            return f"تانل {self.link_label(link)} مدام قطع و وصل می‌شود"
        return ""

    # ------------------------------------------------------------ deployment
    async def _install(self, srv: Server) -> None:
        if srv.backpack_version:
            return
        srv.backpack_version = await self.driver.ensure_installed(srv, self.s.install_backpack)

    async def _ensure_probe(self, link: Link) -> None:
        if link.probe_port:
            return
        iran = self.store.servers.get(link.iran_id)
        busy: set[int] = set()
        if iran:
            try:
                busy = await self.driver.listening(iran)
            except (SSHError, OSError):
                pass
        port = self.store.free_port(link.iran_id, self.s.probe_port_base)
        while port in busy:
            port += 1
        link.probe_port = port

    async def _ports_taken(self, link: Link) -> str:
        """Before a tunnel is built for the first time: are any of the ports
        it would listen on already used on the Iran server? A live server
        must never have a port taken away from what is running there."""
        if link.built:
            return ""
        iran = self.store.servers.get(link.iran_id)
        if iran is None:
            return ""
        try:
            busy = await self.driver.listening(iran)
        except (SSHError, OSError) as e:
            return f"پورت‌های آزاد {iran.name} بررسی نشد: {e}"
        wanted = {link.tunnel_port} | listen_ports(self.store.link_ports(link))
        if link.probe_port:
            wanted.add(link.probe_port)
        clash = sorted(wanted & busy)
        if clash:
            return f"پورت {', '.join(map(str, clash[:8]))} روی {iran.name} از قبل در حال استفاده است"
        return ""

    async def _try(self, link: Link, transport: str, ports: list[str]) -> TestResult:
        iran, kharej = self.pair(link)
        assert iran and kharej
        await self._ensure_probe(link)
        try:
            await self.driver.deploy(link, iran, kharej, transport, ports)
            p = await self.driver.wait_up(link, iran, self.s.test_timeout)
        except (SSHError, DeployError, OSError) as e:
            p = Probe(ok=False, error=str(e))
        r = TestResult(transport=transport, ok=p.ok, latency_ms=p.latency_ms, connect_s=p.connect_s, error=p.error)
        link.tests[transport] = r.to_dict()
        await self.push({"type": "test", "link_id": link.id, "result": r.to_dict()})
        return r

    def _mark_up(self, link: Link, transport: str, latency: float | None) -> None:
        t = time.time()
        link.transport = transport
        if link.status != L_UP:
            link.up_since = t
        link.status = L_UP
        link.latency_ms = latency
        link.fail_count = 0
        link.last_ok = t
        link.last_change = t
        link.error = ""
        link.verified = True
        self.prev_ok[link.id] = True
        link.built = True
        link.record(latency)

    async def discover(self, link: Link, transports: list[str] | None = None) -> bool:
        """Test every candidate transport on a pair, deploy the fastest."""
        if link.id in self.busy:
            return False
        iran, kharej = self.pair(link)
        if not (iran and kharej):
            return False
        self.busy.add(link.id)
        prev = link.status
        link.status = L_TESTING
        await self.changed()
        try:
            try:
                await asyncio.gather(self._install(iran), self._install(kharej))
            except (SSHError, DeployError, OSError) as e:
                link.status, link.error = L_DOWN, f"install: {e}"
                await self.emit("error", "install", f"نصب BackPack روی {self.link_label(link)} ناموفق بود: {e}", link=link.id)
                return False
            taken = await self._ports_taken(link)
            if taken:
                link.status, link.error = (L_PENDING if not link.built else L_DOWN), taken
                await self.emit("error", "discover", f"تانل {self.link_label(link)} ساخته نشد: {taken}", link=link.id)
                return False
            cands = transports or link.allowed or self.s.candidate_transports
            await self.emit("info", "discover", f"تست پروتکل‌ها روی {self.link_label(link)}: {', '.join(cands)}", notify=False, link=link.id)
            results = [await self._try(link, t, []) for t in cands]
            good = sorted((r for r in results if r.ok), key=lambda r: r.latency_ms or 9e9)
            if link.pinned and link.transport and any(r.transport == link.transport for r in good):
                best = next(r for r in good if r.transport == link.transport)
            else:
                best = good[0] if good else None
            if best is None:
                link.status, link.error = L_DOWN, "no transport worked"
                link.transport = link.transport or cands[0]
                link.fail_count = self.s.fail_threshold
                self.repair_after[link.id] = time.time() + REPAIR_BACKOFF
                if link.managed:
                    await self.driver.stop(link, iran, kharej)
                await self.emit("error", "discover", f"هیچ پروتکلی بین {self.link_label(link)} کار نکرد", link=link.id)
                return False
            final = await self._try(link, best.transport, self.store.link_ports(link))
            if not final.ok:
                link.status, link.error = L_DOWN, final.error or "failed after adding ports"
                link.fail_count = self.s.fail_threshold
                await self.emit("error", "discover", f"{self.link_label(link)} با پورت‌های نهایی بالا نیامد: {link.error}", link=link.id)
                return False
            self._mark_up(link, best.transport, final.latency_ms)
            ranking = ", ".join(f"{r.transport} {r.latency_ms:.0f}ms" for r in good[:4])
            await self.emit(
                "success",
                "discover",
                f"تانل {self.link_label(link)} با {best.transport} برقرار شد ({final.latency_ms:.0f}ms) — رتبه‌بندی: {ranking}",
                link=link.id,
            )
            return True
        finally:
            self.busy.discard(link.id)
            if link.status == L_TESTING:
                link.status = prev
            await self.changed()

    async def discover_all(self, link_ids: list[str] | None = None, parallel: int = 3) -> None:
        self.store.ensure_links()
        links = [x for x in self.store.links.values() if link_ids is None or x.id in link_ids]
        if link_ids is None:
            # "build everything" builds what is not built or clearly down; a
            # working or merely wobbling tunnel is never touched
            links = [x for x in links if x.status in (L_PENDING, L_DOWN) and x.id not in self.busy]
        await self.emit("info", "discover", f"شروع تست و اتصال {len(links)} تانل")
        sem = asyncio.Semaphore(parallel)

        async def one(link: Link):
            async with sem:
                await self.discover(link)

        await asyncio.gather(*(one(x) for x in links))
        await self.evaluate_domains()
        up = sum(1 for x in links if x.status == L_UP)
        await self.emit("info", "discover", f"پایان اتصال: {up} از {len(links)} تانل برقرار است")

    async def set_transport(self, link: Link, transport: str, pin: bool = True) -> bool:
        if link.id in self.busy:
            raise RuntimeError("an operation is already running on this link")
        iran, kharej = self.pair(link)
        if not (iran and kharej):
            raise RuntimeError("link servers are missing")
        self.busy.add(link.id)
        old = link.transport
        link.status = L_TESTING
        link.pinned = pin
        await self.changed()
        try:
            await asyncio.gather(self._install(iran), self._install(kharej))
            taken = await self._ports_taken(link)
            if taken:
                link.status, link.error = (L_PENDING if not link.built else L_DOWN), taken
                await self.emit("error", "transport", f"تانل {self.link_label(link)} ساخته نشد: {taken}", link=link.id)
                return False
            r = await self._try(link, transport, self.store.link_ports(link))
            if r.ok:
                self._mark_up(link, transport, r.latency_ms)
                await self.emit("success", "transport", f"پروتکل {self.link_label(link)} از {old or '—'} به {transport} تغییر کرد ({r.latency_ms:.0f}ms)", link=link.id)
                return True
            link.transport = transport
            link.status, link.error = L_DOWN, r.error
            link.fail_count = self.s.fail_threshold
            await self.emit("error", "transport", f"تغییر پروتکل {self.link_label(link)} به {transport} ناموفق بود: {r.error}", link=link.id)
            return False
        except (SSHError, DeployError, OSError) as e:
            link.status, link.error = L_DOWN, str(e)
            await self.emit("error", "transport", f"تغییر پروتکل {self.link_label(link)} ناموفق: {e}", link=link.id)
            return False
        finally:
            self.busy.discard(link.id)
            await self.changed()

    async def repair(self, link: Link) -> bool:
        """Link is down while both ends are reachable: try other transports."""
        if link.id in self.busy:
            return False
        iran, kharej = self.pair(link)
        if not (self.usable(iran) and self.usable(kharej)):
            return False
        self.busy.add(link.id)
        link.status = L_TESTING
        await self.changed()
        current = link.transport
        try:
            if link.pinned and current:
                order = [current]
            else:
                ranked = [t for t in link.ranked_transports(self.s.candidate_transports) if t != current]
                probe = self.last_probe.get(link.id)
                crashed = probe is not None and probe.active not in ("active", "")
                # a service that died only needs a restart; a blocked
                # transport is better tried last
                order = ([current] + ranked if crashed else ranked + [current]) if current else ranked
            await self.emit("warning", "repair", f"تانل {self.link_label(link)} ({current or '—'}) قطع است؛ تلاش برای بازسازی با: {', '.join(order)}", link=link.id)
            ports = self.store.link_ports(link)
            for t in order:
                r = await self._try(link, t, ports)
                if r.ok:
                    self._mark_up(link, t, r.latency_ms)
                    self.repair_after.pop(link.id, None)
                    how = "با همان پروتکل" if t == current else f"با پروتکل {t} (قبلی: {current or '—'})"
                    await self.emit("success", "repair", f"تانل {self.link_label(link)} {how} دوباره برقرار شد و وارد مدار شد ({r.latency_ms:.0f}ms)", link=link.id)
                    return True
            # nothing worked: leave the best known transport deployed so the
            # tunnel heals by itself when the path does
            if link.pinned and current:
                fallback = current
            else:
                fallback = (link.ranked_transports(self.s.candidate_transports) or [current])[0] or current
            if fallback:
                link.transport = fallback
                try:
                    await self.driver.deploy(link, iran, kharej, fallback, ports)  # type: ignore[arg-type]
                except (SSHError, DeployError, OSError):
                    pass
            link.status, link.error = L_DOWN, "all transports failed"
            link.fail_count = max(link.fail_count, self.s.fail_threshold)
            self.repair_after[link.id] = time.time() + REPAIR_BACKOFF
            await self.emit("error", "repair", f"بازسازی تانل {self.link_label(link)} ناموفق بود؛ هیچ پروتکلی جواب نداد (تلاش دوباره تا {REPAIR_BACKOFF // 60} دقیقه دیگر)", link=link.id)
            return False
        finally:
            self.busy.discard(link.id)
            if link.status == L_TESTING:
                link.status = L_DOWN
            await self.changed()

    async def redeploy_iran_side(self, link: Link) -> bool:
        iran, kharej = self.pair(link)
        if not (self.usable(iran) and kharej and link.transport):
            return False
        await self._ensure_probe(link)
        try:
            await self.driver.deploy_iran(link, iran, kharej, self.store.link_ports(link))  # type: ignore[arg-type]
            return True
        except (SSHError, DeployError, OSError) as e:
            await self.emit("error", "deploy", f"به‌روزرسانی پورت‌های {self.link_label(link)} ناموفق: {e}", link=link.id)
            return False

    async def ports_changed(self, link: Link) -> None:
        """A link's port list changed: re-render the Iran side carrying them."""
        carrier = self.store.links.get(self.store.carrier(link.id))
        if carrier and carrier.status != L_PENDING and carrier.transport:
            if await self.redeploy_iran_side(carrier):
                await self.emit("info", "ports", f"پورت‌های فورواردی {self.link_label(link)} روی سرور داخل: {', '.join(link.ports) or '—'}", link=link.id)

    async def remove_links(self, links: list[Link]) -> None:
        for link in links:
            if not link.managed:
                continue  # adopted tunnels are only forgotten, never deleted
            iran, kharej = self.pair(link)
            await self.driver.remove(link, iran, kharej)

    # ----------------------------------------------------------- adoption
    async def scan_all(self, servers: list[Server] | None = None) -> int:
        """Find tunnels already running on the servers and add them."""
        st = self.store
        servers = [s for s in (servers or list(st.servers.values())) if self.usable(s)]
        found: dict[str, list[Found]] = {}

        async def one(srv: Server):
            try:
                found[srv.id] = await self.driver.scan(srv)
                srv.last_scan = time.time()
            except (SSHError, OSError) as e:
                log.info("scan %s: %s", srv.name, e)

        await asyncio.gather(*(one(s) for s in servers))
        self.last_scan = time.time()
        # Iran servers hold the [server] sections, kharejs the [client] ones;
        # a pair is a matching (tunnel port, token)
        sides: dict[tuple[int, str], list[tuple[Server, Found]]] = {}
        for sid, items in found.items():
            srv = st.servers[sid]
            if srv.role != IRAN:
                continue
            for f in items:
                port = f.port()
                if f.role == "server" and port:
                    sides.setdefault((port, f.token), []).append((srv, f))
        added = 0
        stale: list[str] = []
        loop = asyncio.get_running_loop()
        for sid, items in found.items():
            kharej = st.servers[sid]
            if kharej.role != KHAREJ:
                continue
            for c in items:
                port = c.port()
                if c.role != "client" or not port:
                    continue
                options = sides.get((port, c.token), [])
                if not options:
                    continue
                host = c.host()
                match = next(((i, f) for i, f in options if i.ip == host), None)
                if match is None and host:
                    try:
                        ipaddress.ip_address(host)
                    except ValueError:  # a hostname: resolve it
                        try:
                            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                            ips = {i[4][0] for i in infos}
                            match = next(((i, f) for i, f in options if i.ip in ips), None)
                        except OSError:
                            pass
                if match is None and len(options) == 1:
                    match = options[0]  # port and token agree: NAT or a second address
                if match is None:
                    continue
                iran, f = match
                if f.active != "active" or c.active != "active":
                    stale.append(f"{f.name} ({iran.name} ⇄ {kharej.name})")
                    continue
                if await self._adopt(iran, kharej, f, c):
                    added += 1
        if stale:
            log.info("scan: configs found but not running, left alone: %s", ", ".join(stale))
        if added:
            # drop the placeholders of pairs that turned out to have a tunnel already
            for link in list(st.links.values()):
                if link.managed and link.status == L_PENDING and not link.transport and any(
                    not x.managed for x in st.links_between(link.iran_id, link.kharej_id)
                ):
                    st.remove_link(link.id)
        await self.changed()
        return added

    async def _adopt(self, iran: Server, kharej: Server, f: Found, c: Found) -> bool:
        st = self.store
        if f.name.startswith("tm-") and f.name[3:] in st.links:
            return False  # one of ours
        ports, probe = split_ports([str(p) for p in (f.data.get("ports") or [])])
        existing = next(
            (x for x in st.links_between(iran.id, kharej.id) if x.iran_name == f.name and x.kharej_name == c.name),
            None,
        )
        if existing:
            if existing.id not in self.busy and existing.id not in st.handover and existing.id not in st.handover.values():
                # edited outside the panel: follow it
                existing.transport = f.transport
                existing.token = f.token
                existing.ports = ports
                existing.probe_port = probe or existing.probe_port
                existing.iran_base = {k: v for k, v in f.data.items() if k != "ports"}
                existing.kharej_base = dict(c.data)
                existing.iran_unit = "" if f.unit == unit_name(f.name) else f.unit
                existing.kharej_unit = "" if c.unit == unit_name(c.name) else c.unit
            return False
        link = Link(
            iran_id=iran.id,
            kharej_id=kharej.id,
            tunnel_port=f.port() or 0,
            probe_port=probe,
            token=f.token,
            transport=f.transport,
            ports=ports,
            accept_udp=bool(f.data.get("accept_udp")),
            managed=False,
            iran_name=f.name,
            kharej_name=c.name,
            iran_base={k: v for k, v in f.data.items() if k != "ports"},
            kharej_base=dict(c.data),
            label=f.name,
            status=L_DEGRADED,  # the next check decides
            iran_unit="" if f.unit == unit_name(f.name) else f.unit,
            kharej_unit="" if c.unit == unit_name(c.name) else c.unit,
            built=True,
        )
        st.links[link.id] = link
        state = "فعال" if f.active == "active" and c.active == "active" else f"سرویس: {f.active or '?'} / {c.active or '?'}"
        await self.emit(
            "success",
            "adopt",
            f"تانل موجود «{f.name}» بین {kharej.name} ⇄ {iran.name} پیدا و به پنل اضافه شد ({f.transport}، پورت تانل {link.tunnel_port}، پورت‌ها: {', '.join(ports) or '—'}، {state})",
            link=link.id,
        )
        return True

    # ------------------------------------------------------------- monitoring
    async def check_servers(self) -> None:
        servers = [s for s in self.store.servers.values() if s.enabled]

        async def one(srv: Server):
            kind = "داخل" if srv.role == IRAN else "خارج"
            try:
                srv.ssh_latency_ms = round(await self.driver.ping(srv), 1)
                srv.fail_count = 0
                srv.last_seen = time.time()
                srv.error = ""
                if srv.status != ONLINE:
                    was = srv.status
                    srv.status = ONLINE
                    if was == OFFLINE:
                        await self.emit("success", "server", f"سرور {kind} {srv.name} ({srv.ip}) دوباره در دسترس است", server=srv.id)
            except (SSHError, OSError) as e:
                srv.fail_count += 1
                srv.error = str(e)
                srv.ssh_latency_ms = None
                if srv.fail_count >= self.s.fail_threshold and srv.status != OFFLINE:
                    srv.status = OFFLINE
                    await self.emit("error", "server", f"سرور {kind} {srv.name} ({srv.ip}) به مشکل خورد و از دسترس خارج شد: {e}", server=srv.id)
                elif srv.status == "unknown":
                    srv.status = OFFLINE

        await asyncio.gather(*(one(x) for x in servers))

    async def check_links(self) -> None:
        by_iran: dict[str, list[Link]] = {}
        for link in self.store.links.values():
            if link.id in self.busy or link.status == L_PENDING or not link.transport:
                continue
            by_iran.setdefault(link.iran_id, []).append(link)

        async def one(iran_id: str, links: list[Link]):
            iran = self.store.servers.get(iran_id)
            probes: dict[str, Probe] = {}
            if self.usable(iran):
                try:
                    probes = await self.driver.check(iran, links)  # type: ignore[arg-type]
                except (SSHError, OSError) as e:
                    log.info("check %s: %s", iran_id, e)
            for link in links:
                if link.id in self.busy:
                    continue
                await self._apply_probe(link, probes.get(link.id))

        await asyncio.gather(*(one(i, ls) for i, ls in by_iran.items()))

    async def _apply_probe(self, link: Link, p: Probe | None) -> None:
        t = time.time()
        if p is not None:
            self.last_probe[link.id] = p
        if p is not None and p.ok:
            was = link.status
            self.prev_ok[link.id] = True
            link.latency_ms = p.latency_ms
            link.fail_count = 0
            link.last_ok = t
            link.error = ""
            link.verified = p.verified
            link.record(p.latency_ms)
            if was != L_UP:
                link.status = L_UP
                link.last_change = t
                if was != L_DEGRADED or not link.up_since:
                    link.up_since = t
                if was == L_DOWN:
                    await self.emit("success", "link", f"تانل {self.link_label(link)} ({link.transport}) دوباره وصل شد و وارد مدار شد", link=link.id)
            if link.id in self.flap_reported and not self.flapping(link):
                self.flap_reported.discard(link.id)
            return
        # failed
        if self.prev_ok.get(link.id):
            link.flaps.append(t)
            del link.flaps[:-50]
        self.prev_ok[link.id] = False
        link.last_fail = t
        link.fail_count += 1
        link.record(None)
        link.latency_ms = None
        if p is None:
            link.error = "Iran server unreachable"
        elif p.active not in ("active",):
            link.error = f"service {p.active or 'missing'}"
        elif p.connected:
            link.error = "engine connected but probe failed"
        else:
            link.error = "tunnel not connected"
        if self.flapping(link) and link.id not in self.flap_reported:
            self.flap_reported.add(link.id)
            n = sum(1 for x in link.flaps if x >= t - self.s.flap_window)
            await self.emit("warning", "flap", f"تانل {self.link_label(link)} مدام قطع و وصل می‌شود: {n} قطعی در {fmt_dur(self.s.flap_window)} اخیر", link=link.id)
        if link.fail_count >= self.s.fail_threshold:
            if link.status != L_DOWN:
                link.status = L_DOWN
                link.last_change = t
                # a dead server is reported once on its own; its tunnels going
                # down with it are not worth a Telegram message each
                _, kharej = self.pair(link)
                cascade = p is None or (kharej is not None and kharej.status == OFFLINE)
                await self.emit("error", "link", f"تانل {self.link_label(link)} ({link.transport}) قطع شد: {link.error}", notify=not cascade, link=link.id)
        elif link.status == L_UP:
            link.status = L_DEGRADED
            link.last_change = t

    async def check_all(self) -> None:
        async with self._check_lock:
            self.store.ensure_links()
            await self.check_servers()
            if self.s.auto_adopt and time.time() - self.last_scan >= self.s.scan_interval:
                await self.scan_all()
            await self.check_links()
            await self.evaluate_domains()
            await self.release_handovers()
            self.schedule_repairs()
            await self.check_propagation()
            self.last_check = time.time()
            await self.changed()

    # -------------------------------------------------------------- policies
    def schedule_repairs(self) -> None:
        if not self.s.auto_repair or self.s.observe_only:
            return
        for link in self.store.links.values():
            if link.status != L_DOWN or link.id in self.busy:
                continue
            if self.repair_after.get(link.id, 0) > time.time():
                continue
            iran, kharej = self.pair(link)
            if self.usable(iran) and self.usable(kharej):
                self.busy.add(link.id)  # reserve now so the next tick does not double-start
                self.spawn(self._repair_then_evaluate(link))

    async def _repair_then_evaluate(self, link: Link) -> None:
        self.busy.discard(link.id)
        await self.repair(link)
        await self.evaluate_domains()

    async def hand_over(self, src: Link, dst: Link, reason: str) -> bool:
        """Expose src's forwarded ports on dst instead (same Iran server)."""
        st = self.store
        old = st.links.get(st.carrier(src.id)) or src
        if dst.id == src.id:
            st.handover.pop(src.id, None)
        else:
            if st.carrier(dst.id) == src.id:
                st.handover.pop(dst.id, None)  # never a loop
            st.handover[src.id] = dst.id
        # free the ports first, then bind them on the new carrier
        ok = True
        if old.id != dst.id:
            ok = await self.redeploy_iran_side(old)
        ok = await self.redeploy_iran_side(dst) and ok
        await self.emit(
            "warning",
            "handover",
            f"پورت‌های {self.link_label(src)} روی سرور داخل {self.name(src.iran_id)} به تانل {self.link_label(dst)} منتقل شد (رکورد DNS تغییری نکرد) — {reason}",
            link=src.id,
            target=dst.id,
        )
        return ok

    async def release_handovers(self) -> None:
        st = self.store
        if self.s.observe_only:
            return
        for src_id, dst_id in list(st.handover.items()):
            src, dst = st.links.get(src_id), st.links.get(dst_id)
            if src is None or dst is None:
                st.handover.pop(src_id, None)
                continue
            if not self.stable(src):
                continue
            st.handover.pop(src_id, None)
            await self.redeploy_iran_side(dst)
            await self.redeploy_iran_side(src)
            await self.emit(
                "success",
                "failback",
                f"تانل {self.link_label(src)} {fmt_dur(self.s.failback_after)} بدون قطعی پایدار بود؛ پورت‌هایش از {self.link_label(dst)} برگشت",
                link=src_id,
            )

    # ---------------------------------------------------------- domains
    def route(self, iran_id: str, spec: str) -> Link | None:
        return self.store.port_map(iran_id).get(first_port(spec))

    def cover(self, d: Domain, iran_id: str, group: list[Link], stable: bool = False) -> tuple[list[str], list[str]]:
        """Can this Iran server carry every port of the domain?
        Returns (hard problems, soft problems): a hard problem is a reason to
        move (missing, down, flapping, server gone); a soft one is a tunnel
        that dropped a check or two."""
        hard, soft = [], []
        iran = self.store.servers.get(iran_id)
        if iran is None or self.is_down(iran):
            return [f"سرور داخل {self.name(iran_id)} در دسترس نیست"], []
        allowed = {x.id for x in group} if d.group else None
        for spec in self.store.domain_specs(d):
            link = self.route(iran_id, spec)
            if link is None:
                hard.append(f"پورت {spec} روی {self.name(iran_id)} تانلی ندارد")
                continue
            owner = self.store.owner(iran_id, spec)
            if allowed is not None and link.id not in allowed and (owner is None or owner.id not in allowed):
                hard.append(f"پورت {spec} روی {self.name(iran_id)} با تانلی خارج از گروه دامنه است")
                continue
            ok = self.stable(link) if stable else self.healthy(link)
            if not ok:
                why = self.broken(link)
                (hard if why or stable else soft).append(f"پورت {spec}: {why or 'تانل ' + self.link_label(link) + ' ناپایدار'}")
        if not self.store.domain_specs(d):
            hard.append("پورت‌های دامنه مشخص نشده")
        return hard, soft

    def routes_text(self, d: Domain, iran_id: str) -> str:
        parts = []
        for spec in self.store.domain_specs(d):
            link = self.route(iran_id, spec)
            parts.append(f"{spec}→{self.name(link.kharej_id) if link else '؟'}")
        return "، ".join(parts)

    async def move_domain(self, d: Domain, iran_id: str, reason: str, failback: bool = False) -> bool:
        """Point the domain's A record at another Iran server."""
        st = self.store
        iran = st.servers.get(iran_id)
        p = st.providers.get(d.provider_id)
        if not iran or not p:
            await self.emit("error", "dns", f"دامنه {d.fqdn}: حساب DNS یا سرور مقصد پیدا نشد", domain=d.id)
            return False
        if d.iran_id == iran_id and d.current_ip == iran.ip:
            return True
        async with self._dns_lock:
            try:
                await self.dns_factory(p).set_a(d.fqdn, iran.ip, d.ttl)
            except Exception as e:  # DNSError, httpx errors, anything the API throws
                if d.error != str(e):
                    d.error = str(e)
                    await self.emit("error", "dns", f"تغییر رکورد {d.fqdn} به {iran.ip} ناموفق بود: {e}", domain=d.id)
                return False
        old = st.servers.get(d.iran_id)
        d.iran_id = iran_id
        d.current_ip, d.last_switch, d.error = iran.ip, time.time(), ""
        d.pending_ip, d.pending_since = iran.ip, time.time()
        d.status = "ok"
        self.suggested.pop(d.id, None)
        frm = f"{old.name} ({old.ip})" if old else "—"
        routes = self.routes_text(d, iran_id)
        if failback:
            msg = f"برگشت به سرور اصلی: رکورد {d.fqdn} از {frm} به {iran.name} ({iran.ip}) تغییر کرد — {reason}. مسیرها: {routes}"
        elif old:
            msg = (
                f"رکورد {d.fqdn} از {frm} به {iran.name} ({iran.ip}) تغییر کرد — {reason}. "
                f"مسیرها: {routes}؛ در حال بررسی رسیدن تغییر به کاربران…"
            )
        else:
            msg = f"رکورد {d.fqdn} روی {iran.name} ({iran.ip}) تنظیم شد. مسیرها: {routes}"
        await self.emit("success" if failback or not old else "warning", "dns", msg, domain=d.id)
        return True

    async def evaluate_domains(self) -> None:
        st = self.store
        for d in list(st.domains.values()):
            if not d.iran_id:
                await self._assign_initial(d)
                continue
            group = st.group_of(d)
            hard, soft = self.cover(d, d.iran_id, group)
            if not hard and not soft:
                if d.status != "ok":
                    d.status = "ok"
                    d.error = ""
                if self.suggested.pop(d.id, None):
                    await self.emit("success", "observe", f"دامنه {d.fqdn} دوباره سالم است (حالت نظارت: تغییری داده نشده بود)", domain=d.id)
                await self._maybe_failback(d, group)
                continue
            if not hard:
                continue  # dropped a check or two: not a reason to move yet
            why = "؛ ".join(hard[:3])
            if not d.auto_failover:
                if d.status != "broken":
                    d.status = "broken"
                    await self.emit("error", "domain", f"دامنه {d.fqdn}: {why} (جابه‌جایی خودکار خاموش است)", domain=d.id)
                continue
            plan = self._plan(d, group)
            if plan is None:
                if any(x.id in self.busy for x in group):
                    continue  # a tunnel of the group is being built or repaired right now
                if d.status != "broken":
                    d.status = "broken"
                    await self.emit(
                        "error",
                        "domain",
                        f"دامنه {d.fqdn}: {why} — و هیچ سرور داخل دیگری همه پورت‌هایش ({', '.join(st.domain_specs(d))}) را سالم ندارد؛ رکورد تغییر نکرد",
                        domain=d.id,
                    )
                self._kick(group)
                continue
            if self.s.observe_only:
                d.status = "broken"
                await self._suggest(d, plan, why)
                continue
            if plan[0] == "dns":
                await self.move_domain(d, plan[1], why)
            else:
                _, owner, target, spec = plan
                await self.hand_over(owner, target, f"دامنه {d.fqdn}، پورت {spec}: {why}")
                d.last_switch = time.time()

    def _plan(self, d: Domain, group: list[Link]):
        """What would fix the domain: ("handover", owner, target, spec) on the
        same Iran server, or ("dns", iran_id) to another one, or None."""
        st, cur = self.store, d.iran_id
        broken_specs = []
        for spec in st.domain_specs(d):
            link = self.route(cur, spec)
            if link is None or not self.healthy(link):
                broken_specs.append(spec)
        iran = st.servers.get(cur)
        iran_dead = iran is None or self.is_down(iran)

        def same_iran(spec):
            """A spare tunnel on this Iran server to take the port over: one to
            the same kharej (a spare on another transport), or to any other
            kharej when this port's kharej is gone."""
            if iran_dead:
                return None
            serving, owner = self.route(cur, spec), st.owner(cur, spec)
            if serving is None or owner is None:
                return None
            kharej_dead = self.is_down(st.servers.get(serving.kharej_id))
            for t in group:
                if t.iran_id == cur and t.id != serving.id and self.healthy(t) and st.carrier(t.id) == t.id:
                    if t.kharej_id == serving.kharej_id or kharej_dead:
                        return ("handover", owner, t, spec)
            return None

        first = broken_specs[0] if broken_specs else None
        if first is not None:
            serving = self.route(cur, first)
            if serving is not None and self.is_down(st.servers.get(serving.kharej_id)):
                fix = same_iran(first)  # the kharej is gone, not the path: keep the Iran server
                if fix:
                    return fix
        for t in group:
            if t.status == L_PENDING:
                continue
            if t.iran_id == cur:
                if first is not None:
                    fix = same_iran(first)
                    if fix and fix[2].id == t.id:
                        return fix
            elif not self.cover(d, t.iran_id, group)[0] and not self.cover(d, t.iran_id, group)[1]:
                return ("dns", t.iran_id)
        return None

    async def _suggest(self, d: Domain, plan, why: str) -> None:
        """Observe mode: say what would have happened, once, and do nothing."""
        key = plan[1] if plan[0] == "dns" else f"{plan[1].id}>{plan[2].id}"
        if self.suggested.get(d.id) == key:
            return
        self.suggested[d.id] = key
        if plan[0] == "dns":
            iran = self.store.servers.get(plan[1])
            would = f"رکوردش به {iran.name if iran else '?'} ({iran.ip if iran else '?'}) تغییر می‌کرد (مسیرها: {self.routes_text(d, plan[1])})"
        else:
            would = f"پورت {plan[3]} روی همان سرور داخل به تانل {self.link_label(plan[2])} منتقل می‌شد"
        await self.emit(
            "warning",
            "observe",
            f"حالت نظارت — دامنه {d.fqdn}: {why}. اگر جابه‌جایی خودکار روشن بود، {would}. هیچ تغییری داده نشد.",
            domain=d.id,
        )

    async def read_record(self, d: Domain) -> None:
        """Read the live A record, so a domain that already points at one of
        our Iran servers starts from there instead of changing DNS."""
        p = self.store.providers.get(d.provider_id)
        if not p:
            return
        self.last_read[d.id] = time.time()
        try:
            ips = await self.dns_factory(p).get_a(d.fqdn)
        except Exception as e:
            err = f"DNS read: {e}"
            if d.error != err:
                d.error = err
                await self.emit("error", "dns", f"رکورد دامنه {d.fqdn} خوانده نشد: {e}", domain=d.id)
            await self.changed()
            return
        d.current_ip, d.error = (ips[0] if ips else ""), ""
        await self.changed()
        self.wake()

    async def _assign_initial(self, d: Domain) -> None:
        """A domain without an Iran server yet: take the one its record
        already points at, and the ports it serves there."""
        st = self.store
        match = next((s for s in st.irans() if d.current_ip and s.ip == d.current_ip), None)
        if match:
            d.iran_id = match.id
            d.primary_iran = d.primary_iran or match.id
            if not d.ports and d.kharej_id:
                d.ports = st.domain_specs(d)
            hard, _ = self.cover(d, d.iran_id, st.group_of(d))
            d.status = "unknown" if hard else "ok"
            tail = f"مسیرها: {self.routes_text(d, d.iran_id)}" if st.domain_specs(d) else "پورت‌های دامنه را در پنل دامنه مشخص کنید"
            await self.emit("info", "domain", f"دامنه {d.fqdn} الان به {match.name} ({match.ip}) اشاره می‌کند؛ {tail}", notify=False, domain=d.id)
            return
        if not d.current_ip and not d.error:
            return  # the record has not been read yet
        if d.error.startswith("DNS read"):
            # the provider refused; try again now and then (the fix is on its side)
            if time.time() - self.last_read.get(d.id, 0) >= 300:
                self.spawn(self.read_record(d))
            return
        if self.suggested.get(d.id) != f"init:{d.current_ip}":
            self.suggested[d.id] = f"init:{d.current_ip}"
            await self.emit(
                "warning",
                "domain",
                f"دامنه {d.fqdn} به {d.current_ip or 'هیچ آی‌پی'} اشاره می‌کند که هیچ‌کدام از سرورهای داخل ثبت‌شده نیست؛ رکورد دست نخورد. "
                "در پنل دامنه سرور داخل را دستی انتخاب کنید.",
                domain=d.id,
            )

    async def _maybe_failback(self, d: Domain, group: list[Link]) -> None:
        order = self.store.iran_order(d)
        if not order or not d.auto_failover or self.s.observe_only:
            return
        primary = order[0]
        if primary == d.iran_id or time.time() - d.last_switch < self.s.failback_after:
            return
        hard, soft = self.cover(d, primary, group, stable=True)
        if hard or soft:
            return
        await self.move_domain(
            d,
            primary,
            f"همه پورت‌های {self.name(primary)} {fmt_dur(self.s.failback_after)} بدون قطعی پایدار بودند",
            failback=True,
        )

    def domain_info(self, d: Domain) -> dict:
        """Live view of a domain for the dashboard."""
        st = self.store
        group = st.group_of(d)
        routes = []
        for spec in st.domain_specs(d):
            link = self.route(d.iran_id, spec) if d.iran_id else None
            routes.append({
                "spec": spec,
                "link_id": link.id if link else "",
                "kharej_id": link.kharej_id if link else "",
                "healthy": self.healthy(link),
            })
        coverage = []
        order = st.iran_order(d)
        for s_ in st.irans():
            hard, soft = self.cover(d, s_.id, group)
            coverage.append({"iran_id": s_.id, "ok": not hard and not soft, "problems": hard + soft, "rank": order.index(s_.id) if s_.id in order else 99})
        coverage.sort(key=lambda c: c["rank"])
        failback = None
        if order and order[0] != d.iran_id and d.auto_failover:
            primary = order[0]
            hard, soft = self.cover(d, primary, group)
            if hard or soft:
                failback = {"iran_id": primary, "wait": -1}
            else:
                since = max([d.last_switch] + [
                    max(x.last_fail, x.up_since) for x in (self.route(primary, sp) for sp in st.domain_specs(d)) if x
                ])
                failback = {"iran_id": primary, "wait": max(0, round(self.s.failback_after - (time.time() - since)))}
        return {"routes": routes, "coverage": coverage, "failback": failback}

    def _kick(self, group: list[Link]) -> None:
        if not self.s.auto_repair or self.s.observe_only:
            return
        for link in group:
            if link.id in self.busy:
                continue
            iran, kharej = self.pair(link)
            if not (self.usable(iran) and self.usable(kharej)):
                continue
            if link.status == L_PENDING:
                self.spawn(self.discover(link))
            elif link.status == L_DOWN and self.repair_after.get(link.id, 0) <= time.time():
                self.busy.add(link.id)
                self.spawn(self._repair_then_evaluate(link))

    async def check_propagation(self) -> None:
        """Tell when a changed record has actually reached users."""
        for d in self.store.domains.values():
            if not d.pending_ip:
                continue
            p = self.store.providers.get(d.provider_id)
            waited = time.time() - d.pending_since
            if p is None or p.proxied:
                d.pending_ip = ""  # proxied records resolve to the CDN: nothing to watch
                continue
            try:
                answers = await self.resolver(d.fqdn, self.s.doh_resolvers)
            except Exception as e:
                log.info("propagation %s: %s", d.fqdn, e)
                continue
            seen = [a for a in answers.values() if a is not None]
            if seen and all(a == [d.pending_ip] for a in seen):
                await self.emit(
                    "success",
                    "propagated",
                    f"بعد از {fmt_dur(waited)}، سرور {self.name(d.iran_id)} ({d.pending_ip}) پشت دامنه {d.fqdn} قرار گرفت. مسیرها: {self.routes_text(d, d.iran_id)}",
                    domain=d.id,
                )
                d.pending_ip = ""
            elif waited > PROPAGATION_GIVE_UP:
                got = ", ".join(sorted({ip for a in seen for ip in a})) or "—"
                await self.emit("warning", "propagated", f"بعد از {fmt_dur(waited)} هنوز همه DNSها آی‌پی جدید {d.fqdn} را نشان نمی‌دهند (دیده‌شده: {got})", domain=d.id)
                d.pending_ip = ""

    # --------------------------------------------------------------- runtime
    def wake(self) -> None:
        self._wake.set()

    async def run(self) -> None:
        while True:
            try:
                await self.check_all()
            except Exception:
                log.exception("check cycle failed")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=max(5, self.s.check_interval))
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    # ------------------------------------------------------------ bot output
    def summary(self) -> str:
        st = self.store
        lines = ["<b>📊 وضعیت TunnelManager</b>", ""]
        for role, title in ((KHAREJ, "🌍 خارج"), (IRAN, "🇮🇷 داخل")):
            lines.append(f"<b>{title}</b>")
            for srv in st.by_role(role):
                dot = "🟢" if srv.status == ONLINE else "🔴" if srv.status == OFFLINE else "⚪"
                lines.append(f"{dot} {esc(srv.name)} <code>{esc(srv.ip)}</code>")
            lines.append("")
        lines.append(self.domains_text())
        return "\n".join(lines)

    def domains_text(self) -> str:
        st = self.store
        lines = ["<b>🌐 دامنه‌ها</b>"]
        for d in st.domains.values():
            dot = "🟢" if d.status == "ok" else "🔴" if d.status == "broken" else "⚪"
            extra = " ⏳ در حال انتشار DNS" if d.pending_ip else ""
            where = f"{self.name(d.iran_id)} ({self.routes_text(d, d.iran_id)})" if d.iran_id else "—"
            lines.append(f"{dot} {esc(d.fqdn)} → {esc(where)}{extra}")
        return "\n".join(lines) if len(lines) > 1 else "دامنه‌ای ثبت نشده"

    def links_text(self) -> str:
        icon = {L_UP: "🟢", L_DEGRADED: "🟡", L_DOWN: "🔴", L_TESTING: "🔵", L_PENDING: "⚪"}
        lines = ["<b>🔗 تانل‌ها</b>"]
        for x in sorted(self.store.links.values(), key=lambda x: (self.name(x.kharej_id), self.name(x.iran_id))):
            if x.status == L_PENDING:
                continue
            lat = f" {x.latency_ms:.0f}ms" if x.latency_ms else ""
            flap = " ⚡ناپایدار" if self.flapping(x) else ""
            lines.append(f"{icon.get(x.status, '⚪')} {esc(self.link_label(x))} <code>{esc(x.transport or '—')}</code>{lat}{flap}")
        return "\n".join(lines)

    async def bot_command(self, cmd: str, args: list[str]) -> str:
        if cmd in ("/start", "/help"):
            return (
                "دستورها:\n/status — خلاصه وضعیت\n/links — وضعیت تانل‌ها\n"
                "/domains — دامنه‌ها و مسیرشان\n/check — بررسی فوری همه مسیرها\n/scan — جستجوی تانل‌های موجود روی سرورها"
            )
        if cmd == "/status":
            return self.summary()
        if cmd == "/links":
            return self.links_text()
        if cmd == "/domains":
            return self.domains_text()
        if cmd == "/check":
            self.wake()
            return "🔄 بررسی فوری شروع شد"
        if cmd == "/scan":
            n = await self.scan_all()
            return f"🔍 جستجو تمام شد: {n} تانل جدید اضافه شد"
        return "دستور ناشناخته — /help"
