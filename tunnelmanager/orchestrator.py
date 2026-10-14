"""The brain: discovery, health checks and the failover state machine.

Failover policy (what happens when a domain's path breaks)
---------------------------------------------------------
A domain's A record points at one Iran server; that server reaches the
domain's kharej through a BackPack tunnel (a *link*).

1. Link down, both ends reachable  -> **repair**: try the other transports on
   the same pair (fastest first). Telegram is told either way.
2. Repair failed, or the Iran server itself is down -> **move the domain**:
   point the A record at another Iran server whose tunnel to the same kharej
   is up (building/repairing one if needed).
3. The kharej itself is down (SSH unreachable and none of its tunnels up)
   -> **take over the kharej**: another kharej's tunnels start exposing the
   dead one's ports on every Iran server, so the domains keep their Iran
   server and traffic lands on the new kharej. When the original kharej is
   back (and auto_failback is on) its ports are handed back.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable

from .backpack import DeployError, Driver, Probe
from .dns import DNSClient, DNSError
from .models import (
    IRAN,
    KHAREJ,
    L_DEGRADED,
    L_DOWN,
    L_PENDING,
    L_SUSPENDED,
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
from .store import Store
from .telegram import ICON, esc

log = logging.getLogger(__name__)

REPAIR_BACKOFF = 300  # seconds before a failed repair is retried


def listen_key(mapping: str) -> str:
    """The listening half of a port mapping, normalised: "443", "1.2.3.4:443"."""
    return mapping.split("=", 1)[0].strip()


class Orchestrator:
    def __init__(
        self,
        store: Store,
        driver: Driver,
        dns_factory: Callable[..., DNSClient],
        notify: Callable[[str], None] = lambda text: None,
        broadcast: Callable[[dict], Awaitable[None]] | None = None,
    ):
        self.store = store
        self.driver = driver
        self.dns_factory = dns_factory
        self.notify = notify
        self.broadcast = broadcast
        self.busy: set[str] = set()  # link ids with an operation in flight
        self.repair_after: dict[str, float] = {}
        self.takeover_at: dict[str, float] = {}
        self.last_probe: dict[str, Probe] = {}
        self.tasks: set[asyncio.Task] = set()
        self._check_lock = asyncio.Lock()
        self._dns_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self.last_check: float = 0

    # ------------------------------------------------------------------ util
    @property
    def s(self):
        return self.store.settings

    def name(self, sid: str) -> str:
        srv = self.store.servers.get(sid)
        return srv.name if srv else sid

    def link_label(self, link: Link) -> str:
        return f"{self.name(link.kharej_id)} ⇄ {self.name(link.iran_id)}"

    async def emit(self, level: str, kind: str, message: str, notify: bool = True, **refs: str) -> Event:
        ev = Event(level=level, kind=kind, message=message, refs=refs)
        self.store.events.append(ev)
        del self.store.events[: -1000]
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

    # ------------------------------------------------------------ deployment
    async def _install(self, srv: Server) -> None:
        if srv.backpack_version:
            return
        ver = await self.driver.ensure_installed(srv, self.s.install_backpack)
        srv.backpack_version = ver

    async def _try(self, link: Link, transport: str, ports: list[str]) -> TestResult:
        iran, kharej = self.pair(link)
        assert iran and kharej
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
        link.transport = transport
        link.status = L_UP
        link.latency_ms = latency
        link.fail_count = 0
        link.last_ok = time.time()
        link.last_change = time.time()
        link.error = ""
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
            cands = transports or self.s.candidate_transports
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
                await self.driver.stop(link, iran, kharej)
                await self.emit("error", "discover", f"هیچ پروتکلی بین {self.link_label(link)} کار نکرد", link=link.id)
                return False
            final = await self._try(link, best.transport, self.store.link_ports(link))
            if not final.ok:
                link.status, link.error = L_DOWN, final.error or "failed after adding ports"
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
        links = [x for x in self.store.links.values() if (link_ids is None or x.id in link_ids)]
        links = [x for x in links if x.status != L_SUSPENDED]
        await self.emit("info", "discover", f"شروع تست و اتصال {len(links)} مسیر", notify=True)
        sem = asyncio.Semaphore(parallel)

        async def one(link: Link):
            async with sem:
                await self.discover(link)

        await asyncio.gather(*(one(x) for x in links))
        await self.evaluate_domains()
        up = sum(1 for x in links if x.status == L_UP)
        await self.emit("info", "discover", f"پایان اتصال: {up} از {len(links)} مسیر برقرار است")

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
            r = await self._try(link, transport, self.store.link_ports(link))
            if r.ok:
                self._mark_up(link, transport, r.latency_ms)
                await self.emit("success", "transport", f"پروتکل {self.link_label(link)} از {old or '—'} به {transport} تغییر کرد ({r.latency_ms:.0f}ms)", link=link.id)
                return True
            link.transport = transport
            link.status, link.error = L_DOWN, r.error
            await self.emit("error", "transport", f"تغییر پروتکل {self.link_label(link)} به {transport} ناموفق بود: {r.error}", link=link.id)
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
                # transport is better skipped until last
                order = ([current] + ranked if crashed else ranked + [current]) if current else ranked
            await self.emit("warning", "repair", f"ارتباط {self.link_label(link)} ({current or '—'}) قطع است؛ تلاش با پروتکل‌های دیگر: {', '.join(order)}", link=link.id)
            ports = self.store.link_ports(link)
            for t in order:
                r = await self._try(link, t, ports)
                if r.ok:
                    self._mark_up(link, t, r.latency_ms)
                    self.repair_after.pop(link.id, None)
                    how = "با همان پروتکل" if t == current else f"با پروتکل {t} (قبلی: {current or '—'})"
                    await self.emit("success", "repair", f"ارتباط {self.link_label(link)} {how} دوباره برقرار شد ({r.latency_ms:.0f}ms)", link=link.id)
                    return True
            # nothing worked: leave the historically best transport deployed
            # so the link heals by itself when the path does
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
            await self.emit("error", "repair", f"هیچ پروتکلی بین {self.link_label(link)} جواب نداد", link=link.id)
            return False
        finally:
            self.busy.discard(link.id)
            if link.status == L_TESTING:
                link.status = L_DOWN
            await self.changed()

    async def redeploy_iran_side(self, link: Link) -> None:
        iran, kharej = self.pair(link)
        if not (self.usable(iran) and kharej and link.transport):
            return
        try:
            await self.driver.deploy_iran(link, iran, kharej, self.store.link_ports(link))  # type: ignore[arg-type]
        except (SSHError, DeployError, OSError) as e:
            await self.emit("error", "deploy", f"به‌روزرسانی پورت‌های {self.link_label(link)} ناموفق: {e}", link=link.id)

    async def ports_changed(self, kharej_id: str) -> None:
        """A kharej's port list changed: re-render every Iran side carrying it."""
        holder = self.store.effective_kharej(kharej_id)
        for link in list(self.store.links.values()):
            if link.kharej_id == holder and link.status not in (L_PENDING, L_SUSPENDED):
                await self.redeploy_iran_side(link)

    async def remove_links(self, links: list[Link]) -> None:
        for link in links:
            iran, kharej = self.pair(link)
            await self.driver.remove(link, iran, kharej)

    # ------------------------------------------------------------- monitoring
    async def check_servers(self) -> None:
        servers = [s for s in self.store.servers.values() if s.enabled]

        async def one(srv: Server):
            try:
                srv.ssh_latency_ms = round(await self.driver.ping(srv), 1)
                srv.fail_count = 0
                srv.last_seen = time.time()
                srv.error = ""
                if srv.status != ONLINE:
                    was = srv.status
                    srv.status = ONLINE
                    if was == OFFLINE:
                        await self.emit("success", "server", f"سرور {srv.name} ({srv.ip}) دوباره در دسترس است", server=srv.id)
            except (SSHError, OSError) as e:
                srv.fail_count += 1
                srv.error = str(e)
                srv.ssh_latency_ms = None
                if srv.fail_count >= self.s.fail_threshold and srv.status != OFFLINE:
                    srv.status = OFFLINE
                    await self.emit("error", "server", f"سرور {srv.name} ({srv.ip}) از دسترس خارج شد: {e}", server=srv.id)
                elif srv.status == "unknown":
                    srv.status = OFFLINE

        await asyncio.gather(*(one(x) for x in servers))

    async def check_links(self) -> None:
        by_iran: dict[str, list[Link]] = {}
        for link in self.store.links.values():
            if link.id in self.busy or link.status in (L_PENDING, L_SUSPENDED) or not link.transport:
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
        if p is not None:
            self.last_probe[link.id] = p
        if p is not None and p.ok:
            was = link.status
            link.latency_ms = p.latency_ms
            link.fail_count = 0
            link.last_ok = time.time()
            link.error = ""
            link.record(p.latency_ms)
            if was != L_UP:
                link.status = L_UP
                link.last_change = time.time()
                if was == L_DOWN:
                    await self.emit("success", "link", f"ارتباط {self.link_label(link)} ({link.transport}) دوباره وصل شد", link=link.id)
            return
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
        if link.fail_count >= self.s.fail_threshold:
            if link.status != L_DOWN:
                link.status = L_DOWN
                link.last_change = time.time()
                # a dead server is reported once on its own; its tunnels
                # going down with it is not news worth a Telegram message each
                _, kharej = self.pair(link)
                cascade = p is None or (kharej is not None and kharej.status == OFFLINE)
                await self.emit("error", "link", f"ارتباط {self.link_label(link)} ({link.transport}) قطع شد: {link.error}", notify=not cascade, link=link.id)
        elif link.status == L_UP:
            link.status = L_DEGRADED
            link.last_change = time.time()

    async def check_all(self) -> None:
        async with self._check_lock:
            self.store.ensure_links()
            await self.check_servers()
            await self.check_links()
            await self.evaluate_kharejs()
            self.schedule_repairs()
            await self.evaluate_domains()
            self.last_check = time.time()
            await self.changed()

    # -------------------------------------------------------------- policies
    def schedule_repairs(self) -> None:
        for link in self.store.links.values():
            if link.status != L_DOWN or link.id in self.busy or link.kharej_id in self.store.takeover:
                continue
            if self.repair_after.get(link.id, 0) > time.time():
                continue
            iran, kharej = self.pair(link)
            if self.usable(iran) and self.usable(kharej):
                self.busy.add(link.id)  # reserve now so the next tick does not double-start
                self.spawn(self._repair_then_failover(link))

    async def _repair_then_failover(self, link: Link) -> None:
        self.busy.discard(link.id)
        await self.repair(link)
        await self.evaluate_domains()

    def kharej_dead(self, k: Server) -> bool:
        if not self.is_down(k):
            return False
        return not any(x.status == L_UP for x in self.store.links_of(k.id))

    async def evaluate_kharejs(self) -> None:
        st = self.store
        for k in st.kharejs():
            if not k.enabled:
                continue
            if k.id not in st.takeover and self.kharej_dead(k):
                await self.takeover(k)
            elif k.id in st.takeover and self.s.auto_failback and self.usable(k):
                # a flapping kharej must not bounce its ports back and forth
                settle = max(120, 3 * self.s.check_interval)
                if time.time() - self.takeover_at.get(k.id, 0) >= settle:
                    await self.release(k)

    def pick_takeover_target(self, dead: Server) -> Server | None:
        st = self.store
        best, best_score = None, None
        for k in st.kharejs():
            if k.id == dead.id or not self.usable(k) or k.id in st.takeover:
                continue
            up = [x for x in st.links_of(k.id) if x.status == L_UP]
            if not up:
                continue
            # prefer a kharej that is up on the Iran servers the dead one's domains use
            irans = {d.iran_id for d in st.domains.values() if st.effective_kharej(d.kharej_id) == dead.id}
            covered = sum(1 for x in up if x.iran_id in irans)
            score = (-covered, -len(up), k.priority)
            if best_score is None or score < best_score:
                best, best_score = k, score
        return best

    def port_conflicts(self, dead: Server, target: Server) -> list[str]:
        """Mappings of the dead kharej that cannot move because the target
        already listens on the same port with a different mapping."""
        theirs = {listen_key(p): p for p in target.ports}
        return [p for p in dead.ports if listen_key(p) in theirs and theirs[listen_key(p)] != p]

    async def takeover(self, dead: Server, target: Server | None = None) -> bool:
        st = self.store
        target = target or self.pick_takeover_target(dead)
        if target is None:
            await self.emit("error", "kharej", f"سرور خارج {dead.name} از کار افتاده و هیچ سرور خارج سالمی برای جایگزینی نیست", server=dead.id)
            st.takeover.pop(dead.id, None)
            return False
        conflicts = self.port_conflicts(dead, target)
        st.takeover[dead.id] = target.id
        self.takeover_at[dead.id] = time.time()
        for link in st.links_of(dead.id):
            if link.kharej_id == dead.id:
                link.status = L_SUSPENDED
                link.last_change = time.time()
                iran = st.servers.get(link.iran_id)
                if self.usable(iran):
                    try:
                        await self.driver.stop(link, iran, None)  # free its ports on the Iran side
                    except (SSHError, OSError):
                        pass
        for link in st.links.values():
            if link.kharej_id == target.id and link.status not in (L_PENDING, L_SUSPENDED):
                await self.redeploy_iran_side(link)
        doms = [d.fqdn for d in st.domains.values() if st.effective_kharej(d.kharej_id) == target.id and d.kharej_id != target.id]
        msg = f"سرور خارج {dead.name} از کار افتاده؛ ترافیک و پورت‌هایش به {target.name} منتقل شد"
        if doms:
            msg += f" (دامنه‌ها: {', '.join(doms)})"
        if conflicts:
            msg += f" — پورت‌های تکراری منتقل نشدند: {', '.join(conflicts)}"
        await self.emit("warning", "kharej", msg, server=dead.id, target=target.id)
        await self.changed()
        return True

    async def release(self, k: Server) -> None:
        st = self.store
        holder = st.effective_kharej(k.id)
        st.takeover.pop(k.id, None)
        for link in st.links.values():
            if link.kharej_id == holder and link.status not in (L_PENDING, L_SUSPENDED):
                await self.redeploy_iran_side(link)
        for link in st.links_of(k.id):
            if link.kharej_id == k.id and link.status == L_SUSPENDED:
                link.status = L_DOWN
                link.fail_count = self.s.fail_threshold
                self.repair_after.pop(link.id, None)
        await self.emit("success", "kharej", f"سرور خارج {k.name} برگشت؛ پورت‌هایش از {self.name(holder)} پس گرفته شد", server=k.id)
        # its links are rebuilt by the repair pass (same transport first)
        self.schedule_repairs()

    def best_iran_for(self, d: Domain, exclude: str | None = None) -> tuple[Server, Link] | None:
        st = self.store
        k = st.effective_kharej(d.kharej_id)
        options = []
        for i in st.irans():
            if i.id == exclude or not self.usable(i):
                continue
            link = st.link_for(i.id, k)
            if link and link.status == L_UP:
                options.append((i.priority, link.latency_ms or 9e9, i, link))
        if not options:
            return None
        options.sort(key=lambda o: (o[0], o[1]))
        return options[0][2], options[0][3]

    async def switch_domain(self, d: Domain, iran: Server, reason: str = "") -> bool:
        p = self.store.providers.get(d.provider_id)
        if not p:
            await self.emit("error", "dns", f"دامنه {d.fqdn} حساب DNS ندارد", domain=d.id)
            return False
        old = self.store.servers.get(d.iran_id)
        async with self._dns_lock:
            try:
                await self.dns_factory(p).set_a(d.fqdn, iran.ip, d.ttl)
            except (DNSError, OSError, Exception) as e:  # noqa: B014 - httpx errors too
                d.error = str(e)
                await self.emit("error", "dns", f"تغییر رکورد {d.fqdn} به {iran.ip} ناموفق بود: {e}", domain=d.id)
                return False
        d.iran_id, d.current_ip, d.last_switch, d.error = iran.id, iran.ip, time.time(), ""
        d.status = "ok"
        frm = f"{old.name} ({old.ip})" if old else "—"
        await self.emit(
            "warning" if reason else "success",
            "dns",
            f"آی‌پی دامنه {d.fqdn} از {frm} به {iran.name} ({iran.ip}) تغییر کرد" + (f" — {reason}" if reason else ""),
            domain=d.id,
        )
        return True

    async def evaluate_domains(self) -> None:
        st = self.store
        for d in list(st.domains.values()):
            k = st.effective_kharej(d.kharej_id)
            iran = st.servers.get(d.iran_id) if d.iran_id else None
            link = st.link_for(d.iran_id, k) if d.iran_id else None
            healthy = bool(link and link.status == L_UP and self.usable(iran))
            if healthy:
                if d.status != "ok":
                    d.status = "ok"
                    d.error = ""
                continue
            if link and link.id in self.busy:
                continue  # repair in progress: give it a chance first
            if not d.auto_failover and d.iran_id:
                d.status = "broken"
                continue
            iran_dead = iran is None or self.is_down(iran)
            link_dead = link is None or link.status in (L_DOWN, L_SUSPENDED, L_PENDING)
            if not (iran_dead or link_dead):
                continue  # degraded only: wait for the threshold
            if (
                not iran_dead
                and link is not None
                and link.status == L_DOWN
                and self.repair_after.get(link.id, 0) <= time.time()
                and self.usable(st.servers.get(k))
            ):
                continue  # repair not attempted yet; schedule_repairs will
            choice = self.best_iran_for(d, exclude=d.iran_id or None)
            if choice is None:
                if any(x.id in self.busy for x in st.links.values() if x.kharej_id == k):
                    continue  # paths to this kharej are being built/repaired right now
                if d.status != "broken":
                    d.status = "broken"
                    await self.emit("error", "domain", f"دامنه {d.fqdn}: هیچ سرور داخلی با مسیر سالم به {self.name(k)} پیدا نشد؛ در حال ساخت/تعمیر مسیرها", domain=d.id)
                self._kick_paths_for(k)
                continue
            new_iran, new_link = choice
            if not d.iran_id:
                reason = ""
            elif iran_dead:
                reason = f"سرور داخل {self.name(d.iran_id)} در دسترس نیست"
            else:
                reason = f"مسیر {self.name(d.iran_id)} ⇄ {self.name(k)} قطع است"
            await self.switch_domain(d, new_iran, reason)

    def _kick_paths_for(self, kharej_id: str) -> None:
        """No Iran server reaches this kharej: build or repair its links."""
        for link in self.store.links.values():
            if link.kharej_id != kharej_id or link.id in self.busy:
                continue
            iran, kharej = self.pair(link)
            if not (self.usable(iran) and self.usable(kharej)):
                continue
            if link.status == L_PENDING:
                self.spawn(self.discover(link))
            elif link.status == L_DOWN and self.repair_after.get(link.id, 0) <= time.time():
                self.busy.add(link.id)
                self.spawn(self._repair_then_failover(link))

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
                extra = ""
                if srv.id in st.takeover:
                    extra = f" → {esc(self.name(st.takeover[srv.id]))}"
                lines.append(f"{dot} {esc(srv.name)} <code>{esc(srv.ip)}</code>{extra}")
            lines.append("")
        lines.append("<b>🌐 دامنه‌ها</b>")
        for d in st.domains.values():
            dot = "🟢" if d.status == "ok" else "🔴" if d.status == "broken" else "⚪"
            k = st.effective_kharej(d.kharej_id)
            lines.append(f"{dot} {esc(d.fqdn)} → {esc(self.name(d.iran_id) if d.iran_id else '—')} ⇄ {esc(self.name(k))}")
        return "\n".join(lines)

    def links_text(self) -> str:
        icon = {L_UP: "🟢", L_DEGRADED: "🟡", L_DOWN: "🔴", L_TESTING: "🔵", L_SUSPENDED: "⏸", L_PENDING: "⚪"}
        lines = ["<b>🔗 تانل‌ها</b>"]
        for x in sorted(self.store.links.values(), key=lambda x: (self.name(x.kharej_id), self.name(x.iran_id))):
            lat = f" {x.latency_ms:.0f}ms" if x.latency_ms else ""
            lines.append(f"{icon.get(x.status, '⚪')} {esc(self.link_label(x))} <code>{esc(x.transport or '—')}</code>{lat}")
        return "\n".join(lines)

    async def bot_command(self, cmd: str, args: list[str]) -> str:
        if cmd in ("/start", "/help"):
            return (
                "دستورها:\n/status — خلاصه وضعیت\n/links — وضعیت تانل‌ها\n"
                "/domains — دامنه‌ها\n/check — بررسی فوری همه مسیرها"
            )
        if cmd in ("/status",):
            return self.summary()
        if cmd == "/links":
            return self.links_text()
        if cmd == "/domains":
            return self.summary().split("<b>🌐 دامنه‌ها</b>", 1)[-1].strip() or "دامنه‌ای ثبت نشده"
        if cmd == "/check":
            self.wake()
            return "🔄 بررسی فوری شروع شد"
        return "دستور ناشناخته — /help"
