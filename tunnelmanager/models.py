"""Data model. Everything is plain dataclasses persisted as one JSON file."""

from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any

IRAN = "iran"
KHAREJ = "kharej"

# Server status
ONLINE = "online"
OFFLINE = "offline"
UNKNOWN = "unknown"

# Link status
L_PENDING = "pending"  # placeholder, never deployed
L_TESTING = "testing"  # transport discovery / repair running
L_UP = "up"  # tunnel carries traffic
L_DEGRADED = "degraded"  # failing, but not for long enough to act on
L_DOWN = "down"

# Transports a reverse BackPack tunnel can run on that carry TCP and need no
# extra setup (wss/wssmux fall back to a self-signed certificate). "udp" only
# carries UDP and cannot be probed with TCP, so it is not offered.
ALL_TRANSPORTS = ["tcpmux", "wsmux", "tcp", "ws", "stealth", "kcp", "quic", "wssmux", "wss"]
DEFAULT_TRANSPORTS = ["tcpmux", "wsmux", "tcp", "ws", "stealth", "kcp", "quic"]
TCP_TRANSPORTS = {"tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "stealth"}


def new_id(prefix: str = "") -> str:
    return prefix + secrets.token_hex(3)


def now() -> float:
    return time.time()


class Model:
    """Mixin: tolerant (de)serialisation, so old state files keep loading."""

    @classmethod
    def from_dict(cls, d: dict[str, Any]):
        names = {f.name for f in fields(cls)}  # type: ignore[arg-type]
        return cls(**{k: v for k, v in d.items() if k in names})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[call-overload]


@dataclass
class Server(Model):
    name: str
    role: str  # iran | kharej
    ip: str
    id: str = field(default_factory=lambda: new_id("s"))
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str = ""
    ssh_key: str = ""  # private key text (optional)
    priority: int = 100  # lower = preferred
    enabled: bool = True
    # kharej only: what the health probe dials at the far end of each tunnel.
    # Anything that speaks first works; sshd's banner is always there.
    probe_target: str = ""
    # runtime
    status: str = UNKNOWN
    last_seen: float = 0
    ssh_latency_ms: float | None = None
    backpack_version: str = ""
    error: str = ""
    fail_count: int = 0
    last_scan: float = 0

    def probe_addr(self) -> str:
        return self.probe_target or f"127.0.0.1:{self.ssh_port}"

    def public(self) -> dict[str, Any]:
        d = self.to_dict()
        d["ssh_password"] = "••••" if self.ssh_password else ""
        d["ssh_key"] = "••••" if self.ssh_key else ""
        return d


@dataclass
class TestResult(Model):
    transport: str
    ok: bool
    latency_ms: float | None = None
    connect_s: float | None = None  # seconds until the tunnel carried traffic
    error: str = ""
    at: float = field(default_factory=now)


@dataclass
class Link(Model):
    """One BackPack reverse tunnel: a [server] config on an Iran server and the
    matching [client] config on a kharej server. Several links may join the
    same pair (e.g. one on tcpmux and a spare on wsmux)."""

    iran_id: str
    kharej_id: str
    tunnel_port: int
    id: str = field(default_factory=lambda: new_id("l"))
    probe_port: int = 0  # loopback probe on the Iran side; 0 = not added yet
    token: str = field(default_factory=lambda: secrets.token_hex(16))
    transport: str = ""
    # forwarded ports, BackPack syntax. They live in the Iran side's config:
    # "443" = Iran :443 -> kharej 127.0.0.1:443, "8443=2096", "2053-2060"...
    ports: list[str] = field(default_factory=list)
    accept_udp: bool = False
    label: str = ""
    priority: int = 100  # order among links of the same pair
    # managed links were built by the panel (tm-<id>); adopted ones were found
    # already running on the servers and keep their own names and settings
    managed: bool = True
    iran_name: str = ""
    kharej_name: str = ""
    iran_base: dict[str, Any] = field(default_factory=dict)  # original [server] keys
    kharej_base: dict[str, Any] = field(default_factory=dict)  # original [client] keys
    allowed: list[str] = field(default_factory=list)  # transports repair may use; [] = global list
    pinned: bool = False  # never change the transport automatically
    # systemd units running each side; "" = BackPack's own "backpack-<name>.service"
    iran_unit: str = ""
    kharej_unit: str = ""
    built: bool = False  # has run at least once (adopted tunnels: always)
    # runtime
    status: str = L_PENDING
    latency_ms: float | None = None
    last_ok: float = 0
    last_fail: float = 0
    last_change: float = field(default_factory=now)
    up_since: float = 0
    fail_count: int = 0
    flaps: list[float] = field(default_factory=list)  # when a working link started failing
    verified: bool = True  # False when health could only be inferred (no probe)
    tests: dict[str, dict[str, Any]] = field(default_factory=dict)  # transport -> TestResult
    error: str = ""
    history: list[list[float]] = field(default_factory=list)  # [[ts, latency or -1], ...]

    def __post_init__(self) -> None:
        if not self.iran_name:
            self.iran_name = f"tm-{self.id}"
        if not self.kharej_name:
            self.kharej_name = f"tm-{self.id}"

    def ranked_transports(self, candidates: list[str]) -> list[str]:
        """Candidates ordered by last test: working ones fastest first, then
        untested ones in the configured order, then the ones that failed."""
        if self.allowed:
            candidates = [t for t in candidates if t in self.allowed] or list(self.allowed)
        ok, untested, bad = [], [], []
        for t in candidates:
            r = self.tests.get(t)
            if r is None:
                untested.append(t)
            elif r.get("ok"):
                ok.append((r.get("latency_ms") or 9e9, t))
            else:
                bad.append(t)
        return [t for _, t in sorted(ok)] + untested + bad

    def record(self, latency: float | None, keep: int = 120) -> None:
        self.history.append([round(now()), -1 if latency is None else round(latency, 1)])
        del self.history[:-keep]

    def flapping(self, window: float, count: int) -> bool:
        cutoff = now() - window
        return sum(1 for t in self.flaps if t >= cutoff) >= count


@dataclass
class DNSProvider(Model):
    name: str
    kind: str  # cloudflare | arvan
    api_token: str
    zone: str  # example.com
    id: str = field(default_factory=lambda: new_id("p"))
    proxied: bool = False  # cloudflare orange cloud / arvan "cloud"

    def public(self) -> dict[str, Any]:
        d = self.to_dict()
        d["api_token"] = "••••" if self.api_token else ""
        return d


@dataclass
class Domain(Model):
    fqdn: str
    provider_id: str
    kharej_id: str = ""  # where the service lives; builds the automatic group
    id: str = field(default_factory=lambda: new_id("d"))
    # Failover group: the tunnels this domain may use, in order of preference.
    # The first one is the primary the domain returns to once it is stable.
    # Empty = automatic (every tunnel to kharej_id, best Iran server first).
    group: list[str] = field(default_factory=list)
    link_id: str = ""  # the tunnel whose ports the domain is served from; DNS points at its Iran server
    ttl: int = 120
    auto_failover: bool = True
    status: str = UNKNOWN  # ok | broken | unknown
    current_ip: str = ""
    last_switch: float = 0
    # DNS propagation of the last change
    pending_ip: str = ""
    pending_since: float = 0
    error: str = ""


@dataclass
class Telegram(Model):
    bot_token: str = ""
    chat_ids: list[str] = field(default_factory=list)
    api_base: str = "https://api.telegram.org"  # a reverse proxy if Telegram is blocked
    proxy: str = ""  # http://... or socks5://...
    enabled: bool = True


@dataclass
class Settings(Model):
    # Observe only: watch, show and report, but change nothing by itself (no
    # DNS switch, no config rewrite, no restart). Actions taken by hand in
    # the panel still work. On by default, so a fresh panel pointed at live
    # servers cannot disturb them until it is switched off on purpose.
    observe_only: bool = True
    check_interval: int = 30
    fail_threshold: int = 3  # consecutive failed checks before a tunnel counts as down
    flap_window: int = 600  # seconds
    flap_count: int = 3  # this many drops inside flap_window = unstable
    failback_after: int = 600  # seconds the primary must be stable before traffic returns
    candidate_transports: list[str] = field(default_factory=lambda: list(DEFAULT_TRANSPORTS))
    tunnel_port_base: int = 3080
    probe_port_base: int = 61000
    test_timeout: int = 15  # seconds a transport gets to come up during a test
    auto_repair: bool = True  # rebuild broken tunnels with other transports
    auto_adopt: bool = True  # import tunnels already running on the servers
    auto_mesh: bool = False  # offer a (not yet built) tunnel for pairs that have none
    scan_interval: int = 600
    install_backpack: bool = True  # push the binary to servers that lack it
    backpack_release: str = "latest"  # GitHub release tag, or "latest"
    doh_resolvers: list[str] = field(
        default_factory=lambda: ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
    )
    telegram: dict[str, Any] = field(default_factory=lambda: Telegram().to_dict())

    def tg(self) -> Telegram:
        return Telegram.from_dict(self.telegram)


@dataclass
class Event(Model):
    level: str  # info | success | warning | error
    kind: str
    message: str
    refs: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("e"))
    ts: float = field(default_factory=now)
