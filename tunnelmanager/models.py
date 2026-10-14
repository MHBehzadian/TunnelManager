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
L_PENDING = "pending"  # created, never deployed
L_TESTING = "testing"  # transport discovery / repair running
L_UP = "up"  # probe through the tunnel succeeds
L_DEGRADED = "degraded"  # engine says connected but the probe fails
L_DOWN = "down"
L_SUSPENDED = "suspended"  # its kharej is down and another kharej took its ports

# Transports a reverse BackPack tunnel can run on that carry TCP and need no
# extra setup (wss/wssmux fall back to a self-signed certificate). "udp" only
# carries UDP and cannot be probed with TCP, so it is not offered.
ALL_TRANSPORTS = ["tcpmux", "wsmux", "tcp", "ws", "stealth", "kcp", "quic", "wssmux", "wss"]

DEFAULT_TRANSPORTS = ["tcpmux", "wsmux", "tcp", "ws", "stealth", "kcp", "quic"]


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
    # kharej only: forwarded port mappings, BackPack syntax ("443", "8443=2096", ...)
    ports: list[str] = field(default_factory=list)
    accept_udp: bool = False
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
    iran_id: str
    kharej_id: str
    tunnel_port: int
    probe_port: int
    id: str = field(default_factory=lambda: new_id("l"))
    token: str = field(default_factory=lambda: secrets.token_hex(16))
    transport: str = ""
    status: str = L_PENDING
    latency_ms: float | None = None
    last_ok: float = 0
    last_change: float = field(default_factory=now)
    fail_count: int = 0
    tests: dict[str, dict[str, Any]] = field(default_factory=dict)  # transport -> TestResult
    pinned: bool = False  # user picked the transport by hand
    error: str = ""
    history: list[list[float]] = field(default_factory=list)  # [[ts, latency or -1], ...]

    @property
    def service(self) -> str:
        return f"tm-{self.id}"

    def ranked_transports(self, candidates: list[str]) -> list[str]:
        """Candidates ordered by last test: working ones fastest first, then
        untested ones in the configured order, then the ones that failed."""
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
    kharej_id: str  # the kharej server this domain's service lives on
    id: str = field(default_factory=lambda: new_id("d"))
    iran_id: str = ""  # the Iran server the A record points at right now
    ttl: int = 60
    auto_failover: bool = True
    status: str = UNKNOWN  # ok | broken | unknown
    current_ip: str = ""
    last_switch: float = 0
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
    check_interval: int = 30
    fail_threshold: int = 3  # consecutive failed checks before acting
    candidate_transports: list[str] = field(default_factory=lambda: list(DEFAULT_TRANSPORTS))
    tunnel_port_base: int = 3080
    probe_port_base: int = 61000
    test_timeout: int = 15  # seconds a transport gets to come up during a test
    auto_failback: bool = True  # give a recovered kharej its ports back
    install_backpack: bool = True  # push the binary to servers that lack it
    backpack_release: str = "latest"  # GitHub release tag, or "latest"
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
