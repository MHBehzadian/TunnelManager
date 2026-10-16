"""Everything that touches BackPack on the servers: config rendering, deploy,
install, scanning for existing tunnels, and the health checks.

A link's files follow BackPack's own layout, so every tunnel also shows up
in BackPack's CLI and web panel:

    /etc/backpack/<name>.toml                 config
    /etc/backpack/<name>.metrics.json         written by the engine
    /etc/systemd/system/backpack-<name>.service

Tunnels the panel builds are named ``tm-<link id>``. Tunnels it *adopts*
(found already running) keep their names, and every key in their config the
panel does not manage is preserved when it rewrites them.

Health is checked end to end where possible: the Iran side of a tunnel gets a
loopback-only *probe port* mapped to the kharej's sshd (``127.0.0.1:61000 =
127.0.0.1:22``), and reading ``SSH-`` from it on the Iran server proves the
whole path works. An adopted tunnel has no probe until the panel first
rewrites its config; until then the engine's own report (``connected`` in
its metrics file) or an established connection on the tunnel port is used.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import re
import shlex
import statistics
import tarfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .models import TCP_TRANSPORTS, Link, Server
from .ssh import SSHError, SSHPool

log = logging.getLogger(__name__)

BIN_PATH = "/usr/local/bin/backpack"
CONF_DIR = "/etc/backpack"
UNIT_DIR = "/etc/systemd/system"
RELEASE_URL = "https://github.com/AminMGMT/BackPack/releases/{path}"

ARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armv7",
    "armv6l": "armv6",
    "i686": "386",
    "i386": "386",
}

_SAFE = re.compile(r"^[A-Za-z0-9_.:\-=|,\[\]]+$")
_NAME = re.compile(r"^[A-Za-z0-9_.\-]+$")
PROBE_RE = re.compile(r"^127\.0\.0\.1:(\d+)=127\.0\.0\.1:\d+$")


class DeployError(Exception):
    pass


@dataclass
class Probe:
    ok: bool
    latency_ms: float | None = None
    active: str = ""
    connected: bool | None = None
    connect_s: float | None = None
    verified: bool = True
    error: str = ""


@dataclass
class Found:
    """A tunnel config found on a server by scan()."""

    name: str
    role: str  # server | client
    data: dict[str, Any]
    active: str = ""
    unit: str = ""  # systemd unit running it ("" = none found)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def transport(self) -> str:
        return str(self.data.get("transport", "tcp"))

    @property
    def token(self) -> str:
        return str(self.data.get("token") or "backpack")  # BackPack's built-in default

    def port(self) -> int | None:
        addr = str(self.data.get("bind_addr" if self.role == "server" else "remote_addr", ""))
        try:
            return int(addr.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return None

    def host(self) -> str:
        addr = str(self.data.get("bind_addr" if self.role == "server" else "remote_addr", ""))
        return addr.rsplit(":", 1)[0].strip("[]") if ":" in addr else ""


def validate_port_mapping(p: str) -> str:
    p = p.strip()
    if not p or not _SAFE.match(p):
        raise ValueError(f"invalid port mapping: {p!r}")
    return p


def split_ports(ports: list[str]) -> tuple[list[str], int]:
    """Separate the panel's probe mapping from the user's ports."""
    probe, out = 0, []
    for p in ports:
        m = PROBE_RE.match(p.strip())
        if m and int(m.group(1)) >= 1024 and not probe:
            probe = int(m.group(1))
        else:
            out.append(p)
    return out, probe


# ---------------------------------------------------------------- TOML out
def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + "".join(f"    {_toml_value(x)},\n" for x in v) + "]"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def dump_section(name: str, data: dict[str, Any], header: str = "") -> str:
    lines = [header] if header else []
    lines.append(f"[{name}]")
    subs = []
    for k, v in data.items():
        if isinstance(v, dict):
            subs.append((k, v))
        else:
            lines.append(f"{k} = {_toml_value(v)}")
    out = "\n".join(lines) + "\n"
    for k, v in subs:
        out += "\n" + dump_section(f"{name}.{k}", v)
    return out


def q(s: str) -> str:
    return _toml_value(s)


# ------------------------------------------------------------ rendering
def server_section(link: Link, transport: str, ports: list[str], kharej: Server) -> dict[str, Any]:
    d = dict(link.iran_base)
    host = str(d.get("bind_addr", "0.0.0.0:0")).rsplit(":", 1)[0] or "0.0.0.0"
    d["bind_addr"] = f"{host}:{link.tunnel_port}"
    d["transport"] = transport
    d["token"] = link.token
    d["accept_udp"] = bool(link.accept_udp)
    d.setdefault("log_level", "info")
    probe = [f"127.0.0.1:{link.probe_port}={kharej.probe_addr()}"] if link.probe_port else []
    d["ports"] = probe + list(ports)
    return d


def client_section(link: Link, transport: str, iran: Server) -> dict[str, Any]:
    d = dict(link.kharej_base)
    base_host = str(d.get("remote_addr", "")).rsplit(":", 1)[0] if ":" in str(d.get("remote_addr", "")) else ""
    host = base_host or (f"[{iran.ip}]" if ":" in iran.ip else iran.ip)
    d["remote_addr"] = f"{host}:{link.tunnel_port}"
    d["transport"] = transport
    d["token"] = link.token
    d.setdefault("connection_pool", 8)
    d.setdefault("log_level", "info")
    return d


def render_server(link: Link, transport: str, ports: list[str], kharej: Server) -> str:
    head = f"# Managed by TunnelManager (link {link.id}) - kharej {kharej.name} -> this Iran server"
    return dump_section("server", server_section(link, transport, ports, kharej), head)


def render_client(link: Link, transport: str, iran: Server) -> str:
    head = f"# Managed by TunnelManager (link {link.id}) - this kharej server -> Iran {iran.name}"
    return dump_section("client", client_section(link, transport, iran), head)


def unit_name(name: str) -> str:
    return f"backpack-{name}.service"


def iran_unit(link: Link) -> str:
    return link.iran_unit or unit_name(link.iran_name)


def kharej_unit(link: Link) -> str:
    return link.kharej_unit or unit_name(link.kharej_name)


def conf_path(name: str) -> str:
    return f"{CONF_DIR}/{name}.toml"


def render_unit(name: str) -> str:
    return f"""[Unit]
Description=Backpack Tunnel ({name})
After=network.target

[Service]
Type=simple
ExecStart={BIN_PATH} -c {conf_path(name)}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


# ------------------------------------------------------------- scripts
def _probe_snippet(port: int) -> str:
    # Opens the probe port and reads the first bytes the far end sends.
    return f"timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; head -c 4 <&3' 2>/dev/null"


def check_script(links: list[Link]) -> str:
    """One round trip per Iran server: unit state, the engine's own view, an
    end-to-end probe where the tunnel has one, and established connections
    on the tunnel port (from /proc, no tools needed) as the last resort."""
    parts = []
    for x in links:
        n = shlex.quote(x.iran_name)
        u = shlex.quote(iran_unit(x))
        if x.probe_port:
            probe = f't0=$(date +%s%N); b=$({_probe_snippet(x.probe_port)}); t1=$(date +%s%N); p=$( [ -n "$b" ] && echo 1 || echo 0)'
        else:
            probe = "t0=0; t1=0; p=-"
        parts.append(
            f"""a=$(systemctl is-active {u} 2>/dev/null)
c=$(grep -o '"connected": *[a-z]*' {CONF_DIR}/{n}.metrics.json 2>/dev/null | grep -o '[a-z]*$')
{probe}
e=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '{{ split($2,a,":"); if (a[2]=="{x.tunnel_port:04X}" && $4=="01") n++ }} END {{ print n+0 }}')
echo "@@{x.id}|$a|$c|$p|$(( (t1-t0)/1000 ))|$e"
"""
        )
    return "".join(parts)


def parse_check(out: str, links: dict[str, Link] | None = None) -> dict[str, Probe]:
    res = {}
    for line in out.splitlines():
        if not line.startswith("@@"):
            continue
        parts = line[2:].split("|")
        if len(parts) < 5:
            continue
        lid, active, conn, ok, us = parts[:5]
        estab = int(parts[5]) if len(parts) > 5 and parts[5].strip().isdigit() else 0
        connected = None if conn == "" else conn == "true"
        if ok in ("0", "1"):
            good = ok == "1"
            res[lid] = Probe(
                ok=good,
                active=active,
                connected=connected,
                latency_ms=round(int(us) / 1000, 1) if good and us.isdigit() else None,
            )
            continue
        # no probe port: infer from the engine, then from the socket table
        link = (links or {}).get(lid)
        tcp = link is None or link.transport in TCP_TRANSPORTS
        if active != "active":
            good = False
        elif connected is not None:
            good = connected
        elif tcp:
            good = estab > 0
        else:
            good = True  # a running datagram tunnel we cannot see into
        res[lid] = Probe(ok=good, active=active, connected=connected, verified=False)
    return res


def wait_script(port: int, timeout: int, samples: int = 5) -> str:
    return f"""s=$(date +%s%N); end=$(( $(date +%s) + {timeout} ))
while :; do
  b=$({_probe_snippet(port)})
  [ -n "$b" ] && break
  [ $(date +%s) -ge $end ] && {{ echo FAIL; exit 0; }}
  sleep 0.5
done
c=$(( ($(date +%s%N) - s) / 1000000 )); out="OK $c"
for i in $(seq 1 {samples}); do
  t0=$(date +%s%N); b=$({_probe_snippet(port)}); t1=$(date +%s%N)
  [ -n "$b" ] && out="$out $(( (t1-t0)/1000 ))"
done
echo "$out"
"""


def parse_wait(out: str) -> Probe:
    words = out.strip().split()
    if not words or words[0] != "OK":
        return Probe(ok=False, error="tunnel did not carry traffic in time")
    connect_ms = int(words[1])
    lats = [int(w) / 1000 for w in words[2:] if w.isdigit()]
    if not lats:
        return Probe(ok=False, error="tunnel came up but is unstable", connect_s=connect_ms / 1000)
    return Probe(ok=True, latency_ms=round(statistics.median(lats), 1), connect_s=round(connect_ms / 1000, 2))


SCAN_SCRIPT = f"""for f in {CONF_DIR}/*.toml; do
  [ -f "$f" ] || continue
  n=$(basename "$f" .toml)
  u="backpack-$n.service"
  if ! systemctl cat "$u" >/dev/null 2>&1; then
    u=$(grep -lsF -- "$f" /etc/systemd/system/*.service /lib/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null | head -n1)
    u=${{u##*/}}
  fi
  a=-
  [ -n "$u" ] && a=$(systemctl is-active "$u" 2>/dev/null)
  echo "@@FILE $n ${{u:--}} ${{a:--}}"
  head -c 65536 "$f"
  echo
done
echo "@@END"
"""

LISTEN_SCRIPT = (
    "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"0A\" {split($2,a,\":\"); print a[2]}'; "
    "cat /proc/net/udp /proc/net/udp6 2>/dev/null | awk '{split($2,a,\":\"); print a[2]}'"
)


def parse_listening(out: str) -> set[int]:
    ports = set()
    for w in out.split():
        try:
            ports.add(int(w, 16))
        except ValueError:
            pass
    return ports


def listen_ports(mappings: list[str], limit: int = 5000) -> set[int]:
    """The ports a list of mappings makes the Iran side listen on."""
    out: set[int] = set()
    for m in mappings:
        port = m.split("=", 1)[0].strip().rsplit(":", 1)[-1]
        lo, _, hi = port.partition("-")
        try:
            a, b = int(lo), int(hi or lo)
        except ValueError:
            continue
        out.update(range(a, min(b, a + limit) + 1))
    return out


def parse_scan(out: str) -> list[Found]:
    """Reverse tunnels in a server's /etc/backpack. Direct/L3 tunnels and
    anything unparsable are skipped."""
    found: list[Found] = []
    chunks = out.split("@@FILE ")[1:]
    for chunk in chunks:
        head, _, body = chunk.partition("\n")
        body = body.split("@@END")[0]
        parts = head.split()
        if not parts or not _NAME.match(parts[0]):
            continue
        name = parts[0]
        if len(parts) >= 3:  # name unit active
            unit, active = parts[1], parts[2]
        else:  # older panel scripts: name active
            unit, active = unit_name(name), (parts[1] if len(parts) > 1 else "")
        unit = "" if unit == "-" else unit
        active = "" if active == "-" else active
        try:
            data = tomllib.loads(body)
        except tomllib.TOMLDecodeError:
            log.info("scan: cannot parse %s", name)
            continue
        for role in ("server", "client"):
            sec = data.get(role)
            if isinstance(sec, dict) and sec.get("transport") != "spoof":
                found.append(Found(name=name, role=role, data=sec, active=active.strip(), unit=unit))
    return found


def _ufw_allow(ports: list[str]) -> str:
    """Open ports on ufw if it is active. Mappings are reduced to their
    listening port (or range)."""
    nums = []
    for p in ports:
        listen = p.split("=", 1)[0]
        if listen.startswith(("127.", "[::1]")):
            continue
        port = listen.rsplit(":", 1)[-1]  # "1.2.3.4:443" / "[::]:443" / "443"
        if "-" in port:  # ufw writes ranges as a:b and wants a protocol with them
            nums += [port.replace("-", ":") + "/tcp", port.replace("-", ":") + "/udp"]
        else:
            nums.append(port)
    if not nums:
        return ""
    rules = " ".join(f"ufw allow {shlex.quote(n)} >/dev/null 2>&1;" for n in nums)
    return f"if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then {rules} fi\n"


# --------------------------------------------------------------- drivers
class Driver:
    """Abstract driver so the orchestrator can be tested without servers."""

    async def ping(self, s: Server) -> float: ...
    async def ensure_installed(self, s: Server, install: bool = True) -> str: ...
    async def deploy(self, link: Link, iran: Server, kharej: Server, transport: str, ports: list[str]) -> None: ...
    async def deploy_iran(self, link: Link, iran: Server, kharej: Server, ports: list[str]) -> None: ...
    async def stop(self, link: Link, iran: Server | None, kharej: Server | None) -> None: ...
    async def remove(self, link: Link, iran: Server | None, kharej: Server | None) -> None: ...
    async def check(self, iran: Server, links: list[Link]) -> dict[str, Probe]: ...
    async def wait_up(self, link: Link, iran: Server, timeout: int) -> Probe: ...
    async def scan(self, s: Server) -> list[Found]: ...

    async def listening(self, s: Server) -> set[int]:
        return set()


class SSHDriver(Driver):
    def __init__(self, pool: SSHPool, cache_dir: Path, release: str = "latest"):
        self.pool = pool
        self.cache_dir = Path(cache_dir)
        self.release = release
        self._dl_lock = asyncio.Lock()

    async def ping(self, s: Server) -> float:
        return await self.pool.ping(s)

    # ---- install -------------------------------------------------------
    async def installed_version(self, s: Server) -> tuple[str, str]:
        r = await self.pool.run(
            s, f"uname -m; test -x {BIN_PATH} && {BIN_PATH} -v 2>/dev/null | head -n1 || echo MISSING", timeout=20
        )
        lines = r.out.strip().splitlines() + ["", ""]
        return lines[0].strip(), lines[1].strip()

    async def _binary(self, arch: str) -> bytes:
        """Fetch the release tarball once, verify its checksum, return the
        binary. Servers in Iran often cannot reach GitHub, so the panel
        downloads and pushes it over SSH. A tarball dropped into the cache
        directory by hand is used as is."""
        name = f"backpack_linux_{arch}.tar.gz"
        tag = self.release
        path = self.cache_dir / tag / name
        async with self._dl_lock:
            if not path.exists():
                rel = "latest/download" if tag == "latest" else f"download/{tag}"
                async with httpx.AsyncClient(follow_redirects=True, timeout=120) as c:
                    sums = (await c.get(RELEASE_URL.format(path=f"{rel}/SHA256SUMS"))).raise_for_status().text
                    blob = (await c.get(RELEASE_URL.format(path=f"{rel}/{name}"))).raise_for_status().content
                want = next((ln.split()[0] for ln in sums.splitlines() if ln.strip().endswith(name)), None)
                if want and hashlib.sha256(blob).hexdigest() != want:
                    raise DeployError(f"checksum mismatch for {name}")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(blob)
            with tarfile.open(fileobj=io.BytesIO(path.read_bytes())) as tar:
                for m in tar.getmembers():
                    if m.isfile() and Path(m.name).name == "backpack":
                        f = tar.extractfile(m)
                        assert f
                        return f.read()
        raise DeployError(f"no backpack binary in {name}")

    async def ensure_installed(self, s: Server, install: bool = True) -> str:
        machine, ver = await self.installed_version(s)
        if ver and ver != "MISSING":
            return ver
        if not install:
            raise DeployError(f"BackPack is not installed on {s.name}")
        arch = ARCH.get(machine)
        if not arch:
            raise DeployError(f"unsupported architecture on {s.name}: {machine}")
        data = await self._binary(arch)
        await self.pool.run(s, f"mkdir -p {CONF_DIR} && chmod 700 {CONF_DIR}")
        await self.pool.put(s, data, BIN_PATH, 0o755)
        _, ver = await self.installed_version(s)
        if not ver or ver == "MISSING":
            raise DeployError(f"BackPack did not run after install on {s.name}")
        return ver

    # ---- deploy --------------------------------------------------------
    async def _install_side(self, s: Server, name: str, toml: str, open_ports: list[str], unit: str = "") -> None:
        if not _NAME.match(name) or (unit and not _NAME.match(unit)):
            raise DeployError(f"bad tunnel name {name!r}")
        conf = conf_path(name)
        # the first time the panel touches a config it did not write, keep the
        # original next to it: <name>.toml.tm-orig (never overwritten)
        await self.pool.run(
            s,
            f"mkdir -p {CONF_DIR} && chmod 700 {CONF_DIR}; "
            f"if [ -f {conf} ] && [ ! -f {conf}.tm-orig ]; then cp -p {conf} {conf}.tm-orig; fi; true",
        )
        await self.pool.put(s, toml.encode(), conf, 0o600)
        u = unit or unit_name(name)
        # keep an existing unit (adopted tunnels have their own); write ours otherwise
        r = await self.pool.run(s, f"systemctl cat {u} >/dev/null 2>&1 && echo yes || echo no", timeout=15)
        if r.out.strip() != "yes":
            await self.pool.put(s, render_unit(name).encode(), f"{UNIT_DIR}/{u}", 0o644)
        cmd = (
            _ufw_allow(open_ports)
            + f"rm -f {CONF_DIR}/{name}.metrics.json; systemctl daemon-reload && "
            f"systemctl enable {u} >/dev/null 2>&1; systemctl restart {u}"
        )
        r = await self.pool.run(s, cmd, timeout=40)
        if not r.ok:
            raise DeployError(f"{s.name}: {r.err.strip() or r.out.strip() or 'systemctl failed'}")

    async def deploy(self, link: Link, iran: Server, kharej: Server, transport: str, ports: list[str]) -> None:
        open_ports = [str(link.tunnel_port)] + ports
        await asyncio.gather(
            self._install_side(iran, link.iran_name, render_server(link, transport, ports, kharej), open_ports, iran_unit(link)),
            self._install_side(kharej, link.kharej_name, render_client(link, transport, iran), [], kharej_unit(link)),
        )

    async def deploy_iran(self, link: Link, iran: Server, kharej: Server, ports: list[str]) -> None:
        await self._install_side(
            iran,
            link.iran_name,
            render_server(link, link.transport, ports, kharej),
            [str(link.tunnel_port)] + ports,
            iran_unit(link),
        )

    async def _stop_side(self, s: Server | None, name: str, purge: bool, unit: str = "") -> None:
        if s is None or not _NAME.match(name) or (unit and not _NAME.match(unit)):
            return
        u = unit or unit_name(name)
        cmd = f"systemctl disable --now {u} >/dev/null 2>&1; true"
        if purge:
            cmd += f"; rm -f {UNIT_DIR}/{u} {conf_path(name)} {CONF_DIR}/{name}.metrics.json; systemctl daemon-reload"
        try:
            await self.pool.run(s, cmd, timeout=30)
        except SSHError as e:
            log.info("stop %s on %s: %s", name, s.name, e)

    async def stop(self, link: Link, iran: Server | None, kharej: Server | None) -> None:
        await asyncio.gather(
            self._stop_side(iran, link.iran_name, False, iran_unit(link)),
            self._stop_side(kharej, link.kharej_name, False, kharej_unit(link)),
        )

    async def remove(self, link: Link, iran: Server | None, kharej: Server | None) -> None:
        await asyncio.gather(
            self._stop_side(iran, link.iran_name, True, iran_unit(link)),
            self._stop_side(kharej, link.kharej_name, True, kharej_unit(link)),
        )

    # ---- health / discovery -------------------------------------------
    async def check(self, iran: Server, links: list[Link]) -> dict[str, Probe]:
        if not links:
            return {}
        r = await self.pool.run(iran, check_script(links), timeout=10 + 4 * len(links))
        return parse_check(r.out, {x.id: x for x in links})

    async def wait_up(self, link: Link, iran: Server, timeout: int) -> Probe:
        r = await self.pool.run(iran, wait_script(link.probe_port, timeout), timeout=timeout + 40)
        return parse_wait(r.out)

    async def scan(self, s: Server) -> list[Found]:
        r = await self.pool.run(s, SCAN_SCRIPT, timeout=30)
        return parse_scan(r.out)

    async def listening(self, s: Server) -> set[int]:
        r = await self.pool.run(s, LISTEN_SCRIPT, timeout=20)
        return parse_listening(r.out)
