"""Everything that touches BackPack on the servers: config rendering, deploy,
install, and the end-to-end health probe.

Each link (Iran x kharej pair) is one BackPack reverse tunnel named
``tm-<link id>``. Its files follow BackPack's own layout so the tunnels also
show up in BackPack's CLI and web panel:

    /etc/backpack/tm-<id>.toml                 config
    /etc/backpack/tm-<id>.metrics.json         written by the engine
    /etc/systemd/system/backpack-tm-<id>.service

Health is checked end to end: the Iran side of every tunnel also exposes a
loopback-only *probe port* mapped to the kharej's sshd (``127.0.0.1:61000 =
127.0.0.1:22``). Reading ``SSH-`` from that port on the Iran server proves
the whole path — listener, tunnel, kharej client, last hop — works.
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
from dataclasses import dataclass
from pathlib import Path

import httpx

from .models import Link, Server
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


class DeployError(Exception):
    pass


@dataclass
class Probe:
    ok: bool
    latency_ms: float | None = None
    active: str = ""
    connected: bool | None = None
    connect_s: float | None = None
    error: str = ""


def q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_port_mapping(p: str) -> str:
    p = p.strip()
    if not p or not _SAFE.match(p):
        raise ValueError(f"invalid port mapping: {p!r}")
    return p


def unit_name(link: Link) -> str:
    return f"backpack-{link.service}.service"


def conf_path(link: Link) -> str:
    return f"{CONF_DIR}/{link.service}.toml"


def render_server(link: Link, transport: str, ports: list[str], kharej: Server) -> str:
    all_ports = [f"127.0.0.1:{link.probe_port}={kharej.probe_addr()}"] + list(ports)
    lines = [
        "# Managed by TunnelManager - changes here are overwritten.",
        f"# link {link.id}: kharej {kharej.name} -> this Iran server",
        "[server]",
        f'bind_addr = "0.0.0.0:{link.tunnel_port}"',
        f"transport = {q(transport)}",
        f"token = {q(link.token)}",
        f"accept_udp = {'true' if kharej.accept_udp else 'false'}",
        'log_level = "info"',
        "ports = [",
        *[f"    {q(p)}," for p in all_ports],
        "]",
    ]
    return "\n".join(lines) + "\n"


def render_client(link: Link, transport: str, iran: Server) -> str:
    host = f"[{iran.ip}]" if ":" in iran.ip else iran.ip
    lines = [
        "# Managed by TunnelManager - changes here are overwritten.",
        f"# link {link.id}: this kharej server -> Iran {iran.name}",
        "[client]",
        f'remote_addr = "{host}:{link.tunnel_port}"',
        f"transport = {q(transport)}",
        f"token = {q(link.token)}",
        "connection_pool = 8",
        'log_level = "info"',
    ]
    return "\n".join(lines) + "\n"


def render_unit(link: Link) -> str:
    return f"""[Unit]
Description=Backpack Tunnel ({link.service}) - managed by TunnelManager
After=network.target

[Service]
Type=simple
ExecStart={BIN_PATH} -c {conf_path(link)}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def _probe_snippet(port: int) -> str:
    # Opens the probe port and reads the first bytes the far end sends.
    return f"timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; head -c 4 <&3' 2>/dev/null"


def check_script(links: list[Link]) -> str:
    """One round trip per Iran server: unit state, engine's own view, and an
    end-to-end probe for every link it hosts."""
    parts = []
    for x in links:
        parts.append(
            f"""n={x.service}; a=$(systemctl is-active backpack-$n.service 2>/dev/null)
c=$(grep -o '"connected": *[a-z]*' {CONF_DIR}/$n.metrics.json 2>/dev/null | grep -o '[a-z]*$')
t0=$(date +%s%N); b=$({_probe_snippet(x.probe_port)}); t1=$(date +%s%N)
echo "@@{x.id}|$a|$c|$( [ -n "$b" ] && echo 1 || echo 0)|$(( (t1-t0)/1000 ))"
"""
        )
    return "".join(parts)


def parse_check(out: str) -> dict[str, Probe]:
    res = {}
    for line in out.splitlines():
        if not line.startswith("@@"):
            continue
        try:
            lid, active, conn, ok, us = line[2:].split("|")
        except ValueError:
            continue
        good = ok == "1"
        res[lid] = Probe(
            ok=good,
            active=active,
            connected=None if conn == "" else conn == "true",
            latency_ms=round(int(us) / 1000, 1) if good and us.isdigit() else None,
        )
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
    async def _install_side(self, s: Server, link: Link, toml: str, open_ports: list[str]) -> None:
        await self.pool.run(s, f"mkdir -p {CONF_DIR} && chmod 700 {CONF_DIR}")
        await self.pool.put(s, toml.encode(), conf_path(link), 0o600)
        await self.pool.put(s, render_unit(link).encode(), f"{UNIT_DIR}/{unit_name(link)}", 0o644)
        u = unit_name(link)
        cmd = (
            _ufw_allow(open_ports)
            + f"rm -f {CONF_DIR}/{link.service}.metrics.json; systemctl daemon-reload && "
            f"systemctl enable {u} >/dev/null 2>&1; systemctl restart {u}"
        )
        r = await self.pool.run(s, cmd, timeout=40)
        if not r.ok:
            raise DeployError(f"{s.name}: {r.err.strip() or r.out.strip() or 'systemctl failed'}")

    async def deploy(self, link: Link, iran: Server, kharej: Server, transport: str, ports: list[str]) -> None:
        open_ports = [str(link.tunnel_port)] + ports
        await asyncio.gather(
            self._install_side(iran, link, render_server(link, transport, ports, kharej), open_ports),
            self._install_side(kharej, link, render_client(link, transport, iran), []),
        )

    async def deploy_iran(self, link: Link, iran: Server, kharej: Server, ports: list[str]) -> None:
        await self._install_side(
            iran, link, render_server(link, link.transport, ports, kharej), [str(link.tunnel_port)] + ports
        )

    async def _stop_side(self, s: Server | None, link: Link, purge: bool) -> None:
        if s is None:
            return
        u = unit_name(link)
        cmd = f"systemctl disable --now {u} >/dev/null 2>&1; true"
        if purge:
            cmd += f"; rm -f {UNIT_DIR}/{u} {conf_path(link)} {CONF_DIR}/{link.service}.metrics.json; systemctl daemon-reload"
        try:
            await self.pool.run(s, cmd, timeout=30)
        except SSHError as e:
            log.info("stop %s on %s: %s", link.service, s.name, e)

    async def stop(self, link: Link, iran: Server | None, kharej: Server | None) -> None:
        await asyncio.gather(self._stop_side(iran, link, False), self._stop_side(kharej, link, False))

    async def remove(self, link: Link, iran: Server | None, kharej: Server | None) -> None:
        await asyncio.gather(self._stop_side(iran, link, True), self._stop_side(kharej, link, True))

    # ---- health --------------------------------------------------------
    async def check(self, iran: Server, links: list[Link]) -> dict[str, Probe]:
        if not links:
            return {}
        r = await self.pool.run(iran, check_script(links), timeout=10 + 4 * len(links))
        return parse_check(r.out)

    async def wait_up(self, link: Link, iran: Server, timeout: int) -> Probe:
        r = await self.pool.run(iran, wait_script(link.probe_port, timeout), timeout=timeout + 40)
        return parse_wait(r.out)
