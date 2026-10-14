"""SSH access to the managed servers (cached connections, one per server)."""

from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass

import asyncssh

from .models import Server


class SSHError(Exception):
    pass


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def _text(b) -> str:
    if b is None:
        return ""
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)


class SSHPool:
    def __init__(self, connect_timeout: float = 10):
        self.connect_timeout = connect_timeout
        self._conns: dict[str, asyncssh.SSHClientConnection] = {}
        self._keys: dict[str, tuple] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _fingerprint(self, s: Server) -> tuple:
        return (s.ip, s.ssh_port, s.ssh_user, s.ssh_password, s.ssh_key)

    async def _conn(self, s: Server) -> asyncssh.SSHClientConnection:
        lock = self._locks.setdefault(s.id, asyncio.Lock())
        async with lock:
            c = self._conns.get(s.id)
            if c is not None and self._keys.get(s.id) == self._fingerprint(s) and not c.is_closed():
                return c
            if c is not None:
                c.close()
            kw: dict = dict(
                host=s.ip,
                port=s.ssh_port,
                username=s.ssh_user,
                known_hosts=None,  # servers are added by IP from the panel; we trust them on first use
                connect_timeout=self.connect_timeout,
                keepalive_interval=15,
                keepalive_count_max=2,
            )
            if s.ssh_key:
                kw["client_keys"] = [asyncssh.import_private_key(s.ssh_key)]
            else:
                kw["client_keys"] = None
            if s.ssh_password:
                kw["password"] = s.ssh_password
            try:
                c = await asyncssh.connect(**kw)
            except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
                raise SSHError(f"SSH {s.ip}:{s.ssh_port}: {e or type(e).__name__}") from e
            self._conns[s.id] = c
            self._keys[s.id] = self._fingerprint(s)
            return c

    def drop(self, server_id: str) -> None:
        c = self._conns.pop(server_id, None)
        if c is not None:
            c.close()

    async def run(self, s: Server, cmd: str, timeout: float = 60, input: bytes | None = None) -> Result:
        for attempt in (0, 1):
            c = await self._conn(s)
            try:
                r = await asyncio.wait_for(c.run(cmd, input=input, check=False, encoding=None), timeout)
                return Result(
                    r.exit_status if r.exit_status is not None else -1,
                    _text(r.stdout),
                    _text(r.stderr),
                )
            except asyncio.TimeoutError as e:
                raise SSHError(f"{s.name}: command timed out after {timeout}s") from e
            except (asyncssh.Error, OSError) as e:
                # a cached connection that died under us: reconnect once
                self.drop(s.id)
                if attempt:
                    raise SSHError(f"{s.name}: {e}") from e
        raise SSHError("unreachable")

    async def ping(self, s: Server) -> float:
        t = time.monotonic()
        r = await self.run(s, "true", timeout=15)
        if not r.ok:
            raise SSHError(r.err)
        return (time.monotonic() - t) * 1000

    async def put(self, s: Server, data: bytes, path: str, mode: int = 0o600) -> None:
        c = await self._conn(s)
        try:
            async with c.start_sftp_client() as sftp:
                tmp = path + ".tm-tmp"
                async with sftp.open(tmp, "wb") as f:
                    await f.write(data)
                await sftp.chmod(tmp, mode)
                await sftp.posix_rename(tmp, path)
        except (asyncssh.Error, OSError) as e:
            # some minimal images have no sftp subsystem: fall back to cat
            r = await self.run(
                s,
                f"umask 077; cat > {shlex.quote(path)}.tm-tmp && chmod {mode:o} {shlex.quote(path)}.tm-tmp "
                f"&& mv -f {shlex.quote(path)}.tm-tmp {shlex.quote(path)}",
                input=data,
            )
            if not r.ok:
                raise SSHError(f"{s.name}: upload {path} failed: {e}; {r.err}") from e

    async def close(self) -> None:
        for c in self._conns.values():
            c.close()
        self._conns.clear()
