"""Full backups of the panel: every server, tunnel, domain, DNS account and
setting (state.json), the admin login (auth.json) and the service config
(/etc/default/tunnelmanager).

A backup is gzipped JSON. With a backup password it is encrypted
(AES-256-GCM, key from scrypt), which matters because it holds SSH passwords
and API tokens and travels through Telegram.

    file = b"TMBK1" + salt(16) + nonce(12) + AES-GCM(gzip(json))
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import __version__

log = logging.getLogger(__name__)

MAGIC = b"TMBK1"
FORMAT = "tunnelmanager-backup"
ENV_FILE = Path("/etc/default/tunnelmanager")
NAME_RE = re.compile(r"^tm-backup-[0-9]{8}-[0-9]{4}(?:-[a-z]+)?\.(?:tmbk|json\.gz)$")


class BackupError(Exception):
    pass


def _key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def make(state: dict[str, Any], auth: dict[str, Any] | None, env: str = "") -> dict[str, Any]:
    return {
        "format": FORMAT,
        "version": 1,
        "app": __version__,
        "created": time.time(),
        "state": state,
        "auth": auth or {},
        "env": env,
    }


def pack(data: dict[str, Any], password: str = "") -> bytes:
    raw = gzip.compress(json.dumps(data, ensure_ascii=False).encode(), mtime=0)
    if not password:
        return raw
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, raw, MAGIC)


def is_encrypted(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def unpack(blob: bytes, password: str = "") -> dict[str, Any]:
    if blob.startswith(MAGIC):
        if not password:
            raise BackupError("این بکاپ رمز دارد؛ رمز بکاپ را وارد کنید")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        try:
            blob = AESGCM(_key(password, salt)).decrypt(nonce, ct, MAGIC)
        except InvalidTag:
            raise BackupError("رمز بکاپ اشتباه است (یا فایل خراب شده)") from None
    try:
        if blob[:2] == b"\x1f\x8b":
            blob = gzip.decompress(blob)
        data = json.loads(blob)
    except (OSError, ValueError):
        raise BackupError("این فایل بکاپ TunnelManager نیست") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("state"), dict):
        raise BackupError("این فایل بکاپ TunnelManager نیست")
    return data


def summary(data: dict[str, Any]) -> str:
    st = data["state"]
    roles = [s.get("role") for s in st.get("servers", [])]
    return (
        f"{roles.count('kharej')} خارج، {roles.count('iran')} داخل، {len(st.get('links', []))} تانل، "
        f"{len(st.get('domains', []))} دامنه، {len(st.get('providers', []))} حساب DNS"
    )


def tz(name: str) -> dt.tzinfo:
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name or "UTC")
    except (ImportError, ValueError, KeyError):  # no tz database: Iran has kept +03:30 all year since 2022
        return dt.timezone(dt.timedelta(hours=3, minutes=30)) if name == "Asia/Tehran" else dt.timezone.utc


def due(now: float, at: str, zone: str, last: float) -> bool:
    """True once a day, at the first check after `at` (HH:MM) in `zone`."""
    z = tz(zone)
    local = dt.datetime.fromtimestamp(now, z)
    try:
        hh, mm = (int(x) for x in at.split(":", 1))
    except ValueError:
        hh, mm = 3, 0
    target = local.replace(hour=hh % 24, minute=mm % 60, second=0, microsecond=0)
    if local < target:
        return False
    return not last or dt.datetime.fromtimestamp(last, z) < target


class Backups:
    """Local copies in <data>/backups, plus the nightly run."""

    def __init__(self, data_dir: Path, env_file: Path = ENV_FILE):
        self.dir = Path(data_dir) / "backups"
        self.env_file = env_file

    def env(self) -> str:
        try:
            return self.env_file.read_text()[:20000]
        except OSError:
            return ""

    def write(self, blob: bytes, encrypted: bool, tag: str = "") -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        stamp = time.strftime("%Y%m%d-%H%M")
        name = f"tm-backup-{stamp}{'-' + tag if tag else ''}.{'tmbk' if encrypted else 'json.gz'}"
        path = self.dir / name
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return path

    def prune(self, keep: int) -> None:
        files = sorted(self.list(), key=lambda f: f["mtime"], reverse=True)
        for f in files[max(1, keep):]:
            try:
                (self.dir / f["name"]).unlink()
            except OSError:
                pass

    def list(self) -> list[dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in self.dir.iterdir():
            if NAME_RE.match(p.name):
                st = p.stat()
                out.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "encrypted": p.name.endswith(".tmbk")})
        return sorted(out, key=lambda f: f["mtime"], reverse=True)

    def read(self, name: str) -> bytes:
        if not NAME_RE.match(name):
            raise BackupError("نام فایل نامعتبر است")
        try:
            return (self.dir / name).read_bytes()
        except OSError:
            raise BackupError("این بکاپ پیدا نشد") from None
