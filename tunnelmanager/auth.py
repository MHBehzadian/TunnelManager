"""Single admin account, PBKDF2 password hash, HMAC-signed session cookie."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

COOKIE = "tm_session"
SESSION_TTL = 7 * 24 * 3600


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


class Auth:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        self._mtime = 0.0
        self._reload()
        if not self.data.get("secret"):
            self.data["secret"] = secrets.token_hex(32)
            self._save()

    def _reload(self) -> None:
        """Pick up a password changed from the command line (`passwd`) while
        the panel is running."""
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime != self._mtime:
            self.data = json.loads(self.path.read_text())
            self._mtime = mtime

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime

    @property
    def configured(self) -> bool:
        self._reload()
        return bool(self.data.get("hash"))

    @property
    def username(self) -> str:
        return self.data.get("username", "admin")

    def set_password(self, username: str, password: str) -> None:
        salt = secrets.token_bytes(16)
        self.data.update(username=username, salt=salt.hex(), hash=_hash(password, salt))
        # rotating the secret logs out every existing session
        self.data["secret"] = secrets.token_hex(32)
        self._save()

    def check(self, username: str, password: str) -> bool:
        self._reload()
        if not self.configured:
            return False
        ok_user = hmac.compare_digest(username, self.username)
        ok_pass = hmac.compare_digest(_hash(password, bytes.fromhex(self.data["salt"])), self.data["hash"])
        return ok_user and ok_pass

    def _sig(self, payload: str) -> str:
        return hmac.new(self.data["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()

    def issue(self) -> str:
        payload = base64.urlsafe_b64encode(json.dumps({"u": self.username, "e": int(time.time()) + SESSION_TTL}).encode()).decode()
        return f"{payload}.{self._sig(payload)}"

    def verify(self, token: str | None) -> bool:
        self._reload()
        if not token or "." not in token:
            return False
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sig(payload)):
            return False
        try:
            data = json.loads(base64.urlsafe_b64decode(payload))
        except ValueError:
            return False
        return data.get("e", 0) > time.time() and data.get("u") == self.username
