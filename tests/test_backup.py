from __future__ import annotations

import base64
import datetime as dt
import os

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeNet
from tunnelmanager import backup as bk
from tunnelmanager.app import create_app

STATE = {"servers": [{"id": "s1", "name": "K", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "pw"}], "settings": {}}


def test_pack_roundtrip_and_password():
    data = bk.make(STATE, {"username": "admin", "hash": "h"}, "TM_PORT=443\n")
    plain = bk.pack(data)
    assert not bk.is_encrypted(plain) and bk.unpack(plain)["state"] == STATE
    sealed = bk.pack(data, "s3cret")
    assert bk.is_encrypted(sealed) and b"10.0.0.1" not in sealed
    assert bk.unpack(sealed, "s3cret")["env"] == "TM_PORT=443\n"
    with pytest.raises(bk.BackupError, match="رمز"):
        bk.unpack(sealed, "nope")
    with pytest.raises(bk.BackupError, match="رمز"):
        bk.unpack(sealed)
    with pytest.raises(bk.BackupError):
        bk.unpack(b"PK\x03\x04 not a backup")


def test_nightly_schedule_in_tehran_time():
    teh = bk.tz("Asia/Tehran")
    at = lambda h, m, day=17: dt.datetime(2026, 10, day, h, m, tzinfo=teh).timestamp()
    assert not bk.due(at(2, 59), "03:00", "Asia/Tehran", 0)
    assert bk.due(at(3, 0), "03:00", "Asia/Tehran", 0)
    assert not bk.due(at(3, 1), "03:00", "Asia/Tehran", at(3, 0))  # once a night
    assert not bk.due(at(23, 0), "03:00", "Asia/Tehran", at(3, 0))
    assert bk.due(at(3, 0, 18), "03:00", "Asia/Tehran", at(3, 0))  # the next night
    assert bk.due(at(9, 0), "03:00", "Asia/Tehran", at(3, 0, 16))  # panel was down at 3: catch up


def test_keeps_only_n_copies(tmp_path):
    b = bk.Backups(tmp_path)
    for i in range(5):
        p = b.write(b"x", False, f"t{'abcde'[i]}")
        os.utime(p, (1000 + i, 1000 + i))
    b.prune(2)
    assert [f["name"].split("-")[-1] for f in b.list()] == ["te.json.gz", "td.json.gz"]
    with pytest.raises(bk.BackupError):
        b.read("../state.json")


def test_backup_and_restore_through_the_api(tmp_path):
    os.environ["TM_NO_MONITOR"] = "1"
    with TestClient(create_app(tmp_path, driver=FakeNet())) as c:
        c.post("/api/setup", json={"username": "admin", "password": "secret1"})
        c.post("/api/servers", json={"name": "K", "role": "kharej", "ip": "10.0.0.1", "ssh_password": "pw"})
        c.put("/api/settings", json={"backup_password": "bkpass", "observe_only": False})
        s = c.get("/api/settings").json()
        assert s["backup_password"] == "••••" and s["backup_time"] == "03:00" and s["backup_tz"] == "Asia/Tehran"
        assert c.put("/api/settings", json={"backup_time": "25:00"}).status_code == 400
        c.put("/api/settings", json={"backup_password": "••••"})  # the mask keeps it
        assert c.app.state.store.settings.backup_password == "bkpass"

        r = c.post("/api/backups/run").json()  # no Telegram configured: kept here, error reported
        assert r["encrypted"] and r["sent"] == 0 and r["error"]
        blob = c.get("/api/backups/download").content
        assert bk.is_encrypted(blob)

        # things change after the backup...
        store = c.app.state.store
        sid = next(iter(store.servers))
        c.delete(f"/api/servers/{sid}")
        assert not store.servers
        assert c.post("/api/backups/restore", json={"data": base64.b64encode(blob).decode(), "password": "wrong"}).status_code == 400
        # ...and come back; the panel restarts in observe mode
        r = c.post("/api/backups/restore", json={"data": base64.b64encode(blob).decode()}).json()  # current password
        assert r["ok"] and "1 خارج" in r["summary"] and not r["relogin"]
        assert sid in store.servers and store.servers[sid].ssh_password == "pw"
        assert store.settings.observe_only is True
        names = [f["name"] for f in c.get("/api/backups").json()["files"]]
        assert any(n.endswith("-pre.tmbk") for n in names)  # what was replaced is kept
        # restoring a local copy by name
        manual = next(n for n in names if "-manual." in n)
        assert c.post("/api/backups/restore", json={"name": manual, "password": "bkpass"}).json()["ok"]


async def test_backup_file_goes_to_every_chat():
    import httpx

    from tunnelmanager.models import Telegram
    from tunnelmanager.telegram import TelegramBot

    seen = []

    def handler(req: httpx.Request):
        body = req.read()
        seen.append((req.url.path, body))
        return httpx.Response(200, json={"ok": True, "result": {}})

    cfg = Telegram(bot_token="1:x", chat_ids=["11", "22"], api_base="https://tg.example")
    bot = TelegramBot(lambda: cfg)
    bot._client, bot._cfg_key = httpx.AsyncClient(transport=httpx.MockTransport(handler)), (cfg.api_base, cfg.proxy)
    assert await bot.send_file("tm-backup.tmbk", b"BLOB", "caption") == 2
    assert all(p == "/bot1:x/sendDocument" and b"BLOB" in b and b'name="document"' in b for p, b in seen)
    assert b"11" in seen[0][1] and b"22" in seen[1][1]
