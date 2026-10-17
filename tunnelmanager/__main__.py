"""python -m tunnelmanager [serve | demo | passwd | backup | restore]"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(prog="tunnelmanager")
    ap.add_argument("--data", default=os.environ.get("TM_DATA_DIR", "data"), help="data directory")
    sub = ap.add_subparsers(dest="cmd")
    sv = sub.add_parser("serve", help="run the panel (default)")
    sv.add_argument("--host", default=os.environ.get("TM_HOST", "0.0.0.0"))
    sv.add_argument("--port", type=int, default=int(os.environ.get("TM_PORT", "8080")))
    dm = sub.add_parser("demo", help="run with a simulated network (no real servers)")
    dm.add_argument("--host", default="127.0.0.1")
    dm.add_argument("--port", type=int, default=8080)
    pw = sub.add_parser("passwd", help="set the admin username/password")
    pw.add_argument("--username", default="admin")
    pw.add_argument("--password", help="non-interactive (for install scripts)")
    bk = sub.add_parser("backup", help="write a full backup file")
    bk.add_argument("--out", help="file to write (default: <data>/backups/...)")
    bk.add_argument("--password", help="encrypt with this password (default: the one set in the panel)")
    rs = sub.add_parser("restore", help="restore a backup file (stop the service first)")
    rs.add_argument("file")
    rs.add_argument("--password", default="")
    rs.add_argument("--with-env", action="store_true", help="also restore /etc/default/tunnelmanager (port, HTTPS)")
    rs.add_argument("--keep-mode", action="store_true", help="keep the backup's observe/auto mode instead of starting in observe mode")
    rs.add_argument("--force", action="store_true", help="even if the service is running")
    args = ap.parse_args()

    if args.cmd in ("backup", "restore"):
        return backup_cli(args)

    if args.cmd == "passwd":
        from .auth import Auth

        a = Auth(Path(args.data) / "auth.json")
        if args.password:
            p1 = args.password
            if len(p1) < 6:
                raise SystemExit("password must be at least 6 characters")
        else:
            p1 = getpass.getpass("New password: ")
            if len(p1) < 6 or p1 != getpass.getpass("Repeat: "):
                raise SystemExit("passwords differ or shorter than 6 characters")
        a.set_password(args.username, p1)
        print("password updated")
        return

    import uvicorn

    from .app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    host = getattr(args, "host", os.environ.get("TM_HOST", "0.0.0.0"))
    port = getattr(args, "port", int(os.environ.get("TM_PORT", "8080")))
    import socket

    probe = socket.socket()
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
    except OSError:
        raise SystemExit(
            f"port {port} is already in use on {host} - pick another one with --port, e.g. --port {port + 1010}\n"
            f"پورت {port} اشغال است؛ با --port یک پورت دیگر بدهید، مثلا --port {port + 1010}"
        ) from None
    finally:
        probe.close()

    demo = args.cmd == "demo"
    data = args.data if not demo else os.path.join(args.data, "demo")
    tls = {}
    if os.environ.get("TM_SSL_CERT") and os.environ.get("TM_SSL_KEY"):
        tls = {"ssl_certfile": os.environ["TM_SSL_CERT"], "ssl_keyfile": os.environ["TM_SSL_KEY"]}
    uvicorn.run(create_app(data, demo=demo), host=host, port=port, proxy_headers=True, log_level="warning", **tls)


def backup_cli(args) -> None:
    import json
    import shutil
    import subprocess

    from . import backup as bk
    from .auth import Auth
    from .store import Store

    data = Path(args.data)
    store = Store(data / "state.json")
    auth = Auth(data / "auth.json")
    backups = bk.Backups(data)
    if args.cmd == "backup":
        pw = args.password if args.password is not None else store.settings.backup_password
        blob = bk.pack(bk.make(store.raw(), dict(auth.data), backups.env()), pw)
        if args.out:
            Path(args.out).write_bytes(blob)
            os.chmod(args.out, 0o600)
            out = args.out
        else:
            out = str(backups.write(blob, bool(pw), "cli"))
        print(f"backup written: {out} ({len(blob)} bytes, {'encrypted' if pw else 'NOT encrypted'})")
        return

    if not args.force and shutil.which("systemctl"):
        running = subprocess.run(
            ["systemctl", "is-active", "--quiet", "tunnelmanager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        ).returncode == 0
        if running:
            raise SystemExit(
                "the panel is running; stop it first:  systemctl stop tunnelmanager\n"
                "پنل در حال اجراست؛ اول متوقفش کنید: systemctl stop tunnelmanager"
            )
    try:
        d = bk.unpack(Path(args.file).read_bytes(), args.password or store.settings.backup_password)
    except bk.BackupError as e:
        raise SystemExit(str(e)) from None
    if (data / "state.json").exists():  # keep what is being replaced
        old = bk.pack(bk.make(store.raw(), dict(auth.data), backups.env()), store.settings.backup_password)
        print(f"current state saved to {backups.write(old, bool(store.settings.backup_password), 'pre')}")
    store.apply(d["state"])
    if not args.keep_mode:
        store.settings.observe_only = True
    store.save()
    if d.get("auth", {}).get("hash"):
        (data / "auth.json").write_text(json.dumps(d["auth"]))
        os.chmod(data / "auth.json", 0o600)
    if args.with_env and d.get("env"):
        bk.ENV_FILE.write_text(d["env"])
        print(f"{bk.ENV_FILE} restored")
    print(f"restored: {bk.summary(d)}")
    print("start the panel again:  systemctl start tunnelmanager" + ("" if args.keep_mode else "   (it starts in observe mode)"))


if __name__ == "__main__":
    main()
