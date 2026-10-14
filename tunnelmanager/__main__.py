"""python -m tunnelmanager [serve | passwd]"""

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
    args = ap.parse_args()

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
    demo = args.cmd == "demo"
    data = args.data if not demo else os.path.join(args.data, "demo")
    tls = {}
    if os.environ.get("TM_SSL_CERT") and os.environ.get("TM_SSL_KEY"):
        tls = {"ssl_certfile": os.environ["TM_SSL_CERT"], "ssl_keyfile": os.environ["TM_SSL_KEY"]}
    uvicorn.run(create_app(data, demo=demo), host=host, port=port, proxy_headers=True, log_level="warning", **tls)


if __name__ == "__main__":
    main()
