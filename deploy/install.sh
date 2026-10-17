#!/usr/bin/env bash
# Installs TunnelManager as a systemd service.
#   bash deploy/install.sh            (from a checkout)
# Run it on a server OUTSIDE Iran: the panel needs to reach the Telegram API,
# Cloudflare/Arvan APIs, GitHub (to fetch BackPack) and every server over SSH.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/tunnelmanager
DATA=/var/lib/tunnelmanager
PORT="${TM_PORT:-8080}"
if [ -f /etc/default/tunnelmanager ]; then
  PORT="$(sed -n 's/^TM_PORT=//p' /etc/default/tunnelmanager | tail -n1)"; PORT="${PORT:-8080}"
fi

# Never take a port from something already running here (a live tunnel
# server may have xray, nginx or BackPack's own panel on it). Checked before
# anything is installed or changed.
port_owner() {
  if command -v ss >/dev/null; then ss -ltnpH "( sport = :$1 )" 2>/dev/null | head -n1; return; fi
  awk -v p="$(printf '%04X' "$1")" '$4=="0A" {split($2,a,":"); if (a[2]==p) {print "in use"; exit}}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
OWNER="$(port_owner "$PORT")"
if [ -n "$OWNER" ] && ! echo "$OWNER" | grep -q tunnelmanager && ! systemctl is-active --quiet tunnelmanager; then
  echo "Port $PORT is already in use on this server:"
  echo "  $OWNER"
  echo "Nothing was changed. Pick a free port, e.g.:  TM_PORT=9090 bash deploy/install.sh"
  echo "پورت $PORT روی این سرور اشغال است؛ هیچ تغییری داده نشد. با یک پورت آزاد اجرا کنید."
  exit 1
fi

if ! command -v python3 >/dev/null; then
  apt-get update && apt-get install -y python3 python3-venv
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "Python 3.10+ is required"; exit 1; }

mkdir -p "$DEST" "$DATA"
chmod 700 "$DATA"
if [ "$SRC" != "$DEST" ]; then
  cp -r "$SRC/tunnelmanager" "$SRC/requirements.txt" "$DEST/"
fi
# Ubuntu ships the venv module without ensurepip until python3-venv (or
# python3.X-venv) is installed, so "venv --help" passing proves nothing
if ! python3 -m venv "$DEST/venv" >/dev/null 2>&1; then
  PYV="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  apt-get update && { apt-get install -y "python$PYV-venv" || apt-get install -y python3-venv; }
  rm -rf "$DEST/venv"
  python3 -m venv "$DEST/venv"
fi
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

if [ ! -f /etc/default/tunnelmanager ]; then
  cat > /etc/default/tunnelmanager <<CONF
TM_HOST=0.0.0.0
TM_PORT=$PORT
# HTTPS directly from the panel (or put it behind nginx/caddy):
#TM_SSL_CERT=/etc/letsencrypt/live/panel.example.com/fullchain.pem
#TM_SSL_KEY=/etc/letsencrypt/live/panel.example.com/privkey.pem
CONF
fi

if [ ! -f "$DATA/auth.json" ] || ! grep -q '"hash"' "$DATA/auth.json"; then
  PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
  (cd "$DEST" && "$DEST/venv/bin/python" -m tunnelmanager --data "$DATA" passwd --username admin --password "$PASS")
  CREATED=1
fi

cp "$SRC/deploy/tunnelmanager.service" /etc/systemd/system/tunnelmanager.service
systemctl daemon-reload
systemctl enable --now tunnelmanager
systemctl restart tunnelmanager

sleep 3
if ! systemctl is-active --quiet tunnelmanager; then
  echo "The panel did not start. Last log lines:"
  journalctl -u tunnelmanager -n 20 --no-pager
  exit 1
fi

IP="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
echo
echo "TunnelManager is running:  http://$IP:$PORT"
if [ "${CREATED:-0}" = 1 ]; then
  echo "  username: admin"
  echo "  password: $PASS"
  echo "  (change it any time: $DEST/venv/bin/python -m tunnelmanager --data $DATA passwd)"
fi
