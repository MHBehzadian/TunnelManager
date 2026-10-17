#!/usr/bin/env bash
# Serve the panel on https://<domain> (port 443) with a free Let's Encrypt
# certificate that renews itself.
#   bash deploy/https.sh panel.example.com [email]
#
# Before running: an A record for the domain pointing at THIS server, with
# CDN proxy off (Arvan "cloud" / Cloudflare orange cloud), and ports 80 and
# 443 open in the provider's firewall. Port 80 is only used for a few seconds
# while the certificate is issued or renewed.
#
# Nothing else on the server is touched: if 443 or 80 is already used by
# another program (xray, nginx, a tunnel...), the script stops before changing
# anything.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
DOMAIN="$(echo "${1:-}" | tr 'A-Z' 'a-z')"
EMAIL="${2:-}"
[ -n "$DOMAIN" ] || { echo "usage: bash deploy/https.sh panel.example.com [email]"; exit 1; }
ENV=/etc/default/tunnelmanager
[ -f "$ENV" ] || { echo "install the panel first: bash deploy/install.sh"; exit 1; }

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\n!! %s\n' "$*"; exit 1; }

port_owner() {
  if command -v ss >/dev/null; then ss -ltnpH "( sport = :$1 )" 2>/dev/null | head -n1; return; fi
  awk -v p="$(printf '%04X' "$1")" '$4=="0A" {split($2,a,":"); if (a[2]==p) {print "in use"; exit}}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
OURPID="$(systemctl show -p MainPID --value tunnelmanager 2>/dev/null || echo 0)"
ours() { [ "${OURPID:-0}" != 0 ] && echo "$1" | grep -q "pid=$OURPID,"; }

say "checking ports"
O443="$(port_owner 443)"
if [ -n "$O443" ] && ! ours "$O443"; then
  fail "port 443 is used by another program on this server:
   $O443
 Nothing was changed. پورت 443 دست برنامه دیگری است؛ هیچ تغییری داده نشد."
fi
O80="$(port_owner 80)"
if [ -n "$O80" ]; then
  fail "port 80 is used by another program (needed for a few seconds to get the certificate):
   $O80
 Nothing was changed. پورت 80 دست برنامه دیگری است؛ هیچ تغییری داده نشد."
fi

say "checking DNS for $DOMAIN"
MYIP="$(curl -fsS4 --max-time 6 https://api.ipify.org 2>/dev/null || true)"
RES="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')"
[ -n "$RES" ] || fail "$DOMAIN does not resolve yet. Add an A record -> ${MYIP:-the IP of this server} and try again in a minute.
 رکورد A دامنه هنوز ساخته نشده یا هنوز پخش نشده."
if [ -n "$MYIP" ] && [ "$RES" != "$MYIP" ] && ! hostname -I | tr ' ' '\n' | grep -qx "$RES"; then
  fail "$DOMAIN points to $RES, but this server is $MYIP.
 If the record is on Arvan/Cloudflare with the CDN proxy (cloud) on, turn it off for this record.
 رکورد دامنه به این سرور اشاره نمی‌کند؛ اگر ابر/پروکسی آروان یا کلادفلر روشن است خاموشش کنید."
fi
echo "   $DOMAIN -> $RES  ok"

say "installing certbot"
command -v certbot >/dev/null || { apt-get update -q && apt-get install -y -q certbot; }

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
fi

say "getting a certificate"
if [ -n "$EMAIL" ]; then ACCOUNT=(-m "$EMAIL"); else ACCOUNT=(--register-unsafely-without-email); fi
certbot certonly --standalone --preferred-challenges http -d "$DOMAIN" \
  --non-interactive --agree-tos --keep-until-expiring "${ACCOUNT[@]}"
CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
[ -s "$CERT" ] && [ -s "$KEY" ] || fail "certbot did not produce $CERT"

# renewals happen by themselves (certbot.timer); restart the panel to load them
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/tunnelmanager.sh <<'HOOK'
#!/bin/sh
systemctl restart tunnelmanager
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/tunnelmanager.sh

say "switching the panel to https://$DOMAIN"
cp "$ENV" "$ENV.bak"
set_env() {
  if grep -qE "^#?$1=" "$ENV"; then sed -i -E "s|^#?$1=.*|$1=$2|" "$ENV"; else echo "$1=$2" >> "$ENV"; fi
}
set_env TM_HOST 0.0.0.0
set_env TM_PORT 443
set_env TM_SSL_CERT "$CERT"
set_env TM_SSL_KEY "$KEY"
systemctl restart tunnelmanager
sleep 4
if ! systemctl is-active --quiet tunnelmanager || ! curl -fsS --max-time 8 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/session" >/dev/null; then
  echo "the panel did not come up on 443; putting the previous settings back"
  journalctl -u tunnelmanager -n 15 --no-pager || true
  mv "$ENV.bak" "$ENV"
  systemctl restart tunnelmanager
  exit 1
fi

echo
echo "TunnelManager:  https://$DOMAIN"
echo "(the certificate renews itself; the old http port is no longer used)"
