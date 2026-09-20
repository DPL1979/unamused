#!/usr/bin/env bash
# Unamused one-shot deploy. Run as root on a fresh Ubuntu 24.04 server:
#   curl -fsSL https://raw.githubusercontent.com/DPL1979/unamused/master/deploy.sh -o /root/deploy.sh && bash /root/deploy.sh
# Installs everything, starts the app on :80, then waits for DNS and finishes
# HTTPS automatically. Safe to re-run.
set -euo pipefail

DOMAIN="unamused.app"
SITE_URL="https://unamused.app"
GITHUB_URL="https://github.com/DPL1979/unamused"
APP_DIR="/home/unamused/app"

if [ "$(id -u)" -ne 0 ]; then echo "run this as root"; exit 1; fi

echo "=== packages ==="
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3-venv python3-pip nginx certbot python3-certbot-nginx git dnsutils curl

echo "=== app user ==="
id unamused >/dev/null 2>&1 || adduser --disabled-password --gecos "" unamused

echo "=== app code ==="
if [ -d "$APP_DIR/.git" ]; then
  su - unamused -c "cd $APP_DIR && git pull --ff-only -q"
else
  rm -rf "$APP_DIR"
  su - unamused -c "git clone -q $GITHUB_URL $APP_DIR"
fi

echo "=== python env ==="
su - unamused -c "cd $APP_DIR && python3 -m venv .venv"
su - unamused -c "cd $APP_DIR && .venv/bin/pip install -q -r requirements.txt"

echo "=== systemd ==="
cat > /etc/systemd/system/unamused.service <<EOF
[Unit]
Description=Unamused audit site
After=network.target

[Service]
User=unamused
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/.venv/bin
Environment=GITHUB_URL=$GITHUB_URL
Environment=SITE_URL=$SITE_URL
# Single worker with threads: the in-memory rate limiter is per-process.
ExecStart=$APP_DIR/.venv/bin/gunicorn -w 1 --threads 4 -b 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now unamused

echo "=== nginx ==="
cat > /etc/nginx/sites-enabled/unamused <<EOF
server {
  listen 80; server_name $DOMAIN www.$DOMAIN;
  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    client_max_body_size 1m;
  }
  location /static/ { alias $APP_DIR/static/; }
}
EOF
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "=== firewall ==="
ufw allow 22,80,443/tcp >/dev/null 2>&1 || true
yes | ufw enable >/dev/null 2>&1 || true

echo "=== smoke test ==="
sleep 3
curl -fsS -o /dev/null http://127.0.0.1:8000/ && echo "app is up on :8000"

echo ""
echo "=== waiting for DNS ==="
echo "Add these A records at your registrar, both -> this server's IPv4:"
echo "  $DOMAIN            A   <server IPv4>"
echo "  www.$DOMAIN        A   <server IPv4>"
echo "This script will detect DNS and finish HTTPS by itself (up to 60 min)."
for _ in $(seq 1 120); do
  if getent hosts "$DOMAIN" >/dev/null 2>&1; then break; fi
  sleep 30
done
if ! getent hosts "$DOMAIN" >/dev/null 2>&1; then
  echo "DNS never appeared. When it does, run:"
  echo "  certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --register-unsafely-without-email --redirect"
  exit 0
fi
echo "DNS is live — issuing certificate..."
certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
  --non-interactive --agree-tos --register-unsafely-without-email --redirect -q
echo "=== DONE: $SITE_URL ==="
curl -fsS -o /dev/null "$SITE_URL/" && echo "live on HTTPS"
