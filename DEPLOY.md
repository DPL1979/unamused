# Deploying Unamused

## VPS (Ubuntu, e.g. Hetzner/DigitalOcean ~$5/mo)

```bash
# on the server, as root
apt update && apt install -y python3-venv nginx certbot python3-certbot-nginx
adduser --disabled-password --gecos "" unamused
su - unamused
git clone <your-repo-url> app && cd app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Systemd unit `/etc/systemd/system/unamused.service`:
```ini
[Unit]
Description=Unamused audit site
After=network.target

[Service]
User=unamused
WorkingDirectory=/home/unamused/app
Environment=PATH=/home/unamused/app/.venv/bin
Environment=GITHUB_URL=https://github.com/<you>/unamused
Environment=SITE_URL=https://unamused.app
# Single worker with threads (not -w 2): the in-memory rate limiter is
# per-process, so multiple workers would multiply the 10/hour limit.
ExecStart=/home/unamused/app/.venv/bin/gunicorn -w 1 --threads 4 -b 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now unamused
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

nginx site (`/etc/nginx/sites-enabled/unamused`):
```nginx
server {
  listen 80; server_name yourdomain.com www.yourdomain.com;
  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 1m;
  }
  location /static/ { alias /home/unamused/app/static/; }
}
```
The app reads `X-Forwarded-For` for rate limiting — keep that header.

## Environment variables

| Var | Purpose |
|---|---|
| `GITHUB_URL` | repo link shown on the site (hide if unset) |
| `SITE_URL` | canonical public URL; fix-kit credit lines link back to it |

## Ops notes

- Audits run synchronously (~5–15s each); gunicorn `-w 1 --threads 4` handles a
  few concurrent users. If traffic grows, move audits to a worker queue.
- Audit reports persist as JSON in `data/` (see `DATA_DIR` in app.py). Back it up.
- Report JSON is persisted under `data/` so shared links survive restarts.
- Rate limit: 10 audits/IP/hour (in-memory; use Redis if multi-worker matters).
- SSRF guard: only public http(s) hosts are fetched; private/loopback/link-local
  IPs are refused, and the post-redirect landing host is re-checked.
