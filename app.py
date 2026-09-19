#!/usr/bin/env python3
"""
Unamused — public website audit tool.
Dev:   pip install -r requirements.txt && python3 app.py
Prod:  gunicorn -w 2 -b 127.0.0.1:8000 app:app   (behind nginx, see README.md)
"""
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

from flask import Flask, request, render_template, redirect, url_for, abort, send_file

import audit as engine
import fixkit as fixkit_gen

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)

REPORTS = {}        # rid -> report dict (also persisted to data/)
RATE = {}           # ip -> [timestamps]
RATE_MAX = 10       # audits per IP per hour
RATE_WINDOW = 3600
AUDIT_TIMEOUT = 55  # seconds, bounds the whole audit


def is_public_host(host):
    """True only if the hostname resolves exclusively to public IPs (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except Exception:
        return False
    if not infos:
        return False
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except Exception:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
    return True


def clean_url(raw):
    """Normalize user input to a safe, public http(s) URL. Returns None if unsafe."""
    raw = (raw or "").strip()[:500]
    if not raw:
        return None
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    try:
        u = urllib.parse.urlparse(raw)
    except Exception:
        return None
    if u.scheme not in ("http", "https") or not u.netloc:
        return None
    if "@" in u.netloc:          # userinfo smuggling
        return None
    host = u.hostname or ""
    if not host or "." not in host and ":" not in host:
        return None
    if not is_public_host(host):
        return None
    path = u.path or "/"
    if len(path) > 300:
        return None
    return "%s://%s%s" % (u.scheme, u.netloc, path)


def run_audit(url):
    box = {}

    def target():
        try:
            box["rep"] = engine.audit(url)
        except Exception as e:  # noqa: BLE001 - never 500 on engine failure
            box["rep"] = {"url": url, "error": str(e)[:200], "score": 0,
                          "grade": "Unreachable", "checks": [],
                          "recommendations": [],
                          "audited_at": datetime.now(timezone.utc).isoformat()}

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(AUDIT_TIMEOUT)
    return box.get("rep")


def client_ip():
    return request.headers.get("X-Forwarded-For",
                               request.remote_addr or "").split(",")[0].strip()


@app.route("/")
def index():
    return render_template("index.html",
                           github_url=os.environ.get("GITHUB_URL", ""))


@app.route("/audit", methods=["POST"])
def audit_route():
    ip = client_ip()
    now = time.time()
    hits = [t for t in RATE.get(ip, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_MAX:
        return render_template(
            "error.html",
            message="Rate limit reached (10 audits/hour). Try again in a bit."), 429

    url = clean_url(request.form.get("url", ""))
    if not url:
        return render_template(
            "error.html",
            message="That doesn't look like a valid public website address."), 400
    hits.append(now)
    RATE[ip] = hits

    rep = run_audit(url)
    if rep is None:
        return render_template(
            "error.html",
            message="The audit timed out or the site didn't respond. Try again."), 502

    # SSRF: the site may have redirected somewhere non-public; verify landing host.
    try:
        fh = urllib.parse.urlparse(rep.get("final_url") or url).hostname or ""
        if fh and not is_public_host(fh):
            return render_template(
                "error.html", message="That address isn't a public website."), 400
    except Exception:
        return render_template(
            "error.html", message="That address isn't a public website."), 400

    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = rep
    with open(os.path.join(DATA_DIR, "report-%s.json" % rid), "w") as f:
        json.dump(rep, f)
    return redirect(url_for("report", rid=rid))


@app.route("/r/<rid>")
def report(rid):
    rid = re.sub(r"[^a-z0-9]", "", rid.lower())[:16]
    rep = REPORTS.get(rid)
    if not rep:
        path = os.path.join(DATA_DIR, "report-%s.json" % rid)
        if os.path.isfile(path):
            with open(path) as f:
                rep = json.load(f)
            REPORTS[rid] = rep
    if not rep:
        abort(404)
    return render_template("report.html", r=rep, rid=rid)


@app.route("/kit/<rid>")
def kit(rid):
    """Free Fix Kit download, generated from the stored audit report."""
    rid = re.sub(r"[^a-z0-9]", "", rid.lower())[:16]
    rep = REPORTS.get(rid)
    if not rep:
        path = os.path.join(DATA_DIR, "report-%s.json" % rid)
        if os.path.isfile(path):
            with open(path) as f:
                rep = json.load(f)
            REPORTS[rid] = rep
    if not rep or rep.get("error"):
        abort(404)
    ip = client_ip()
    now = time.time()
    hits = [t for t in RATE.get("kit:" + ip, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_MAX:
        return render_template(
            "error.html",
            message="Rate limit reached (10 kits/hour). Try again in a bit."), 429
    hits.append(now)
    RATE["kit:" + ip] = hits
    import tempfile
    tmp = tempfile.mkdtemp(prefix="fixkit-")
    try:
        zpath = fixkit_gen.generate(rep["url"], tmp)
    except Exception:
        return render_template(
            "error.html",
            message="Kit generation failed — the site may have blocked us. Try again."), 502
    return send_file(zpath, as_attachment=True,
                     download_name=os.path.basename(zpath))


@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, threaded=True)
