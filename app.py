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

from flask import Flask, request, render_template, redirect, url_for, abort, send_file, Response

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


def hit_rate(key):
    """Record one hit against a rate-limit bucket. False when over the limit."""
    now = time.time()
    hits = [t for t in RATE.get(key, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_MAX:
        return False
    hits.append(now)
    RATE[key] = hits
    return True


def load_report(rid):
    """Fetch a stored audit report by id. Returns (rid, report or None)."""
    rid = re.sub(r"[^a-z0-9]", "", (rid or "").lower())[:16]
    rep = REPORTS.get(rid)
    if not rep:
        path = os.path.join(DATA_DIR, "report-%s.json" % rid)
        if os.path.isfile(path):
            with open(path) as f:
                rep = json.load(f)
            REPORTS[rid] = rep
    return rid, rep


def md(text):
    """Tiny safe markdown subset for kit guides/README: #/##/### headings,
    - lists, **bold**, `code`, paragraphs. HTML-escaped first."""
    import html as _html

    def inline(s):
        s = _html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
        return s

    out, in_list = [], False
    for line in (text or "").split("\n"):
        s = line.strip()
        if s.startswith("#### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<h5>%s</h5>" % inline(s[5:]))
        elif s.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<h4>%s</h4>" % inline(s[4:]))
        elif s.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<h3>%s</h3>" % inline(s[3:]))
        elif s.startswith("# "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<h2>%s</h2>" % inline(s[2:]))
        elif s.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>%s</li>" % inline(s[2:]))
        elif not s:
            if in_list:
                out.append("</ul>")
                in_list = False
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<p>%s</p>" % inline(s))
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


app.jinja_env.filters["md"] = md


def api_base():
    return request.host_url.rstrip("/")


@app.route("/")
def index():
    return render_template("index.html",
                           github_url=os.environ.get("GITHUB_URL", ""))


@app.route("/audit", methods=["POST"])
def audit_route():
    ip = client_ip()
    if not hit_rate(ip):
        return render_template(
            "error.html",
            message="Rate limit reached (10 audits/hour). Try again in a bit."), 429

    url = clean_url(request.form.get("url", ""))
    if not url:
        return render_template(
            "error.html",
            message="That doesn't look like a valid public website address."), 400

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
    rid, rep = load_report(rid)
    if not rep:
        abort(404)
    return render_template("report.html", r=rep, rid=rid)


def _kit_files_or_error(rid, key_prefix):
    """Shared loader for the zip, web page, and API kit endpoints."""
    rid, rep = load_report(rid)
    if not rep or rep.get("error"):
        return None, None, (render_template(
            "error.html", message="No audit found for that link."), 404)
    if not hit_rate(key_prefix + client_ip()):
        return None, None, (render_template(
            "error.html",
            message="Rate limit reached (10 kits/hour). Try again in a bit."), 429)
    try:
        files, _rep = fixkit_gen.build_kit(rep["url"])
    except Exception:
        return None, None, (render_template(
            "error.html",
            message="Kit generation failed — the site may have blocked us. Try again."), 502)
    return rid, files, None


@app.route("/kit/<rid>")
def kit(rid):
    """Free Fix Kit download, generated from the stored audit report."""
    rid, rep = load_report(rid)
    if not rep or rep.get("error"):
        abort(404)
    if not hit_rate("kit:" + client_ip()):
        return render_template(
            "error.html",
            message="Rate limit reached (10 kits/hour). Try again in a bit."), 429
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


@app.route("/k/<rid>")
def kit_page(rid):
    """The Fix Kit as a web page: read the files, copy with one click."""
    rid, files, err = _kit_files_or_error(rid, "kit:")
    if err:
        return err
    _rid, rep = load_report(rid)
    copy_files = {n: c for n, c in files.items() if n != "README.md"}
    guides = {n: c for n, c in files.items() if n.startswith("guides/")}
    paste_files = {n: c for n, c in copy_files.items() if not n.startswith("guides/")}
    return render_template("kit.html", rid=rid, rep=rep, readme=files.get("README.md", ""),
                           paste_files=paste_files, guides=guides)


@app.route("/api")
def api_docs():
    return render_template("api.html")


def _api_url(path):
    return api_base() + path


@app.route("/api/v1/audit", methods=["POST"])
def api_audit():
    """Run an audit via JSON: {"url": "https://example.com"}."""
    if not hit_rate("api:" + client_ip()):
        return {"error": "Rate limit reached (10 audits/hour). Try again in a bit."}, 429
    raw = ""
    if request.is_json:
        raw = (request.get_json(silent=True) or {}).get("url", "")
    if not raw:
        raw = request.form.get("url", "")
    url = clean_url(raw)
    if not url:
        return {"error": "Provide a valid public website address as 'url'."}, 400
    rep = run_audit(url)
    if rep is None:
        return {"error": "The audit timed out or the site didn't respond. Try again."}, 502
    try:
        fh = urllib.parse.urlparse(rep.get("final_url") or url).hostname or ""
        if fh and not is_public_host(fh):
            return {"error": "That address isn't a public website."}, 400
    except Exception:
        return {"error": "That address isn't a public website."}, 400
    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = rep
    with open(os.path.join(DATA_DIR, "report-%s.json" % rid), "w") as f:
        json.dump(rep, f)
    return {
        "url": rep.get("url"),
        "score": rep.get("score"),
        "grade": rep.get("grade"),
        "checks": rep.get("checks", []),
        "recommendations": rep.get("recommendations", []),
        "audited_at": rep.get("audited_at"),
        "report_url": _api_url("/r/" + rid),
        "kit_page_url": _api_url("/k/" + rid),
        "kit_zip_url": _api_url("/kit/" + rid),
    }


@app.route("/api/v1/report/<rid>")
def api_report(rid):
    rid, rep = load_report(rid)
    if not rep:
        return {"error": "No audit found for that id."}, 404
    return {
        "url": rep.get("url"),
        "score": rep.get("score"),
        "grade": rep.get("grade"),
        "checks": rep.get("checks", []),
        "recommendations": rep.get("recommendations", []),
        "audited_at": rep.get("audited_at"),
        "report_url": _api_url("/r/" + rid),
        "kit_page_url": _api_url("/k/" + rid),
        "kit_zip_url": _api_url("/kit/" + rid),
    }


@app.route("/api/v1/kit/<rid>")
def api_kit(rid):
    """The Fix Kit files as JSON: {"files": {"llms.txt": "...", ...}}."""
    rid, files, err = _kit_files_or_error(rid, "kit:")
    if err:
        body, code = err
        return {"error": "Kit unavailable."}, code
    return {"files": files, "kit_zip_url": _api_url("/kit/" + rid)}


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/health")
def health():
    return "ok", 200


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           '  <url><loc>https://unamused.app/</loc></url>\n'
           '  <url><loc>https://unamused.app/api</loc></url>\n'
           '</urlset>\n')
    return Response(xml, mimetype="application/xml")


@app.route("/llms.txt")
def llms_txt():
    body = ("# Unamused\n"
            "> Free audit: how ready a business website is for AI agents to read, "
            "recommend, and transact with it. Independent project, not affiliated with Meta.\n"
            "\n"
            "## Key pages\n"
            "- Audit your site (free): https://unamused.app/\n"
            "- Method and source code: https://github.com/DPL1979/unamused\n"
            "\n"
            "## What it scores\n"
            "Action surface (booking/ordering), schema.org structured data, machine-readable "
            "contact, semantic HTML, sitemap/robots, technical hygiene, llms.txt, Open Graph.\n")
    return Response(body, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, threaded=True)
