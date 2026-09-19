#!/usr/bin/env python3
"""
Unamused Audit v0.1
Scores how ready a business website is for AI agents (Muse-first, agent-general).

Usage: python3 audit.py <url> [--out dir]

Checks (weighted, total 100):
  Action surface ............ 25   Can an agent DO something? (book, order, contact)
  Structured business data .. 20   JSON-LD schema.org (name, phone, address, hours...)
  Machine-readable contact .. 15   tel:/mailto: links, address & hours in text
  Semantic HTML ............. 10   title, description, h1, landmarks, lang
  Discoverability ........... 10   sitemap.xml (5) + robots.txt (5)
  llms.txt ..................  5   Emerging convention; cheap hedge, weighted low on purpose
  Hygiene ................... 10   HTTPS (4) + mobile viewport (3) + fast response (3)
  Social/OG meta ............  5   og: tags for rich unfurls

Methodology note: llms.txt is deliberately low-weighted. 2026 server-log studies
(Ahrefs, ~137k domains) found ~97% of llms.txt files received zero requests and no
major AI provider confirms consuming it. We check it as cheap hygiene, not as a
ranking lever. What actually lets an agent serve a business: structured data plus
a machine-usable action surface. That is what this audit weights.
"""

import json
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from datetime import datetime, timezone

VERSION = "0.1"
UA = "Mozilla/5.0 (compatible; UnamusedAudit/%s; +https://muse.ai)" % VERSION
TIMEOUT = 15

BOOKING_PROVIDERS = [
    "zocdoc", "booksy", "vagaro", "mindbodyonline", "opentable", "resy",
    "yelp.com", "calendly", "acuityscheduling", "fresha", "square.site",
    "squarespacescheduling", "localmed", "nexhealth", "patientpop",
    "demandforce", "weave", "solutionreach", "doctolib", "jameda",
    "opentable.com", "tock", "yelp", "groupon", "booksy.com",
]
BOOKING_KEYWORDS = re.compile(
    r"book|appointment|schedule|reserve|reservation|order online|order now|"
    r"book now|book online|request appointment|make an appointment",
    re.I,
)
AI_BOTS = ["gptbot", "claudebot", "claude-bot", "perplexitybot", "google-extended",
           "deepseekbot", "meta-externalagent", "facebookexternalhit"]
BUSINESS_TYPES = re.compile(r"business|store|dentist|restaurant|clinic|medical|hotel|"
                            r"professionalservice|service|organization|place", re.I)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.h1 = 0
        self.metas = {}
        self.anchors = []          # (href, text)
        self._cur_a = None
        self.ld_json = []
        self._in_ld = False
        self._ld_buf = ""
        self.forms = 0
        self.landmarks = set()
        self.lang = ""
        self._in_html_tag_done = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html" and not self._in_html_tag_done:
            self.lang = a.get("lang", "")
            self._in_html_tag_done = True
        if tag == "title":
            self._in_title = True
        if tag in ("main", "header", "nav", "footer"):
            self.landmarks.add(tag)
        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name and "content" in a:
                self.metas[name] = a["content"]
        if tag == "h1":
            self.h1 += 1
        if tag == "a":
            self._cur_a = [a.get("href", ""), ""]
        if tag == "form":
            self.forms += 1
        if tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_ld = True
            self._ld_buf = ""

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "a" and self._cur_a is not None:
            self.anchors.append((self._cur_a[0], self._cur_a[1].strip()))
            self._cur_a = None
        if tag == "script" and self._in_ld:
            self._in_ld = False
            self.ld_json.append(self._ld_buf)

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._cur_a is not None:
            self._cur_a[1] += data
        if self._in_ld:
            self._ld_buf += data


def fetch(url):
    """GET a URL. Returns dict with ok, status, body, ms, final_url, error."""
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read()
            ms = int((time.time() - t0) * 1000)
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return {"ok": True, "status": r.status, "body": text,
                    "bytes": len(body), "ms": ms, "final_url": r.geturl(),
                    "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "body": "", "bytes": 0,
                "ms": int((time.time() - t0) * 1000), "final_url": url,
                "error": "HTTP %s" % e.code}
    except Exception as e:
        return {"ok": False, "status": 0, "body": "", "bytes": 0,
                "ms": int((time.time() - t0) * 1000), "final_url": url,
                "error": str(e)[:120]}


def audit(url):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    base = "%s://%s" % (parsed.scheme, parsed.netloc)

    checks = []
    recs = []

    def add(name, weight, score, status, detail, fix=None, priority=None):
        checks.append({"name": name, "weight": weight, "score": score,
                       "status": status, "detail": detail})
        if fix and status != "pass":
            recs.append({"priority": priority or "Medium", "check": name, "fix": fix})

    # ---- main page ----
    page = fetch(url)
    if not page["ok"]:
        return {"url": url, "error": page["error"], "score": 0,
                "grade": "Unreachable", "checks": [], "recommendations": [],
                "audited_at": datetime.now(timezone.utc).isoformat()}
    p = PageParser()
    try:
        p.feed(page["body"][:2_000_000])
    except Exception:
        pass
    text_low = re.sub(r"<[^>]+>", " ", page["body"][:500_000]).lower()

    # ---- 1. Action surface (25) ----
    provider_hit = [b for b in BOOKING_PROVIDERS
                    if b in page["body"].lower() or
                    any(b in (h or "").lower() for h, _ in p.anchors)]
    kw_hits = [(h, t) for h, t in p.anchors
               if h and BOOKING_KEYWORDS.search((t or "") + " " + h)]
    tel_links = [h for h, _ in p.anchors if (h or "").startswith("tel:")]
    if provider_hit:
        add("Action surface", 25, 25, "pass",
            "Booking provider detected: %s. An agent can complete a booking."
            % ", ".join(sorted(set(provider_hit))[:3]))
    elif kw_hits:
        sample = (kw_hits[0][1] or kw_hits[0][0])[:60]
        add("Action surface", 25, 15, "warn",
            "Booking links found ('%s') but no embedded booking provider; "
            "an agent may need to drive a form." % sample,
            "Embed online scheduling (e.g. booksy/vagaro/zocdoc for clinics, "
            "opentable/resy for restaurants) so an agent can book without a human.",
            "High")
    elif p.forms > 0:
        add("Action surface", 25, 8, "warn",
            "Contact form present but no booking flow; agents can enquire, not transact.",
            "Add real online booking or ordering — agents convert only where they can act.",
            "High")
    else:
        add("Action surface", 25, 0, "fail",
            "No booking, ordering, or contact action detected. An agent can read "
            "about this business but cannot do anything for a customer.",
            "Add online booking/ordering. This is the single highest-leverage fix: "
            "agents send customers only where they can complete the task.", "High")

    # ---- 2. Structured business data (20) ----
    schemas = []
    for blob in p.ld_json:
        try:
            data = json.loads(blob)
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for it in items:
            if isinstance(it, dict) and "@graph" in it:
                items.extend([n for n in it["@graph"] if isinstance(n, dict)])
                continue
            if isinstance(it, dict):
                schemas.append(it)
    biz = None
    for s in schemas:
        t = s.get("@type", "")
        types = t if isinstance(t, list) else [t]
        if any(BUSINESS_TYPES.search(str(x)) for x in types):
            biz = s
            break
    if biz:
        fields = {"name": biz.get("name"), "telephone": biz.get("telephone"),
                  "address": biz.get("address"),
                  "hours": biz.get("openingHours") or biz.get("openingHoursSpecification"),
                  "geo": biz.get("geo")}
        have = [k for k, v in fields.items() if v]
        sc = 10 + int(10 * len(have) / 5)
        missing = [k for k in fields if k not in have]
        add("Structured business data", 20, sc, "pass" if not missing else "warn",
            "JSON-LD %s found with %d/5 key fields (%s)." %
            (biz.get("@type"), len(have), ", ".join(have)),
            ("Add missing schema.org fields: %s." % ", ".join(missing)) if missing else None,
            "High" if missing else None)
    else:
        n_ld = len(p.ld_json)
        add("Structured business data", 20, 0, "fail",
            "No business schema.org markup found%s. Agents must guess your "
            "name, phone, address and hours from prose." %
            (" (%d unrelated JSON-LD blocks)" % n_ld if n_ld else ""),
            "Add JSON-LD LocalBusiness (or Dentist/Restaurant/etc.) markup with "
            "name, telephone, address, openingHours and geo. Copy-pasteable in 20 minutes.",
            "High")

    # ---- 3. Machine-readable contact (15) ----
    contact_pts, contact_notes = 0, []
    if tel_links:
        contact_pts += 6
        contact_notes.append("%d tap-to-call link(s)" % len(tel_links))
    if any((h or "").startswith("mailto:") for h, _ in p.anchors):
        contact_pts += 2
        contact_notes.append("email link")
    if re.search(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", text_low):
        contact_pts += 3
        contact_notes.append("phone in text")
    if re.search(r"\b\d{5}(-\d{4})?\b", text_low):
        contact_pts += 2
        contact_notes.append("postal code in text")
    if re.search(r"mon(day)?|tue(sday)?|wed(nesday)?|hours|open daily|am\s*[–-]\s*\d", text_low):
        contact_pts += 2
        contact_notes.append("hours in text")
    contact_pts = min(15, contact_pts)
    add("Machine-readable contact", 15, contact_pts,
        "pass" if contact_pts >= 12 else ("warn" if contact_pts >= 7 else "fail"),
        "Found: %s." % (", ".join(contact_notes) if contact_notes else "almost nothing"),
        "Put phone as a tel: link, plus street address, hours and email in plain "
        "text on every page. Agents extract facts, not designs." if contact_pts < 12 else None,
        "Medium" if contact_pts < 12 else None)

    # ---- 4. Semantic HTML (10) ----
    sem_pts, sem_notes = 0, []
    if p.title.strip():
        sem_pts += 3
        sem_notes.append("title")
    if p.metas.get("description"):
        sem_pts += 2
        sem_notes.append("meta description")
    if p.h1 >= 1:
        sem_pts += 2
        sem_notes.append("h1")
    if p.landmarks:
        sem_pts += 2
        sem_notes.append("landmarks:%s" % ",".join(sorted(p.landmarks)))
    if p.lang:
        sem_pts += 1
        sem_notes.append("lang=%s" % p.lang)
    add("Semantic HTML", 10, sem_pts,
        "pass" if sem_pts >= 8 else ("warn" if sem_pts >= 5 else "fail"),
        "Present: %s." % (", ".join(sem_notes) if sem_notes else "bare markup"),
        "Use one h1, a real <title> and meta description, and main/header/nav "
        "landmarks. This is how agents (and screen readers) parse a page." if sem_pts < 8 else None,
        "Low" if sem_pts < 8 else None)

    # ---- 5. Discoverability (10) ----
    sm = fetch(base + "/sitemap.xml")
    sm_ok = sm["ok"] and "<url" in sm["body"]
    add("Sitemap", 5, 5 if sm_ok else 0, "pass" if sm_ok else "fail",
        "sitemap.xml found." if sm_ok else "No sitemap.xml at root.",
        None if sm_ok else "Publish a sitemap.xml so agents and crawlers discover "
        "every service page, not just the homepage.", "Low")
    rb = fetch(base + "/robots.txt")
    if rb["ok"]:
        low = rb["body"].lower()
        bots = [b for b in AI_BOTS if b in low]
        blocked = "disallow: /" in low.replace(" ", "")
        detail = "robots.txt found."
        if bots:
            detail += " Mentions AI crawlers: %s." % ", ".join(bots)
        if blocked:
            detail += " WARNING: site-wide Disallow blocks all crawlers, including agents."
        sc = 2 if blocked else 5
        add("robots.txt", 5, sc, "fail" if blocked else "pass", detail,
            "Remove the site-wide Disallow if you want AI agents to read and "
            "recommend you — it blocks them too." if blocked else None,
            "High" if blocked else None)
    else:
        add("robots.txt", 5, 2, "warn", "No robots.txt (not fatal; agents assume allowed).",
            None, None)

    # ---- 6. llms.txt (5, deliberately light) ----
    ll = fetch(base + "/llms.txt")
    if ll["ok"] and len(ll["body"]) > 200:
        rich = "#" in ll["body"] and "http" in ll["body"]
        add("llms.txt", 5, 5 if rich else 3, "pass",
            "llms.txt present (%d chars). Cheap hedge; a few agent tools fetch it." % len(ll["body"]))
    elif ll["ok"]:
        add("llms.txt", 5, 2, "warn", "llms.txt exists but is nearly empty.",
            "Flesh it out: one-line site summary plus curated links to key pages.", "Low")
    else:
        add("llms.txt", 5, 0, "warn", "No llms.txt. Honest note: 2026 server-log studies "
            "show ~97% of llms.txt files get zero requests and no major AI provider "
            "confirms consuming it — treat as 5-minute hygiene, not a lever.",
            "Add a minimal llms.txt (site summary + key page links). Five minutes, "
            "zero downside.", "Low")

    # ---- 7. Hygiene (10) ----
    hy, hy_notes = 0, []
    if parsed.scheme == "https":
        hy += 4
        hy_notes.append("https")
    if p.metas.get("viewport"):
        hy += 3
        hy_notes.append("viewport")
    if page["ms"] < 2000:
        hy += 3
        hy_notes.append("%dms" % page["ms"])
    else:
        hy_notes.append("slow:%dms" % page["ms"])
    add("Hygiene", 10, hy, "pass" if hy >= 8 else "warn",
        ", ".join(hy_notes) + ".",
        "Serve over HTTPS, add a viewport meta tag, keep response under 2s." if hy < 8 else None,
        "Low" if hy < 8 else None)

    # ---- 8. OG meta (5) ----
    og = [k for k in p.metas if k.startswith("og:")]
    add("Social/OG meta", 5, 5 if len(og) >= 3 else (2 if og else 0),
        "pass" if len(og) >= 3 else ("warn" if og else "fail"),
        "%d og: tags." % len(og) if og else "No Open Graph tags; link unfurls are bare.",
        None if len(og) >= 3 else "Add og:title, og:description, og:image for rich previews.",
        "Low")

    total = sum(c["score"] for c in checks)
    max_total = sum(c["weight"] for c in checks)
    score = int(round(100 * total / max_total))
    if score >= 85:
        grade = "Amused"
    elif score >= 65:
        grade = "Almost amused"
    elif score >= 40:
        grade = "Unamused"
    else:
        grade = "Deeply unamused"

    prio = {"High": 0, "Medium": 1, "Low": 2}
    recs.sort(key=lambda r: prio.get(r["priority"], 3))

    return {
        "tool": "Unamused Audit", "version": VERSION,
        "url": url, "final_url": page["final_url"],
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "score": score, "grade": grade,
        "checks": checks, "recommendations": recs,
    }


HTML_TMPL = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unamused Audit — {host}</title>
<style>
body{{font-family:-apple-system,system-ui,sans-serif;max-width:760px;margin:0 auto;
padding:24px;color:#1a1a1a;line-height:1.5}}
.score{{display:flex;align-items:center;gap:20px;margin:20px 0}}
.dial{{width:110px;height:110px;border-radius:50%;display:flex;align-items:center;
justify-content:center;font-size:34px;font-weight:700;color:#fff;background:{color}}}
.grade{{font-size:22px;font-weight:700}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{text-align:left;padding:10px;border-bottom:1px solid #eee;font-size:14px}}
th{{color:#666;font-weight:600}}
.pill{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}}
.pass{{background:#e6f4ea;color:#137333}}.warn{{background:#fef7e0;color:#b06000}}
.fail{{background:#fce8e6;color:#a50e0e}}
.rec{{border-left:4px solid #1a73e8;padding:8px 12px;margin:10px 0;background:#f8f9fa}}
.rec b{{display:block}}.meta{{color:#666;font-size:13px}}
.foot{{margin-top:32px;padding-top:16px;border-top:1px solid #eee;color:#777;font-size:12px}}
</style></head><body>
<h1>Unamused Audit</h1>
<p class="meta">{url}<br>Audited {when} · v{ver}</p>
<div class="score"><div class="dial">{score}</div>
<div><div class="grade">{grade}</div>
<div class="meta">How ready this site is for AI agents to read, recommend, and transact.</div></div></div>
<h2>Checks</h2>
<table><tr><th>Check</th><th>Result</th><th>Score</th><th>Detail</th></tr>{rows}</table>
<h2>Prioritized fixes</h2>{recs}
<div class="foot">Methodology: weighted toward what lets an agent complete a task —
structured business data and a machine-usable action surface (booking/ordering).
llms.txt is checked but lightly weighted: 2026 server-log studies show ~97% of
llms.txt files receive zero requests and no major AI provider confirms consuming it.
We score it as cheap hygiene, not a lever. No snake oil.</div>
</body></html>"""


def render_html(rep):
    color = {"Amused": "#137333", "Almost amused": "#b06000",
             "Unamused": "#b06000", "Deeply unamused": "#a50e0e",
             "Unreachable": "#666"}.get(rep["grade"], "#666")
    rows = ""
    for c in rep["checks"]:
        rows += ("<tr><td><b>%s</b></td>"
                 "<td><span class='pill %s'>%s</span></td>"
                 "<td>%d/%d</td><td>%s</td></tr>") % (
            c["name"], c["status"], c["status"], c["score"], c["weight"], c["detail"])
    recs = ""
    for r in rep["recommendations"]:
        recs += "<div class='rec'><b>[%s] %s</b>%s</div>" % (
            r["priority"], r["check"], r["fix"])
    if not recs:
        recs = "<p>Nothing to fix — this site is agent-ready. 🎉</p>"
    host = urllib.parse.urlparse(rep["url"]).netloc
    when = rep["audited_at"][:10]
    return HTML_TMPL.format(host=host, url=rep["url"], when=when, ver=rep["version"],
                            score=rep["score"], grade=rep["grade"], color=color,
                            rows=rows, recs=recs)


def main():
    if len(sys.argv) < 2:
        print("usage: python3 audit.py <url> [--out dir]")
        sys.exit(1)
    url = sys.argv[1]
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "."
    print("Auditing %s ..." % url, flush=True)
    rep = audit(url)
    host = re.sub(r"[^a-z0-9]+", "-", urllib.parse.urlparse(rep["url"]).netloc.lower()).strip("-")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    base = "%s/%s-%s" % (out.rstrip("/"), host or "site", stamp)
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2)
    with open(base + ".html", "w") as f:
        f.write(render_html(rep))
    print("Score: %d/100 — %s" % (rep["score"], rep["grade"]))
    print("Wrote %s.json and %s.html" % (base, base))


if __name__ == "__main__":
    main()
