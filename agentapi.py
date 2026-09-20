"""Per-business Agent API: generate and host a machine-usable action API
for any business, consumable by Muse (via its connector platform),
Claude, ChatGPT, or any MCP-capable agent.

A business owner defines 1-5 actions (book, quote, order, contact...).
We host:
  - OpenAPI 3.1 spec      GET /a/<id>/openapi.json
  - MCP server (Streamable HTTP, stateless)  POST /a/<id>/mcp
  - Direct REST execution POST /a/<id>/actions/<name>
  - Connector manifest   GET /a/<id>/manifest.json

Execution channels (V1):
  - webhook: POST JSON {action, params} to the business's URL (SSRF-guarded)
  - link:    return a deep URL with params filled in (booking providers etc.)

Actions that touch money or commitments should set requires_approval=True.
Approval is server-enforced: the first call only validates the parameters
and returns a single-use approval_token (10-minute TTL). The action runs
only when called again with that token — after a human has said yes.
Tokens bind the exact approved parameters, so they can't be tampered with.

Webhooks are signed: every outbound POST carries X-Unamused-Signature
(HMAC-SHA256 over "<unix-timestamp>.<raw-body>" with the business's
webhook_secret), X-Unamused-Timestamp, and X-Unamused-Idempotency-Key.
Receivers should verify the signature and reject timestamps outside a
+-5 minute window to stop replays.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

API_ID_RE = re.compile(r"^[0-9a-f]{12}$")
ACTION_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
PARAM_TYPES = ("string", "number", "integer", "boolean")

ACTION_TEMPLATES = [
    {
        "key": "book_appointment",
        "title": "Book an appointment",
        "description": "Book an appointment or consultation with the business.",
        "params": [
            {"name": "name", "type": "string", "required": True,
             "description": "Customer's full name"},
            {"name": "phone_or_email", "type": "string", "required": True,
             "description": "Customer's phone number or email address"},
            {"name": "preferred_time", "type": "string", "required": False,
             "description": "Preferred date/time, e.g. 'Tue afternoon'"},
            {"name": "notes", "type": "string", "required": False,
             "description": "Anything the business should know"},
        ],
        "requires_approval": True,
    },
    {
        "key": "request_quote",
        "title": "Request a quote",
        "description": "Ask the business for a price quote.",
        "params": [
            {"name": "name", "type": "string", "required": True,
             "description": "Customer's full name"},
            {"name": "phone_or_email", "type": "string", "required": True,
             "description": "Customer's phone number or email address"},
            {"name": "details", "type": "string", "required": True,
             "description": "What the customer wants quoted"},
        ],
        "requires_approval": False,
    },
    {
        "key": "place_order",
        "title": "Place an order",
        "description": "Place an order with the business.",
        "params": [
            {"name": "name", "type": "string", "required": True,
             "description": "Customer's full name"},
            {"name": "phone_or_email", "type": "string", "required": True,
             "description": "Customer's phone number or email address"},
            {"name": "items", "type": "string", "required": True,
             "description": "What the customer wants to order"},
        ],
        "requires_approval": True,
    },
    {
        "key": "contact_business",
        "title": "Contact the business",
        "description": "Send a message to the business.",
        "params": [
            {"name": "name", "type": "string", "required": True,
             "description": "Customer's full name"},
            {"name": "phone_or_email", "type": "string", "required": True,
             "description": "Customer's phone number or email address"},
            {"name": "message", "type": "string", "required": True,
             "description": "The customer's message"},
        ],
        "requires_approval": False,
    },
]


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class _PublicRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow webhook redirects only to public hosts (SSRF guard).

    The initial webhook URL is validated before the request, but urllib
    follows redirects by default — a hostile 302 could bounce a request
    from a public URL to an internal one. Re-validate every hop.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = urllib.parse.urlparse(newurl).hostname or ""
        if not is_public_host(host):
            raise urllib.error.URLError(
                "redirect to non-public host blocked: %s" % host)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_public_host(host):
    """True only if the hostname resolves exclusively to public IPs."""
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


def validate_action(raw):
    """Validate one action dict from the builder form. Returns (action, error)."""
    name = (raw.get("name") or "").strip().lower()
    if not ACTION_NAME_RE.match(name):
        return None, "action name must be lowercase letters, numbers, underscores"
    title = (raw.get("title") or "").strip()[:80] or name.replace("_", " ").title()
    description = (raw.get("description") or "").strip()[:500]
    if not description:
        return None, "action %r needs a description" % name
    params = []
    seen = set()
    for p in raw.get("params") or []:
        pname = (p.get("name") or "").strip().lower()
        if not re.match(r"^[a-z][a-z0-9_]{1,30}$", pname) or pname in seen:
            return None, "bad parameter name %r in action %r" % (p.get("name"), name)
        seen.add(pname)
        ptype = p.get("type") or "string"
        if ptype not in PARAM_TYPES:
            return None, "bad parameter type %r in action %r" % (ptype, name)
        params.append({
            "name": pname,
            "type": ptype,
            "required": bool(p.get("required")),
            "description": (p.get("description") or "").strip()[:200],
        })
    if not params:
        return None, "action %r needs at least one parameter" % name
    channel = raw.get("channel") or {}
    ctype = channel.get("type")
    if ctype == "webhook":
        url = (channel.get("url") or "").strip()[:500]
        if not re.match(r"^https://", url, re.I):
            return None, "webhook for %r must be an https URL" % name
        try:
            host = urllib.parse.urlparse(url).hostname or ""
        except Exception:
            return None, "bad webhook URL for %r" % name
        if not is_public_host(host):
            return None, "webhook host for %r is not a public address" % name
        chan = {"type": "webhook", "url": url}
    elif ctype == "link":
        tpl = (channel.get("url_template") or "").strip()[:500]
        if not re.match(r"^https://", tpl, re.I):
            return None, "link template for %r must start with https://" % name
        chan = {"type": "link", "url_template": tpl}
    else:
        return None, "action %r needs a channel (webhook or link)" % name
    return {
        "name": name,
        "title": title,
        "description": description,
        "params": params,
        "channel": chan,
        "requires_approval": bool(raw.get("requires_approval")),
    }, None


def new_api_id():
    return secrets.token_hex(6)


APPROVAL_TTL = 600  # approval tokens live 10 minutes and are single-use


def _approval_path(data_dir, token):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", token or "")
    return os.path.join(data_dir, "approval-%s.json" % safe)


def _purge_expired_approvals(data_dir):
    """Best-effort cleanup of stale approval token files."""
    try:
        names = os.listdir(data_dir)
    except Exception:
        return
    now = time.time()
    for fn in names:
        if not (fn.startswith("approval-") and fn.endswith(".json")):
            continue
        p = os.path.join(data_dir, fn)
        try:
            with open(p) as f:
                exp = json.load(f).get("expires_at", 0)
            if exp < now:
                os.remove(p)
        except Exception:
            try:
                os.remove(p)
            except Exception:
                pass


def prepare_approval(data_dir, record, action_name, params):
    """Validate params for an approval-gated action and mint a single-use
    token instead of executing. Returns (True, result-with-token) or
    (False, error)."""
    action = next((a for a in record["actions"] if a["name"] == action_name), None)
    if not action:
        return False, {"error": "unknown action: %s" % action_name}
    clean, err = coerce_params(action, params or {})
    if err:
        return False, {"error": err}
    _purge_expired_approvals(data_dir)
    token = secrets.token_urlsafe(32)
    pending = {
        "business_id": record["id"],
        "action": action_name,
        "params": clean,  # token binds the exact approved parameters
        "created_at": utcnow(),
        "expires_at": time.time() + APPROVAL_TTL,
    }
    try:
        with open(_approval_path(data_dir, token), "w") as f:
            json.dump(pending, f)
    except Exception as e:
        return False, {"error": "could not create approval: %s" % str(e)[:100]}
    return True, {
        "approval_required": True,
        "approval_token": token,
        "action": action_name,
        "params": clean,
        "expires_in": APPROVAL_TTL,
        "message": ("'%s' commits %s, so it needs a human's approval. Show "
                    "them the action and parameters, get a yes, then call "
                    "again with approval_token to run it."
                    % (action["title"], record["business"])),
    }


def confirm_approval(data_dir, token, business_id=None):
    """Burn a single-use approval token and execute the bound action.
    Returns (ok, result)."""
    path = _approval_path(data_dir, token)
    try:
        with open(path) as f:
            pending = json.load(f)
    except Exception:
        return False, {"error": "unknown or expired approval token"}
    try:
        os.remove(path)  # single use: burn before executing
    except Exception:
        pass
    if pending.get("expires_at", 0) < time.time():
        return False, {"error": "approval token expired — prepare the action again"}
    if business_id and pending.get("business_id") != business_id:
        return False, {"error": "approval token does not match this business"}
    record = load_record(data_dir, pending.get("business_id") or "")
    if record is None:
        return False, {"error": "business no longer exists"}
    idem = hashlib.sha256(("approval:" + token).encode()).hexdigest()[:32]
    return execute_action(record, pending.get("action"), pending.get("params"),
                          data_dir=data_dir, idempotency_key=idem)


def request_action(data_dir, record, action_name, params, approval_token=None):
    """Enforcing entry point for every action call.

    Approval-gated actions never execute on first call: they return
    approval_required + a single-use token. Pass the token back (after a
    human approves) to run. Non-gated actions execute immediately.
    Returns (ok, result)."""
    action = next((a for a in record["actions"] if a["name"] == action_name), None)
    if not action:
        return False, {"error": "unknown action: %s" % action_name}
    if action.get("requires_approval"):
        if approval_token:
            return confirm_approval(data_dir, approval_token, record["id"])
        return prepare_approval(data_dir, record, action_name, params)
    return execute_action(record, action_name, params, data_dir=data_dir)


def build_record(business, url, actions, contact_email=""):
    return {
        "id": new_api_id(),
        "business": (business or "").strip()[:120],
        "url": (url or "").strip()[:500],
        "contact_email": (contact_email or "").strip()[:120],
        "actions": actions,
        "webhook_secret": secrets.token_hex(32),
        "created_at": utcnow(),
        "version": 1,
    }


def input_schema(action):
    props = {}
    required = []
    for p in action["params"]:
        props[p["name"]] = {"type": p["type"],
                            "description": p.get("description", "")}
        if p["required"]:
            required.append(p["name"])
    schema = {"type": "object", "properties": props,
              "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def coerce_params(action, params):
    """Validate + coerce caller params. Returns (clean, error)."""
    if not isinstance(params, dict):
        return None, "params must be an object"
    clean = {}
    for p in action["params"]:
        pname = p["name"]
        if pname in params and params[pname] not in (None, ""):
            v = params[pname]
            try:
                if p["type"] == "integer":
                    v = int(v)
                elif p["type"] == "number":
                    v = float(v)
                elif p["type"] == "boolean":
                    v = bool(v) if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes")
                else:
                    v = str(v)[:2000]
            except (ValueError, TypeError):
                return None, "parameter %r must be %s" % (pname, p["type"])
            clean[pname] = v
        elif p["required"]:
            return None, "missing required parameter: %s" % pname
    return clean, None


def execute_action(record, action_name, params, data_dir=None,
                   idempotency_key=None):
    """Run one action through its channel. Returns (ok, result_dict).

    Webhook deliveries are signed. The business's webhook_secret (generated
    at creation, backfilled for older records) signs the raw body:
        X-Unamused-Signature: t=<unix-ts>,v1=<hmac-sha256 hex of "<ts>.<body>">
    plus X-Unamused-Timestamp and X-Unamused-Idempotency-Key headers.
    Receivers verify with: hmac.new(secret, (ts + "." + body).encode(),
    sha256).hexdigest() and should reject timestamps outside +-5 minutes
    to stop replays. The idempotency key is also inside the JSON body so
    receivers can dedupe retried deliveries.
    """
    action = next((a for a in record["actions"] if a["name"] == action_name), None)
    if not action:
        return False, {"error": "unknown action: %s" % action_name}
    clean, err = coerce_params(action, params or {})
    if err:
        return False, {"error": err}
    chan = action["channel"]
    if chan["type"] == "link":
        url = chan["url_template"]
        for k, v in clean.items():
            url = url.replace("{%s}" % k, urllib.parse.quote(str(v), safe=""))
        return True, {
            "action": action_name,
            "handoff_url": url,
            "message": "Open this link to complete '%s' with %s."
                       % (action["title"], record["business"]),
        }
    # webhook
    secret = record.get("webhook_secret")
    if not secret and data_dir:
        # backfill for records created before signing existed
        secret = secrets.token_hex(32)
        record["webhook_secret"] = secret
        try:
            with open(os.path.join(data_dir,
                                   "agentapi-%s.json" % record["id"]), "w") as f:
                json.dump(record, f)
        except Exception:
            pass
    ts = str(int(time.time()))
    idem = idempotency_key or secrets.token_hex(16)
    payload = json.dumps({
        "source": "unamused-agent-api",
        "api_id": record["id"],
        "business": record["business"],
        "action": action_name,
        "params": clean,
        "idempotency_key": idem,
        "received_at": utcnow(),
    }).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "User-Agent": "Unamused-Agent-API/1.0",
               "X-Unamused-Timestamp": ts,
               "X-Unamused-Idempotency-Key": idem}
    if secret:
        sig = hmac.new(secret.encode(),
                       ts.encode() + b"." + payload,
                       hashlib.sha256).hexdigest()
        headers["X-Unamused-Signature"] = "t=%s,v1=%s" % (ts, sig)
    try:
        host = urllib.parse.urlparse(chan["url"]).hostname or ""
        if not is_public_host(host):
            return False, {"error": "webhook host is not a public address"}
        req = urllib.request.Request(chan["url"], data=payload,
                                     headers=headers, method="POST")
        opener = urllib.request.build_opener(_PublicRedirectHandler())
        with opener.open(req, timeout=15) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
        return True, {
            "action": action_name,
            "delivered": True,
            "idempotency_key": idem,
            "signed": bool(secret),
            "business_response": body[:500],
            "message": "'%s' was sent to %s." % (action["title"], record["business"]),
        }
    except Exception as e:
        return False, {"error": "webhook delivery failed: %s" % str(e)[:200]}


def openapi_spec(record, base_url):
    """OpenAPI 3.1 spec for the business's actions."""
    paths = {}
    for a in record["actions"]:
        op = {
            "summary": a["title"],
            "description": a["description"],
            "operationId": a["name"],
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": input_schema(a)}},
            },
            "responses": {"200": {"description": "Action result"}},
        }
        if a["requires_approval"]:
            op["x-unamused-requires-approval"] = True
            op["description"] += (" NOTE: this action commits the business "
                                  "(booking/order) and approval is enforced "
                                  "server-side. The first call only validates "
                                  "and returns approval_required + a "
                                  "single-use approval_token (10 min). Call "
                                  "again with {\"approval_token\": \"...\"} "
                                  "after the human approves to execute.")
        paths["/a/%s/actions/%s" % (record["id"], a["name"])] = {"post": op}
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "%s — Agent API" % record["business"],
            "version": "1.0.0",
            "description": ("Machine-usable actions for %s (%s), generated free "
                            "by Unamused. Submit this spec to an agent connector "
                            "directory (e.g. Meta's Muse connector platform) to let "
                            "AI agents act on behalf of customers."
                            % (record["business"], record["url"])),
        },
        "servers": [{"url": base_url.rstrip("/")}],
        "paths": paths,
    }


def connector_manifest(record, base_url):
    """Generic connector manifest for agent directory submissions."""
    return {
        "name": "%s Agent API" % record["business"],
        "description": "Let AI agents %s: %s." % (
            record["business"],
            ", ".join(a["title"].lower() for a in record["actions"])),
        "vendor": record["business"],
        "vendor_url": record["url"],
        "openapi_url": "%s/a/%s/openapi.json" % (base_url.rstrip("/"), record["id"]),
        "mcp_url": "%s/a/%s/mcp" % (base_url.rstrip("/"), record["id"]),
        "auth": {"type": "none"},
        "actions": [
            {"name": a["name"], "title": a["title"],
             "requires_approval": a["requires_approval"]}
            for a in record["actions"]
        ],
        "generated_by": "Unamused (https://unamused.app) — free, MIT",
    }


# ---- MCP (Model Context Protocol, Streamable HTTP, stateless) ----

MCP_VERSION = "2025-06-18"


def mcp_input_schema(action):
    """input_schema plus the approval_token field for gated actions."""
    schema = input_schema(action)
    if action.get("requires_approval"):
        schema["properties"]["approval_token"] = {
            "type": "string",
            "description": ("Token from a previous approval_required response. "
                            "Omit on the first call; include it to confirm "
                            "after the human approves."),
        }
    return schema


def _rpc_ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _rpc_err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def mcp_handle(record, payload, data_dir=None):
    """Handle one JSON-RPC message for the MCP endpoint (stateless).

    data_dir is required for approval-gated actions (tokens are stored
    server-side); without it, gated actions fall back to direct execution.
    """
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return _rpc_err(None, -32600, "invalid JSON-RPC request")
    rid = payload.get("id")
    method = payload.get("method", "")
    params = payload.get("params") or {}

    if method == "initialize":
        return _rpc_ok(rid, {
            "protocolVersion": MCP_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "unamused-agent-api-%s" % record["id"],
                           "version": "1.0.0"},
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None  # notification: no response
    if method == "ping":
        return _rpc_ok(rid, {})
    if method == "tools/list":
        tools = []
        for a in record["actions"]:
            tool = {
                "name": a["name"],
                "description": a["description"],
                "inputSchema": mcp_input_schema(a),
            }
            if a["requires_approval"]:
                tool["annotations"] = {"destructiveHint": True}
                tool["description"] += (" This tool is approval-gated: the "
                                        "first call returns approval_required "
                                        "+ an approval_token; call again with "
                                        "the token after the human approves.")
            tools.append(tool)
        return _rpc_ok(rid, {"tools": tools})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        if data_dir:
            ok, result = request_action(
                data_dir, record, name, args,
                approval_token=args.get("approval_token"))
        else:
            ok, result = execute_action(record, name, args)
        if result.get("approval_required"):
            return _rpc_ok(rid, {
                "content": [{"type": "text",
                             "text": json.dumps(result)}],
            })
        text = _action_result_text(record, ok, result)
        return _rpc_ok(rid, {
            "content": [{"type": "text", "text": text}],
            "isError": not ok,
        })
    return _rpc_err(rid, -32601, "method not found: %s" % method)


# ---- Aggregator: the single "Unamused" connector ----
#
# Every business gets its own hosted API (/a/<id>/...), but Muse's
# connector directory lists services, not ten thousand pizzerias. The
# aggregator is the one Unamused connector: one directory listing, one
# review, one OAuth integration — fronting every business API we host.
# A user connects Unamused once, then reaches any business by asking:
# "book me a table at Mario's" -> search_businesses -> get_business
# -> call_action. The per-business endpoints remain for portability
# (any agent, any platform, no Meta involvement needed).


def load_record(data_dir, aid):
    """Load one business API record by id. Returns record or None."""
    if not API_ID_RE.match(aid or ""):
        return None
    path = os.path.join(data_dir, "agentapi-%s.json" % aid)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def record_summary(record):
    """Public directory entry for one business (no contact details)."""
    return {
        "business_id": record.get("id"),
        "business": record.get("business"),
        "url": record.get("url"),
        "demo": bool(record.get("demo")),
        "created_at": record.get("created_at"),
        "action_count": len(record.get("actions") or []),
        "actions": [
            {"name": a["name"], "title": a["title"],
             "requires_approval": a["requires_approval"]}
            for a in record.get("actions") or []
        ],
    }


def business_detail(record):
    """Full public detail: actions with parameter schemas + approval flags."""
    d = record_summary(record)
    d["actions"] = []
    for a in record.get("actions") or []:
        d["actions"].append({
            "name": a["name"],
            "title": a["title"],
            "description": a["description"],
            "requires_approval": a["requires_approval"],
            "channel": a["channel"]["type"],
            "input_schema": input_schema(a),
        })
    return d


def list_records(data_dir):
    """All hosted business APIs, newest first. Skips unreadable files."""
    out = []
    try:
        names = os.listdir(data_dir)
    except Exception:
        return out
    for fn in names:
        if not (fn.startswith("agentapi-") and fn.endswith(".json")):
            continue
        aid = fn[len("agentapi-"):-len(".json")]
        rec = load_record(data_dir, aid)
        if rec and rec.get("business"):
            out.append(record_summary(rec))
    out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return out


def search_records(data_dir, query):
    """Substring search over business name + URL. Empty query lists all."""
    q = (query or "").strip().lower()
    results = list_records(data_dir)
    if not q:
        return results
    return [s for s in results
            if q in (s.get("business") or "").lower()
            or q in (s.get("url") or "").lower()]


AGGREGATOR_TOOLS = [
    {
        "name": "search_businesses",
        "description": ("Search businesses hosted on Unamused by name. Returns "
                        "business_id values to pass to get_business. "
                        "Omit the query to list every business."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "Business name or keyword"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_business",
        "description": ("Get a business's details and its available actions, "
                        "with parameter schemas and per-action approval flags. "
                        "Call this before call_action."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "business_id": {"type": "string",
                               "description": "business_id from search_businesses"},
            },
            "required": ["business_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "call_action",
        "description": ("Call one of a business's actions. Check get_business "
                        "first: actions flagged requires_approval commit the "
                        "business (booking, order) and are gated server-side — "
                        "the first call returns approval_required plus a "
                        "single-use approval_token; ask the human, then call "
                        "again with approval_token to execute."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "business_id": {"type": "string",
                               "description": "business_id from search_businesses"},
                "action_name": {"type": "string",
                               "description": "action name from get_business"},
                "params": {"type": "object",
                           "description": "action parameters"},
                "approval_token": {"type": "string",
                                  "description": ("Token from a previous "
                                                 "approval_required response; "
                                                 "omit on first call")},
            },
            "required": ["business_id", "action_name"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    },
]


def _action_result_text(record, ok, result):
    """Shared human-readable text for an executed action (MCP + REST)."""
    text = result.get("message") or ""
    if result.get("handoff_url"):
        text = (text + " " if text else "") + "URL: " + result["handoff_url"]
    if result.get("delivered") and result.get("business_response"):
        text += " Business response: " + result["business_response"][:300]
    if not text:
        text = json.dumps(result)
    if not ok:
        text = "Error: " + result.get("error", "unknown error")
    return text


def aggregator_mcp_handle(data_dir, payload):
    """JSON-RPC handler for the unified Unamused connector (stateless)."""
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return _rpc_err(None, -32600, "invalid JSON-RPC request")
    rid = payload.get("id")
    method = payload.get("method", "")
    params = payload.get("params") or {}

    if method == "initialize":
        return _rpc_ok(rid, {
            "protocolVersion": MCP_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "unamused-connector", "version": "1.0.0"},
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None  # notification: no response
    if method == "ping":
        return _rpc_ok(rid, {})
    if method == "tools/list":
        return _rpc_ok(rid, {"tools": AGGREGATOR_TOOLS})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        if name == "search_businesses":
            results = search_records(data_dir, args.get("query", ""))
            text = (json.dumps(results)
                    if results else "No businesses found on Unamused.")
            return _rpc_ok(rid, {"content": [{"type": "text", "text": text}]})
        if name == "get_business":
            rec = load_record(data_dir, args.get("business_id", ""))
            if rec is None:
                return _rpc_ok(rid, {
                    "content": [{"type": "text",
                                 "text": "Error: unknown business_id"}],
                    "isError": True})
            return _rpc_ok(rid, {"content": [{
                "type": "text", "text": json.dumps(business_detail(rec), indent=2)}]})
        if name == "call_action":
            rec = load_record(data_dir, args.get("business_id", ""))
            if rec is None:
                return _rpc_ok(rid, {
                    "content": [{"type": "text",
                                 "text": "Error: unknown business_id"}],
                    "isError": True})
            ok, result = request_action(
                data_dir, rec, args.get("action_name", ""), args.get("params"),
                approval_token=args.get("approval_token"))
            if result.get("approval_required"):
                return _rpc_ok(rid, {
                    "content": [{"type": "text",
                                 "text": json.dumps(result)}],
                })
            return _rpc_ok(rid, {
                "content": [{"type": "text",
                             "text": _action_result_text(rec, ok, result)}],
                "isError": not ok,
            })
        return _rpc_err(rid, -32601, "unknown tool: %s" % name)
    return _rpc_err(rid, -32601, "method not found: %s" % method)


def aggregator_openapi_spec(base_url):
    """OpenAPI 3.1 for the unified connector REST surface."""
    base = base_url.rstrip("/")
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Unamused Connector",
            "version": "1.0.0",
            "description": ("One connector for every business API hosted by "
                            "Unamused. Search businesses, inspect their "
                            "actions, and call them — from Meta's Muse, "
                            "Claude, ChatGPT, or any agent. Free, MIT, no key. "
                            "Approval-gated actions are marked "
                            "x-unamused-requires-approval: ask the human "
                            "before calling."),
        },
        "servers": [{"url": base}],
        "paths": {
            "/connector/businesses": {
                "get": {
                    "summary": "Search hosted businesses",
                    "operationId": "search_businesses",
                    "parameters": [{
                        "name": "q", "in": "query",
                        "description": "Business name or keyword; omit to list all",
                        "schema": {"type": "string"},
                    }],
                    "responses": {"200": {"description": "Business summaries"}},
                }
            },
            "/connector/businesses/{business_id}": {
                "get": {
                    "summary": "Business detail with action schemas",
                    "operationId": "get_business",
                    "parameters": [{
                        "name": "business_id", "in": "path", "required": True,
                        "schema": {"type": "string"},
                    }],
                    "responses": {"200": {"description": "Business detail"}},
                }
            },
            "/connector/actions/{business_id}/{action}": {
                "post": {
                    "summary": "Call a business action",
                    "description": ("Executes one action on one business. "
                                    "Actions flagged x-unamused-requires-approval "
                                    "are gated server-side: the first call "
                                    "validates and returns approval_required + "
                                    "a single-use approval_token (10 min); call "
                                    "again with {\"approval_token\": \"...\"} "
                                    "after the human approves to execute."),
                    "operationId": "call_action",
                    "x-unamused-requires-approval": True,
                    "parameters": [
                        {"name": "business_id", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                        {"name": "action", "in": "path", "required": True,
                         "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {
                            "schema": {"type": "object",
                                       "description": "Action parameters"}}},
                    },
                    "responses": {"200": {"description": "Action result"}},
                }
            },
        },
    }


def aggregator_manifest(base_url):
    """The one manifest for the Unamused directory listing."""
    base = base_url.rstrip("/")
    return {
        "name": "Unamused",
        "description": ("Reach every business on Unamused from your AI agent: "
                        "find the business, then book, order, request a quote, "
                        "or contact them."),
        "vendor": "Unamused",
        "vendor_url": "https://unamused.app",
        "openapi_url": base + "/connector/openapi.json",
        "mcp_url": base + "/connector/mcp",
        "auth": {"type": "none"},
        "generated_by": "Unamused (https://unamused.app) — free, MIT",
    }


# ---- Seed demos ----
#
# An empty directory doesn't demo. These three fictional businesses ship
# with the app so the connector's full loop (search -> inspect -> approve
# -> call) works for a first-time visitor. They are clearly marked demo
# everywhere they appear, use example.com URLs, and their webhooks point
# at httpbin.org/post (a public echo service) so calls are harmless.
# Seeded idempotently at startup; deleting the files removes them.

SEED_BUSINESSES = [
    {
        "id": "deadbeef0001",
        "business": "Sunny Smiles Dental (demo)",
        "url": "https://example.com/sunny-smiles",
        "actions": [
            {
                "name": "book_appointment",
                "title": "Book a dental appointment",
                "description": "Book a checkup or cleaning at Sunny Smiles Dental. Demo: no real appointment is made.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Patient's full name"},
                    {"name": "phone_or_email", "type": "string", "required": True, "description": "Patient's phone or email"},
                    {"name": "preferred_time", "type": "string", "required": False, "description": "Preferred date/time"},
                ],
                "channel": {"type": "webhook", "url": "https://httpbin.org/post"},
                "requires_approval": True,
            },
            {
                "name": "request_quote",
                "title": "Request a treatment quote",
                "description": "Ask Sunny Smiles Dental for a treatment price estimate. Demo: returns a sample quote link.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Patient's full name"},
                    {"name": "treatment", "type": "string", "required": True, "description": "Treatment to quote"},
                ],
                "channel": {"type": "link", "url_template": "https://example.com/sunny-smiles/quote?name={name}&treatment={treatment}"},
                "requires_approval": False,
            },
        ],
    },
    {
        "id": "deadbeef0002",
        "business": "Mario's Slice Shop (demo)",
        "url": "https://example.com/marios-slice",
        "actions": [
            {
                "name": "place_order",
                "title": "Order pizza",
                "description": "Place a pickup order at Mario's Slice Shop. Demo: no real order is placed.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Customer's full name"},
                    {"name": "phone_or_email", "type": "string", "required": True, "description": "Customer's phone or email"},
                    {"name": "items", "type": "string", "required": True, "description": "Pizzas and sides to order"},
                ],
                "channel": {"type": "webhook", "url": "https://httpbin.org/post"},
                "requires_approval": True,
            },
            {
                "name": "contact_business",
                "title": "Message the shop",
                "description": "Send a message to Mario's Slice Shop. Demo: goes to the echo service.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Your name"},
                    {"name": "message", "type": "string", "required": True, "description": "Your message"},
                ],
                "channel": {"type": "webhook", "url": "https://httpbin.org/post"},
                "requires_approval": False,
            },
        ],
    },
    {
        "id": "deadbeef0003",
        "business": "Green Thumb Landscaping (demo)",
        "url": "https://example.com/green-thumb",
        "actions": [
            {
                "name": "book_appointment",
                "title": "Book a site visit",
                "description": "Book a free landscaping estimate visit. Demo: no real visit is scheduled.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Customer's full name"},
                    {"name": "phone_or_email", "type": "string", "required": True, "description": "Customer's phone or email"},
                    {"name": "preferred_time", "type": "string", "required": False, "description": "Preferred date/time"},
                ],
                "channel": {"type": "link", "url_template": "https://example.com/green-thumb/book?name={name}&when={preferred_time}"},
                "requires_approval": True,
            },
            {
                "name": "request_quote",
                "title": "Request a quote",
                "description": "Ask Green Thumb Landscaping for a project quote. Demo: goes to the echo service.",
                "params": [
                    {"name": "name", "type": "string", "required": True, "description": "Customer's full name"},
                    {"name": "details", "type": "string", "required": True, "description": "What you want quoted"},
                ],
                "channel": {"type": "webhook", "url": "https://httpbin.org/post"},
                "requires_approval": False,
            },
        ],
    },
]


def ensure_seed_data(data_dir):
    """Write seed demo records that don't exist yet. Idempotent."""
    try:
        os.makedirs(data_dir, exist_ok=True)
    except Exception:
        return
    for seed in SEED_BUSINESSES:
        if not API_ID_RE.match(seed["id"]):
            continue
        path = os.path.join(data_dir, "agentapi-%s.json" % seed["id"])
        if os.path.exists(path):
            continue
        record = {
            "id": seed["id"],
            "business": seed["business"],
            "url": seed["url"],
            "contact_email": "",
            "actions": seed["actions"],
            "webhook_secret": secrets.token_hex(32),
            "demo": True,
            "created_at": utcnow(),
            "version": 1,
        }
        try:
            with open(path, "w") as f:
                json.dump(record, f)
        except Exception:
            pass
