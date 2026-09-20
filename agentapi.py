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

Actions that touch money or commitments should set requires_approval=True;
the flag is surfaced in the OpenAPI spec, the MCP tool annotations, and the
manifest so the agent asks the human before calling.
"""

import ipaddress
import json
import re
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
    import secrets
    return secrets.token_hex(6)


def build_record(business, url, actions, contact_email=""):
    return {
        "id": new_api_id(),
        "business": (business or "").strip()[:120],
        "url": (url or "").strip()[:500],
        "contact_email": (contact_email or "").strip()[:120],
        "actions": actions,
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


def execute_action(record, action_name, params):
    """Run one action through its channel. Returns (ok, result_dict)."""
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
    payload = json.dumps({
        "source": "unamused-agent-api",
        "api_id": record["id"],
        "business": record["business"],
        "action": action_name,
        "params": clean,
        "received_at": utcnow(),
    }).encode("utf-8")
    try:
        host = urllib.parse.urlparse(chan["url"]).hostname or ""
        if not is_public_host(host):
            return False, {"error": "webhook host is not a public address"}
        req = urllib.request.Request(
            chan["url"], data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "Unamused-Agent-API/1.0"},
            method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
        return True, {
            "action": action_name,
            "delivered": True,
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
                                  "(booking/order). Ask the human for approval before calling.")
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


def _rpc_ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _rpc_err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def mcp_handle(record, payload):
    """Handle one JSON-RPC message for the MCP endpoint (stateless)."""
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
                "inputSchema": input_schema(a),
            }
            if a["requires_approval"]:
                tool["annotations"] = {"destructiveHint": True}
                tool["description"] += (" Ask the human for approval before "
                                        "calling this tool.")
            tools.append(tool)
        return _rpc_ok(rid, {"tools": tools})
    if method == "tools/call":
        name = params.get("name", "")
        ok, result = execute_action(record, name, params.get("arguments"))
        text = result.get("message") or ""
        if result.get("handoff_url"):
            text = (text + " " if text else "") + "URL: " + result["handoff_url"]
        if result.get("delivered") and result.get("business_response"):
            text += " Business response: " + result["business_response"][:300]
        if not text:
            text = json.dumps(result)
        if not ok:
            text = "Error: " + result.get("error", "unknown error")
        return _rpc_ok(rid, {
            "content": [{"type": "text", "text": text}],
            "isError": not ok,
        })
    return _rpc_err(rid, -32601, "method not found: %s" % method)
