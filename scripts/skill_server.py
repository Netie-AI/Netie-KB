#!/usr/bin/env python3
"""Netie-KB skill server - the one registry, served over MCP + REST.

Serves the same corpus kb.py reads (rules, workflows, findings, attacks,
skills). Read-only. Stdlib only (plus PyYAML, which kb.py already needs),
so any box or container that clones the KB can run it:

    python scripts/skill_server.py --host 127.0.0.1 --port 8030

Endpoints:
    GET  /healthz          liveness + artifact counts (never auth-gated)
    GET  /search?q=&kind=  REST search for curl / containers
    GET  /item/<ID>        full markdown of one artifact (e.g. /item/R-0015)
    POST /mcp              MCP streamable-HTTP JSON-RPC endpoint
                           (initialize, ping, tools/list, tools/call)

MCP tools: kb_search, kb_show, kb_list.

Auth: set NETIE_KB_TOKEN to require "Authorization: Bearer <token>" on every
endpoint except /healthz. Required before binding to anything but loopback.

Register with Claude Code (all projects):
    claude mcp add netie-kb --scope user --transport http http://127.0.0.1:8030/mcp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import kb  # noqa: E402  (same-dir import, reuses the canonical corpus parser)
from stdio_utf8 import ensure_utf8_stdio  # noqa: E402

SERVER_NAME = "netie-kb"
SERVER_VERSION = "1.0.0"
KNOWN_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
LATEST_PROTOCOL = "2025-06-18"
KINDS = sorted(kb.KIND_DIRS)

INSTRUCTIONS = (
    "Netie-KB skill registry (rules, workflows, findings, attacks, skills). "
    "Search here before authoring or re-deriving anything (R-0016). Read-only; "
    "new artifacts land via kb.py new + git push, never through this server."
)


# ---------------------------------------------------------------- corpus ----

def _artifacts():
    return kb.iter_artifacts()


def _brief(art) -> dict:
    return {
        "id": art.id,
        "kind": art.meta.get("kind"),
        "title": art.meta.get("title"),
        "status": art.meta.get("status"),
        "severity": art.meta.get("severity"),
        "tags": list(art.meta.get("tags", [])),
    }


def _line(art, score=None) -> str:
    head = f"{art.id} [{art.meta.get('status')}] ({art.meta.get('severity')})"
    if score is not None:
        head += f" score={score}"
    return f"{head} - {art.meta.get('title')}"


def do_search(query: str, kind: str | None, limit: int, include_unverified: bool):
    results = []
    for art in _artifacts():
        if kind and art.meta.get("kind") != kind:
            continue
        if not include_unverified and art.meta.get("status") == "unverified":
            continue
        score = kb.search_score(art, query, [])
        if query and score == 0:
            continue
        results.append((score, art))
    results.sort(
        key=lambda x: (
            -x[0],
            kb.SEVERITY_ORDER.get(str(x[1].meta.get("severity")), 9),
            x[1].id,
        )
    )
    return results[: max(1, min(limit, 100))]


def do_show(target: str):
    target = target.strip().upper()
    for art in _artifacts():
        if art.id == target:
            return art
    return None


def do_list(kind: str | None):
    arts = [a for a in _artifacts() if not kind or a.meta.get("kind") == kind]
    arts.sort(key=lambda a: a.id)
    return arts


def counts() -> dict:
    out: dict[str, int] = {k: 0 for k in KINDS}
    for art in _artifacts():
        k = str(art.meta.get("kind"))
        out[k] = out.get(k, 0) + 1
    out["total"] = sum(v for k, v in out.items() if k != "total")
    return out


# ------------------------------------------------------------------- MCP ----

TOOLS = [
    {
        "name": "kb_search",
        "description": (
            "Search the Netie-KB corpus (rules, workflows, findings, attacks, "
            "skills). Use before authoring or re-deriving anything."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "keywords"},
                "kind": {"type": "string", "enum": KINDS},
                "limit": {"type": "integer", "default": 10},
                "include_unverified": {"type": "boolean", "default": False},
            },
            "required": ["query"],
        },
    },
    {
        "name": "kb_show",
        "description": "Fetch one artifact's full markdown by id (e.g. R-0015, W-0001, S-0001).",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "artifact id"}},
            "required": ["id"],
        },
    },
    {
        "name": "kb_list",
        "description": "List corpus artifacts, optionally filtered to one kind.",
        "inputSchema": {
            "type": "object",
            "properties": {"kind": {"type": "string", "enum": KINDS}},
        },
    },
]


def _tool_text(name: str, args: dict) -> str:
    if name == "kb_search":
        hits = do_search(
            str(args.get("query", "")),
            args.get("kind"),
            int(args.get("limit", 10)),
            bool(args.get("include_unverified", False)),
        )
        if not hits:
            return "no matches"
        return "\n".join(_line(a, s) for s, a in hits)
    if name == "kb_show":
        art = do_show(str(args.get("id", "")))
        if art is None:
            raise ValueError(f"not found: {args.get('id')}")
        return art.path.read_text(encoding="utf-8")
    if name == "kb_list":
        arts = do_list(args.get("kind"))
        if not arts:
            return "empty"
        return "\n".join(_line(a) for a in arts)
    raise ValueError(f"unknown tool: {name}")


def handle_rpc(msg: dict) -> dict | None:
    """One JSON-RPC message in, one response dict out (None for notifications)."""
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") or {}

    def ok(result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    if msg_id is None:
        return None  # notification (e.g. notifications/initialized) - no reply

    if method == "initialize":
        asked = str(params.get("protocolVersion", LATEST_PROTOCOL))
        version = asked if asked in KNOWN_PROTOCOLS else LATEST_PROTOCOL
        return ok(
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "title": "Netie-KB skill registry",
                    "version": SERVER_VERSION,
                },
                "instructions": INSTRUCTIONS,
            }
        )
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        try:
            text = _tool_text(name, args)
            return ok({"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:  # noqa: BLE001 - surface as tool error, keep serving
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
    return err(-32601, f"method not found: {method}")


# ------------------------------------------------------------------ HTTP ----

class Handler(BaseHTTPRequestHandler):
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=True, indent=1).encode(), "application/json")

    def _authed(self) -> bool:
        token = os.environ.get("NETIE_KB_TOKEN", "")
        if not token:
            return True
        got = self.headers.get("Authorization", "")
        return got == f"Bearer {token}"

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        if url.path == "/healthz":
            self._json(200, {"ok": True, "service": SERVER_NAME, "counts": counts()})
            return
        if not self._authed():
            self._json(401, {"error": "missing or bad bearer token"})
            return
        if url.path == "/":
            self._json(200, {
                "service": SERVER_NAME,
                "mcp": "POST /mcp",
                "rest": ["/healthz", "/search?q=&kind=&limit=", "/item/<ID>"],
                "rule": "R-0016: search here before re-deriving",
            })
            return
        if url.path == "/search":
            q = parse_qs(url.query)
            hits = do_search(
                (q.get("q") or [""])[0],
                (q.get("kind") or [None])[0],
                int((q.get("limit") or ["10"])[0]),
                (q.get("include_unverified") or ["0"])[0] in ("1", "true"),
            )
            self._json(200, [dict(_brief(a), score=s) for s, a in hits])
            return
        if url.path.startswith("/item/"):
            art = do_show(url.path.split("/item/", 1)[1])
            if art is None:
                self._json(404, {"error": "not found"})
                return
            self._send(200, art.path.read_text(encoding="utf-8").encode(), "text/markdown; charset=utf-8")
            return
        if url.path == "/mcp":
            self._send(405, b"POST JSON-RPC here", "text/plain")
            return
        self._json(404, {"error": "unknown path"})

    def do_POST(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        if url.path not in ("/mcp", "/"):
            self._json(404, {"error": "unknown path"})
            return
        if not self._authed():
            self._json(401, {"error": "missing or bad bearer token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            msg = json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}})
            return
        if isinstance(msg, list):  # legacy batch - answer each
            replies = [r for r in (handle_rpc(m) for m in msg if isinstance(m, dict)) if r]
            if replies:
                self._json(200, replies)
            else:
                self._send(202, b"", "application/json")
            return
        if not isinstance(msg, dict):
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "invalid request"}})
            return
        reply = handle_rpc(msg)
        if reply is None:
            self._send(202, b"", "application/json")
        else:
            self._json(200, reply)

    def do_DELETE(self) -> None:  # noqa: N802 - stateless server, session delete is a no-op
        self._send(202, b"", "application/json")

    def log_message(self, fmt: str, *args) -> None:  # one quiet line per request
        print(f"[{SERVER_NAME}] {self.address_string()} {fmt % args}", file=sys.stderr)


def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="Netie-KB skill server (MCP + REST)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8030)
    args = ap.parse_args()

    token = os.environ.get("NETIE_KB_TOKEN", "")
    if args.host not in ("127.0.0.1", "localhost") and not token:
        print(
            "WARNING: binding beyond loopback with no NETIE_KB_TOKEN set - "
            "the corpus would be public. Set the token first.",
            file=sys.stderr,
        )

    c = counts()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"{SERVER_NAME} {SERVER_VERSION} on http://{args.host}:{args.port} "
        f"(mcp=/mcp, corpus={c['total']}: "
        + ", ".join(f"{k}={c[k]}" for k in KINDS)
        + (", auth=bearer" if token else ", auth=OFF (loopback)")
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
