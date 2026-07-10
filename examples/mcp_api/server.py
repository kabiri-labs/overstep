"""An intentionally-vulnerable MCP server (Streamable HTTP) for the overstep demo.

Exposes a single JSON-RPC endpoint at ``/mcp`` speaking a small subset of the
Model Context Protocol: ``initialize``, ``tools/list`` and ``tools/call``. The
tools are deliberately broken so overstep lights up:

* ``read_document(doc_id)`` — **BOLA**: returns any document regardless of who
  owns it. The content carries the owner's email marker, so a cross-owner read is
  a *confirmed* leak.
* ``list_all_users()`` — **BFLA / privilege escalation**: returns every user with
  no role check (should be admin-only).
* ``reset_tenant()`` — correctly enforced: non-admin callers get an ``isError``
  result, so overstep records the negative test as correctly denied (no finding).

Run it with:  python -m uvicorn examples.mcp_api.server:app --port 9000
Then:         overstep run examples/mcp_api/matrix.yaml --out out
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# token -> (subject, role)
_TOKENS = {
    "alice-token": ("alice", "user"),
    "bob-token": ("bob", "user"),
    "admin-token": ("root", "admin"),
}

# doc_id -> owning subject + a unique marker (their email)
_DOCS = {
    "d-alice": {"owner": "alice", "email": "alice@corp.example", "body": "alice's private notes"},
    "d-bob": {"owner": "bob", "email": "bob@corp.example", "body": "bob's private notes"},
}

_TOOLS = [
    {"name": "read_document", "description": "Read a document by id"},
    {"name": "list_all_users", "description": "List all users (admin only)"},
    {"name": "reset_tenant", "description": "Reset the tenant (admin only)", "annotations": {"destructiveHint": True}},
]


def _caller(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    return _TOKENS.get(token, (None, "anonymous"))


def _ok(req_id, result) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code, message) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _text_result(text: str, is_error: bool = False) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


@app.post("/mcp")
async def mcp(request: Request):
    msg = await request.json()
    req_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    _, role = _caller(request)

    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "overstep-demo-mcp", "version": "1"},
        }
        return JSONResponse(_ok(req_id, result), headers={"Mcp-Session-Id": "demo-session"})

    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "tools/list":
        return JSONResponse(_ok(req_id, {"tools": _TOOLS}))

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "read_document":
            # BOLA: no ownership check whatsoever.
            doc = _DOCS.get(args.get("doc_id"))
            if doc is None:
                return JSONResponse(_ok(req_id, _text_result("not found", is_error=True)))
            return JSONResponse(_ok(req_id, _text_result(
                f'{{"doc_id": "{args.get("doc_id")}", "owner": "{doc["owner"]}", '
                f'"email": "{doc["email"]}", "body": "{doc["body"]}"}}'
            )))

        if name == "list_all_users":
            # BFLA: should require admin, but doesn't.
            users = ", ".join(sorted({d["owner"] for d in _DOCS.values()}))
            return JSONResponse(_ok(req_id, _text_result(f'{{"users": "{users}"}}')))

        if name == "reset_tenant":
            # Correctly enforced: only admin may proceed.
            if role != "admin":
                return JSONResponse(_ok(req_id, _text_result("permission denied", is_error=True)))
            return JSONResponse(_ok(req_id, _text_result('{"status": "reset"}')))

        return JSONResponse(_err(req_id, -32601, f"unknown tool '{name}'"))

    return JSONResponse(_err(req_id, -32601, f"unknown method '{method}'"))
