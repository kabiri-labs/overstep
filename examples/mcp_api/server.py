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

It also serves MCP *resources* at ``doc://acme/{doc_id}`` via ``resources/read``,
with the same missing ownership check — the second door onto the same documents,
and the reason testing only tools is not enough.

Two more defects live in the protocol layer rather than in any one tool, so that
the demo exercises the transport-level probes too:

* **session-hijack** — ``initialize`` issues an ``Mcp-Session-Id`` to an
  authenticated caller, and every later request accepts that id *in place of* a
  credential. The MCP spec forbids exactly this: session ids travel in headers,
  and whoever picks one up inherits the identity that opened it.
* **tool-enumeration** — ``tools/list`` requires a credential but not a role, so
  every authenticated caller is shown the admin-only tools they may not invoke.

Because listing now requires a credential, scaffolding against this server needs
one:  ``overstep scaffold mcp --url ... --token alice-token``.

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
    {
        "name": "read_document",
        "description": "Read a document by id",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "list_all_users",
        "description": "List all users (admin only)",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "reset_tenant",
        "description": "Reset the tenant (admin only)",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"destructiveHint": True, "readOnlyHint": False},
    },
    {
        "name": "create_document",
        "description": "Create a document owned by the caller",
        "inputSchema": {"type": "object", "properties": {"body": {"type": "string"}}},
        "annotations": {"readOnlyHint": False},
    },
    {
        "name": "delete_document",
        "description": "Delete a document by id",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        "annotations": {"destructiveHint": True},
    },
]


# session id -> (subject, role), populated by `initialize`
_SESSIONS: Dict[str, Any] = {}


def _caller(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    if token in _TOKENS:
        return _TOKENS[token]
    # The session-binding defect: an `Mcp-Session-Id` is accepted as proof of
    # identity, so anyone who reads one out of a log or a proxy becomes its owner.
    session = request.headers.get("mcp-session-id", "")
    if session in _SESSIONS:
        return _SESSIONS[session]
    return (None, "anonymous")


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
    subject, role = _caller(request)

    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "overstep-demo-mcp", "version": "1"},
        }
        # Only a caller who proved who they are gets a session — an anonymous
        # handshake yields nothing worth stealing. That is what makes the reuse
        # below a hijack rather than an endpoint that was open all along.
        headers = {}
        if subject is not None:
            session = f"sess-{subject}"
            _SESSIONS[session] = (subject, role)
            headers["Mcp-Session-Id"] = session
        return JSONResponse(_ok(req_id, result), headers=headers)

    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "tools/list":
        if subject is None:
            return JSONResponse(_err(req_id, -32001, "authentication required"), status_code=401)
        # Authenticated, but no role check: `list_all_users` and `reset_tenant`
        # are advertised to everyone, including the users who cannot call them.
        return JSONResponse(_ok(req_id, {"tools": _TOOLS}))

    if method == "resources/templates/list":
        if subject is None:
            return JSONResponse(_err(req_id, -32001, "authentication required"), status_code=401)
        return JSONResponse(_ok(req_id, {"resourceTemplates": [{
            "uriTemplate": "doc://acme/{doc_id}",
            "name": "document",
            "mimeType": "text/plain",
        }]}))

    if method == "resources/read":
        # BOLA again, through the other door: any URI, for any caller.
        uri = params.get("uri") or ""
        doc = _DOCS.get(uri.removeprefix("doc://acme/"))
        if doc is None:
            return JSONResponse(_err(req_id, -32002, f"resource not found: {uri}"))
        return JSONResponse(_ok(req_id, {"contents": [{
            "uri": uri,
            "mimeType": "text/plain",
            "text": f'{{"owner": "{doc["owner"]}", "email": "{doc["email"]}", '
                    f'"body": "{doc["body"]}"}}',
        }]}))

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

        if name == "create_document":
            # A fixture-creating tool: mint a new document owned by the caller and
            # return its id (used by setup steps to seed real BOLA objects).
            new_id = f"d-{len(_DOCS) + 1}"
            _DOCS[new_id] = {
                "owner": subject or "anon",
                "email": f"{subject or 'anon'}@corp.example",
                "body": args.get("body", ""),
            }
            return JSONResponse(_ok(req_id, _text_result(f'{{"id": "{new_id}"}}')))

        if name == "delete_document":
            _DOCS.pop(args.get("doc_id"), None)
            return JSONResponse(_ok(req_id, _text_result('{"status": "deleted"}')))

        return JSONResponse(_err(req_id, -32601, f"unknown tool '{name}'"))

    return JSONResponse(_err(req_id, -32601, f"unknown method '{method}'"))
