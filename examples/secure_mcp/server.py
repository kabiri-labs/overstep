"""A correctly-authorizing MCP server (Streamable HTTP) — the mirror of the broken one.

``examples/mcp_api`` exists so you can watch overstep light up on this surface.
This one exists so you can watch it stay dark *for the right reason*: a clean MCP
result is also what an unreachable server, a rejected credential and an
all-skipped suite produce, and only one of those is worth anything.

Same endpoint, same tools, same documents as the vulnerable demo. Every defect
that one ships is fixed here, one per probe the matrix and the protocol generate:

* ``read_document(doc_id)`` — **ownership enforced**. A user reads only their own
  document; an admin reads any. The cross-owner probe is refused.
* ``doc://acme/{doc_id}`` via ``resources/read`` — **the same check on the second
  door**, which is the whole reason the broken demo has two.
* ``list_all_users()`` and ``reset_tenant()`` — **admin only**, enforced at call
  time.
* ``tools/list`` — **filtered by role**, so the privileged half of the catalogue
  is not advertised to callers who may not invoke it.
* ``Mcp-Session-Id`` — **never authenticates**. The spec is explicit about this:
  session ids travel in headers, and headers leak. Every request must carry its
  own credential, and a session id issued to one identity is refused on another's
  request. A credential-free request holding a stolen session id gets a ``401``.

Run it with:  python -m uvicorn examples.secure_mcp.server:app --port 9010
Then:         overstep run examples/secure_mcp/matrix.yaml --out out

Expect zero vulnerabilities and exit 0 — and, the part that makes the zero mean
something, a conclusive run with every expected-allow test allowed.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

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
        "description": "Read a document you own",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
        # Not part of MCP: this server's own note of who may invoke the tool, so
        # the listing and the call-time check cannot drift apart. A real server
        # would read this from whatever its policy actually is.
        "_roles": {"user", "admin"},
    },
    {
        "name": "list_all_users",
        "description": "List all users (admin only)",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
        "_roles": {"admin"},
    },
    {
        "name": "reset_tenant",
        "description": "Reset the tenant (admin only)",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"destructiveHint": True, "readOnlyHint": False},
        "_roles": {"admin"},
    },
]

# session id -> the subject it was issued to. Used to *bind* a session to its
# owner, never to identify a caller: the value of this map is what lets the
# server refuse a session id presented on somebody else's request.
_SESSIONS: Dict[str, str] = {}


def _authenticate(request: Request) -> Tuple[Optional[str], str]:
    """Resolve the caller from the credential, and from nothing else.

    The vulnerable demo falls back to the ``Mcp-Session-Id`` header here, which
    is the session-binding defect in one line: an identifier that travels in a
    header becomes proof of identity, so whoever reads one out of a log, a proxy
    or a referrer inherits the identity that opened it.
    """
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    if token in _TOKENS:
        return _TOKENS[token]
    return (None, "anonymous")


def _session_mismatch(request: Request, subject: str) -> bool:
    """Is this request carrying a session that belongs to somebody else?

    Binding the session to the identity that opened it is the other half of not
    authenticating with it. A server that merely ignores the header still lets a
    stolen id ride along harmlessly; one that refuses it cannot be confused about
    whose conversation this is.
    """
    session = request.headers.get("mcp-session-id", "")
    return bool(session) and _SESSIONS.get(session, subject) != subject


def _ok(req_id, result) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code, message) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _denied(req_id, message: str = "permission denied") -> Dict[str, Any]:
    """An in-band refusal: the shape a tool-level denial has to take.

    There is no 403 on this surface — a refusal arrives as ``isError`` on the
    result or as a JSON-RPC error — which is why the matrix has to say which of
    those means denied.
    """
    return _ok(req_id, {"content": [{"type": "text", "text": message}], "isError": True})


def _text_result(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _unauthorized(req_id):
    """The HTTP-leg refusal, for a request that carries no usable identity.

    A 401 with a body that is not a JSON-RPC message is exactly what the spec
    describes and what many frameworks send, and it carries no in-band deny
    signal at all — which is why a matrix for this server declares `deny_status`.
    Without it, the servers that reject *before* dispatching are the ones a run
    would report wide open.
    """
    return JSONResponse(_err(req_id, -32001, "authentication required"), status_code=401)


@app.post("/mcp")
async def mcp(request: Request):
    msg = await request.json()
    req_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    subject, role = _authenticate(request)

    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "overstep-demo-mcp-secure", "version": "1"},
        }
        # A session id is still issued, so the binding probe has something to
        # try: a server that issues none is recorded as skipped, which is not
        # the same statement as a server that issues one and refuses to let it
        # authenticate.
        headers = {}
        if subject is not None:
            session = f"sess-{subject}"
            _SESSIONS[session] = subject
            headers["Mcp-Session-Id"] = session
        return JSONResponse(_ok(req_id, result), headers=headers)

    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    # Everything past the handshake needs a credential of its own. A session id
    # is not one, and one belonging to another identity is refused outright.
    if subject is None or _session_mismatch(request, subject):
        return _unauthorized(req_id)

    if method == "tools/list":
        # Filtered, not wholesale: a caller is shown what it may invoke. Listing
        # everything and enforcing at call time is a defensible design, but then
        # the catalogue discloses the shape of the privileged surface, which is
        # what the enumeration probe asks about.
        return JSONResponse(_ok(req_id, {"tools": [
            {k: v for k, v in tool.items() if not k.startswith("_")}
            for tool in _TOOLS
            if role in tool["_roles"]
        ]}))

    if method == "resources/templates/list":
        return JSONResponse(_ok(req_id, {"resourceTemplates": [{
            "uriTemplate": "doc://acme/{doc_id}",
            "name": "document",
            "mimeType": "text/plain",
        }]}))

    if method == "resources/read":
        uri = params.get("uri") or ""
        doc_id = uri.removeprefix("doc://acme/")
        doc = _DOCS.get(doc_id)
        if doc is None:
            return JSONResponse(_err(req_id, -32002, f"resource not found: {uri}"))
        # The same ownership check as the tool. The broken demo omits it here and
        # nowhere else, which is the case a tools-only matrix reports clean.
        if role != "admin" and doc["owner"] != subject:
            return JSONResponse(_err(req_id, -32003, "permission denied"))
        return JSONResponse(_ok(req_id, {"contents": [{
            "uri": uri,
            "mimeType": "text/plain",
            "text": f'{{"owner": "{doc["owner"]}", "email": "{doc["email"]}", '
                    f'"body": "{doc["body"]}"}}',
        }]}))

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}

        tool = next((t for t in _TOOLS if t["name"] == name), None)
        if tool is None:
            return JSONResponse(_err(req_id, -32601, f"unknown tool '{name}'"))
        # The call-time check, which is the one that matters: a tool missing from
        # this caller's listing must still be refused when asked for by name.
        if role not in tool["_roles"]:
            return JSONResponse(_denied(req_id))

        if name == "read_document":
            doc = _DOCS.get(args.get("doc_id"))
            if doc is None:
                return JSONResponse(_denied(req_id, "not found"))
            if role != "admin" and doc["owner"] != subject:
                return JSONResponse(_denied(req_id))
            return JSONResponse(_ok(req_id, _text_result(
                f'{{"doc_id": "{args.get("doc_id")}", "owner": "{doc["owner"]}", '
                f'"email": "{doc["email"]}", "body": "{doc["body"]}"}}'
            )))

        if name == "list_all_users":
            users = ", ".join(sorted({d["owner"] for d in _DOCS.values()}))
            return JSONResponse(_ok(req_id, _text_result(f'{{"users": "{users}"}}')))

        if name == "reset_tenant":
            return JSONResponse(_ok(req_id, _text_result('{"status": "reset"}')))

    return JSONResponse(_err(req_id, -32601, f"unknown method '{method}'"))
