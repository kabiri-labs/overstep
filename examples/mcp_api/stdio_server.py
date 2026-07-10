"""An intentionally-vulnerable **stdio** MCP server for the overstep demo.

Speaks newline-delimited JSON-RPC 2.0 over stdin/stdout (the MCP stdio transport).
Identity is not an HTTP header here — it comes from the ``MCP_TOKEN`` environment
variable the client sets when launching the process, so each overstep subject runs
its own process with its own token.

The tools mirror the HTTP demo: ``read_document`` is BOLA (no owner check),
``list_all_users`` is BFLA (no role check), ``reset_tenant`` is correctly
enforced. Launch is done by overstep; you don't run this by hand.
"""
from __future__ import annotations

import json
import os
import sys

_TOKENS = {
    "alice-token": ("alice", "user"),
    "bob-token": ("bob", "user"),
    "admin-token": ("root", "admin"),
}

_DOCS = {
    "d-alice": {"owner": "alice", "email": "alice@corp.example"},
    "d-bob": {"owner": "bob", "email": "bob@corp.example"},
}

_TOOLS = [
    {"name": "read_document", "description": "Read a document by id",
     "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
     "annotations": {"readOnlyHint": True}},
    {"name": "list_all_users", "description": "List all users (admin only)",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
    {"name": "reset_tenant", "description": "Reset the tenant (admin only)",
     "inputSchema": {"type": "object", "properties": {}},
     "annotations": {"destructiveHint": True, "readOnlyHint": False}},
]


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _text(mid, text: str, is_error: bool = False) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}], "isError": is_error}}


def main() -> None:
    # Identity is fixed for the life of the process — that is the whole point of
    # stdio: the launcher's environment decides who the caller is.
    _, role = _TOKENS.get(os.environ.get("MCP_TOKEN", ""), (None, "anonymous"))

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": mid,
                   "result": {"capabilities": {"tools": {}},
                              "serverInfo": {"name": "overstep-demo-stdio", "version": "1"}}})
        elif method == "notifications/initialized":
            continue  # a notification has no response
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": _TOOLS}})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "read_document":                 # BOLA: no ownership check
                doc = _DOCS.get(args.get("doc_id"))
                if not doc:
                    _send(_text(mid, "not found", is_error=True))
                else:
                    _send(_text(mid, json.dumps({"owner": doc["owner"], "email": doc["email"]})))
            elif name == "list_all_users":              # BFLA: no role check
                _send(_text(mid, json.dumps({"users": ["alice", "bob"]})))
            elif name == "reset_tenant":                # correctly enforced
                if role != "admin":
                    _send(_text(mid, "permission denied", is_error=True))
                else:
                    _send(_text(mid, json.dumps({"status": "reset"})))
            else:
                _send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown tool '{name}'"}})
        else:
            _send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method '{method}'"}})


if __name__ == "__main__":
    main()
