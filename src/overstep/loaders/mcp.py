"""Scaffold a starter matrix from an MCP server's ``tools/list``.

Point this at a live MCP server (or a saved ``tools/list`` response) and it drafts
a full matrix — servers, roles, placeholder subjects, resources and a starter
policy — so adopting overstep for MCP is a couple of edits, not a blank file.

Two things are inferred from each tool:

* **object vs function** — a tool with an id-like argument (``doc_id``, ``*_id``)
  is object-level and gets an ``owner_arg`` (the BOLA surface); everything else is
  function-level.
* **mutating** — from the tool's ``annotations`` (``destructiveHint`` /
  ``readOnlyHint``), falling back to a verb heuristic on the name. Mutating tools
  are marked so ``--read-only`` skips them.

The generated policy is a *guess* (object → user own + admin any; function →
admin only). Review and tighten it — it is a starting point, not a source of truth.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

import httpx
import yaml

from overstep.transports.mcp import _parse_message

# Argument names that identify an owned object.
_OWNER_HINTS = {
    "id", "userid", "user_id", "accountid", "account_id", "orderid", "order_id",
    "docid", "doc_id", "documentid", "document_id", "ticketid", "ticket_id",
    "recordid", "record_id", "objectid", "object_id", "resourceid", "resource_id",
    "itemid", "item_id", "fileid", "file_id", "tenantid", "tenant_id",
    "orgid", "org_id", "customerid", "customer_id",
}

# Verb tokens that suggest a tool changes state (name-based fallback).
_MUTATING_WORDS = {
    "create", "delete", "update", "write", "reset", "send", "set", "remove",
    "add", "put", "patch", "post", "execute", "run", "purge", "revoke", "grant",
    "modify", "cancel", "approve", "reject", "publish", "upload", "insert", "drop",
}


def _norm(name: str) -> str:
    return name.replace("_", "").replace("-", "").lower()


def _tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]


def guess_owner_arg(tool: Dict[str, Any]) -> Optional[str]:
    """The tool argument that identifies an owned object, or None (function)."""
    props = ((tool.get("inputSchema") or {}).get("properties")) or {}
    keys = list(props.keys())
    for key in keys:
        if _norm(key) in _OWNER_HINTS:
            return key
    # Fall back to any argument that looks like an id.
    for key in keys:
        low = key.lower()
        if low == "id" or low.endswith("_id") or low.endswith("id"):
            return key
    return None


def is_mutating(tool: Dict[str, Any]) -> bool:
    """Whether a tool changes state — from annotations, then a name heuristic."""
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint") is True:
        return True
    if ann.get("readOnlyHint") is True:
        return False
    if ann.get("readOnlyHint") is False:
        return True
    return any(tok in _MUTATING_WORDS for tok in _tokens(tool.get("name", "")))


def load_tools_from_file(path: str) -> List[Dict[str, Any]]:
    """Read tools from a saved ``tools/list`` response (several shapes accepted)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return result["tools"]
        if isinstance(data.get("tools"), list):
            return data["tools"]
    return []


def fetch_tools(
    url: str,
    *,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    protocol_version: str = "2025-06-18",
    timeout: float = 15.0,
    verify: bool = True,
) -> List[Dict[str, Any]]:
    """Fetch a live MCP server's tools via ``initialize`` + ``tools/list``."""
    hdrs: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": protocol_version,
    }
    if headers:
        hdrs.update(headers)
    if token and not any(k.lower() == "authorization" for k in hdrs):
        hdrs["Authorization"] = f"Bearer {token}"

    with httpx.Client(timeout=timeout, verify=verify) as client:
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": protocol_version, "capabilities": {},
                       "clientInfo": {"name": "overstep", "version": "1"}},
        }
        try:
            resp = client.post(url, json=init, headers=hdrs)
            session = resp.headers.get("mcp-session-id")
            if session:
                hdrs["Mcp-Session-Id"] = session
        except httpx.HTTPError:
            pass

        resp = client.post(
            url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, headers=hdrs
        )
        message = _parse_message(resp)
        result = message.get("result") if isinstance(message, dict) else None
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools or []


def scaffold_matrix_from_tools(
    tools: List[Dict[str, Any]],
    *,
    server_name: str = "mcp",
    server_url: str = "http://localhost:8000/mcp",
) -> str:
    """Render a full starter matrix YAML from a list of MCP tools."""
    resources: List[Dict[str, Any]] = []
    policy: Dict[str, Any] = {}
    owner_attrs: set = set()

    for tool in tools:
        name = tool.get("name")
        if not name:
            continue
        owner_arg = guess_owner_arg(tool)
        is_object = owner_arg is not None

        call: Dict[str, Any] = {"server": server_name, "tool": name}
        if is_mutating(tool):
            call["mutating"] = True

        entry: Dict[str, Any] = {
            "name": name,
            "transport": "mcp",
            "call": call,
            "type": "object" if is_object else "function",
        }
        if is_object:
            entry["owner_arg"] = owner_arg
            entry["owner_attr"] = owner_arg
            owner_attrs.add(owner_arg)
        if tool.get("description"):
            entry["description"] = tool["description"]
        resources.append(entry)

        if is_object:
            policy[name] = {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]}
        else:
            policy[name] = {"allow": [{"role": "admin"}]}

    user_subject: Dict[str, Any] = {"name": "user1", "role": "user", "token": "PASTE_USER_TOKEN"}
    if owner_attrs:
        user_subject["attributes"] = {a: "REPLACE_ME" for a in sorted(owner_attrs)}

    matrix = {
        "roles": ["anonymous", "user", "admin"],
        "servers": [{"name": server_name, "url": server_url}],
        "mcp_access": {"is_error_is_deny": True, "jsonrpc_error_is_deny": True},
        "subjects": [
            {"name": "anon", "role": "anonymous", "token": None},
            user_subject,
            {"name": "admin1", "role": "admin", "token": "PASTE_ADMIN_TOKEN"},
        ],
        "resources": resources,
        "policy": policy,
    }
    return yaml.safe_dump(matrix, sort_keys=False, allow_unicode=True)
