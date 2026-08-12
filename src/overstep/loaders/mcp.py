"""Scaffold a starter matrix from an MCP server's own listings.

Point this at a live MCP server (or a saved response) and it drafts a full
matrix — servers, roles, placeholder subjects, resources and a starter policy —
so adopting overstep for MCP is a couple of edits, not a blank file.

Both halves of the surface are drafted: a ``call`` per entry in ``tools/list``,
and a ``read`` per entry in ``resources/templates/list``. Drafting only the first
would build in the blind spot the resource surface exists to close, since a
server can enforce ownership on every tool and hand the same objects out by URI.

Two things are inferred from each tool:

* **object vs function** — a tool with an id-like argument (``doc_id``, ``*_id``)
  is object-level and gets an ``owner_arg`` (the BOLA surface); everything else is
  function-level. A URI template is read the same way, with the placeholder
  standing in for the argument and ``owner_uri`` for ``owner_arg``.
* **mutating** — from the tool's ``annotations`` (``destructiveHint`` /
  ``readOnlyHint``), falling back to a verb heuristic on the name. Mutating tools
  are marked so ``--read-only`` skips them.

The generated policy is a *guess* (object → user own + admin any; function →
admin only). Review and tighten it — it is a starting point, not a source of truth.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

import httpx
import yaml

from overstep.documents import read_json
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


# A plain RFC 6570 simple-expression placeholder: {name}. Operator forms
# ({+path}, {?query}, {#frag}, {var*}) are matched separately so a template using
# one can be reported rather than silently mis-substituted.
_URI_PARAM_RE = re.compile(r"{([A-Za-z0-9_.-]+)}")
_URI_OPERATOR_RE = re.compile(r"{[^A-Za-z0-9_{}][^}]*}|{[^}]*[*][^}]*}")

# Upper bound on listing pages followed, matching the run transport's own cap.
_MAX_LIST_PAGES = 20


def _norm(name: str) -> str:
    return name.replace("_", "").replace("-", "").lower()


def uri_placeholders(template: str) -> List[str]:
    """The ``{name}`` placeholders in a URI template, in order."""
    return _URI_PARAM_RE.findall(template or "")


def has_uri_operator(template: str) -> bool:
    """Whether a template uses an RFC 6570 operator overstep cannot fill.

    Ownership is written into a URI by plain ``{name}`` substitution, so
    ``{+path}`` or ``{?q}`` would be left in the URI verbatim and the probe would
    reach for an address that does not exist. Better to leave such a template out
    of the scaffold and say so than to draft a resource that cannot work.
    """
    return _URI_OPERATOR_RE.search(template or "") is not None


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


def guess_owner_uri(template: str) -> Optional[str]:
    """The URI-template placeholder that identifies an owned object, or None.

    Same judgement as :func:`guess_owner_arg` makes over a tool's arguments, on
    the other place an object id can live. A template with exactly one
    placeholder needs no judgement — that is the variable part, and therefore the
    surface. With several, an id-like name is the candidate; ``{owner}/{repo}``
    has no single object in it and the scaffold does not pretend otherwise.
    """
    names = uri_placeholders(template)
    for name in names:
        if _norm(name) in _OWNER_HINTS:
            return name
    for name in names:
        low = name.lower()
        if low == "id" or low.endswith("_id") or low.endswith("id"):
            return name
    return names[0] if len(names) == 1 else None


def load_tools_from_file(path: str) -> List[Dict[str, Any]]:
    """Read tools from a saved ``tools/list`` response (several shapes accepted)."""
    return _from_file(path, "MCP tools file", "tools")


def load_resource_templates_from_file(path: str) -> List[Dict[str, Any]]:
    """Read templates from a saved ``resources/templates/list`` response.

    The same file may hold both listings — a hand-assembled capture of what a
    server exposes — so a document with only ``tools`` yields no templates rather
    than an error.
    """
    return _from_file(path, "MCP tools file", "resourceTemplates")


def _from_file(path: str, role: str, key: str) -> List[Dict[str, Any]]:
    """Pull one listing out of a saved JSON-RPC response, envelope or bare."""
    data = read_json(path, role)
    if isinstance(data, list):
        # A bare array is only meaningful as the listing the caller asked for;
        # for anything else it says nothing, so it is not claimed twice.
        return data if key == "tools" else []
    if isinstance(data, dict):
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get(key), list):
            return result[key]
        if isinstance(data.get(key), list):
            return data[key]
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
    return _fetch_list(
        url, "tools/list", "tools",
        token=token, headers=headers, protocol_version=protocol_version,
        timeout=timeout, verify=verify,
    )


def fetch_resource_templates(
    url: str,
    *,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    protocol_version: str = "2025-06-18",
    timeout: float = 15.0,
    verify: bool = True,
) -> List[Dict[str, Any]]:
    """Fetch a live MCP server's URI templates via ``resources/templates/list``.

    Best-effort: a server exposing no resources answers with a JSON-RPC error or
    an empty result, and either way the answer is "none". Not supporting the
    method is not a scaffolding failure — it means there is no resource surface
    to draft.
    """
    return _fetch_list(
        url, "resources/templates/list", "resourceTemplates",
        token=token, headers=headers, protocol_version=protocol_version,
        timeout=timeout, verify=verify,
    )


def _fetch_list(
    url: str,
    method: str,
    result_key: str,
    *,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    protocol_version: str = "2025-06-18",
    timeout: float = 15.0,
    verify: bool = True,
) -> List[Dict[str, Any]]:
    """One ``initialize`` handshake followed by one listing call."""
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
            # Complete the lifecycle before asking anything, so a server that
            # enforces it answers the listing instead of refusing it.
            client.post(
                url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=hdrs,
            )
        except httpx.HTTPError:
            pass

        # Listings paginate. Reading only the first page would understate the
        # surface — and this number is a denominator: `coverage --fail-under`
        # would count a tool or template on page two as one that does not exist,
        # and report a matrix as complete while part of the server went
        # undeclared. Bounded and cycle-safe, so a server whose cursor never
        # terminates cannot hold the run open.
        listed: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        seen: set = set()
        for _ in range(_MAX_LIST_PAGES):
            params: Dict[str, Any] = {"cursor": cursor} if cursor else {}
            resp = client.post(
                url,
                json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params},
                headers=hdrs,
            )
            message = _parse_message(resp)
            result = message.get("result") if isinstance(message, dict) else None
            if not isinstance(result, dict):
                # A server that does not support the method answers with an
                # error, which is the same answer as "none": there is nothing
                # of this kind to read.
                break
            page = result.get(result_key)
            if isinstance(page, list):
                listed.extend(page)
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                break
            seen.add(cursor)
        return listed


def _template_entry(
    template: Dict[str, Any],
    *,
    server_name: str,
    taken: set,
    owner_attrs: set,
) -> Optional[Dict[str, Any]]:
    """Draft one resource-read from a ``resources/templates/list`` entry."""
    uri = template.get("uriTemplate")
    if not uri:
        return None

    placeholders = uri_placeholders(uri)
    name = template.get("name") or _slugify(uri)
    # A tool and a template may share a name; the matrix needs one key per
    # resource, and reusing the tool's would silently drop one of the two.
    if name in taken:
        name = f"{name}_resource"
    if name in taken:
        return None

    entry: Dict[str, Any] = {
        "name": name,
        "transport": "mcp",
        "read": {"server": server_name, "uri": uri},
        "type": "object" if placeholders else "function",
    }

    owner_uri = guess_owner_uri(uri)
    if owner_uri is not None:
        entry["owner_uri"] = owner_uri
        entry["owner_attr"] = owner_uri
        owner_attrs.add(owner_uri)
    elif placeholders:
        # Several placeholders and no obvious object among them — {owner}/{repo}
        # rather than {doc_id}. Every one still has to be filled or the URI goes
        # out with a literal brace in it, so each becomes its own injection
        # sourced from its own subject attribute, and the author decides which
        # of them is the thing being owned.
        entry["ownership"] = {
            "injections": [
                {"location": "mcp_resource_uri", "selector": p, "owner_attr": p}
                for p in placeholders
            ]
        }
        owner_attrs.update(placeholders)
    if template.get("description"):
        entry["description"] = template["description"]
    return entry


def _slugify(uri: str) -> str:
    """A resource name for a template that did not carry one."""
    slug = re.sub(r"[^a-z0-9]+", "_", uri.lower()).strip("_")
    return f"read_{slug}" if slug else "read_resource"


def scaffold_matrix_from_tools(
    tools: List[Dict[str, Any]],
    *,
    server_name: str = "mcp",
    server_url: str = "http://localhost:8000/mcp",
    templates: Optional[List[Dict[str, Any]]] = None,
    warn: Optional[Callable[[str], None]] = None,
) -> str:
    """Render a full starter matrix YAML from an MCP server's tools and templates.

    Both halves of the surface are drafted: a ``call`` per tool, and a ``read``
    per URI template. Testing only tools leaves a server free to enforce
    ownership on every tool and hand the same objects out through
    ``resources/read``, so a scaffold that drafted only the first would build in
    that blind spot from the start.
    """
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

    taken = {r["name"] for r in resources}
    for template in templates or []:
        uri = template.get("uriTemplate") or ""
        if has_uri_operator(uri):
            # Ownership is written into a URI by plain {name} substitution, so an
            # RFC 6570 operator would survive into the request and the probe
            # would reach for an address that does not exist. Say so rather than
            # draft a resource that cannot work.
            if warn is not None:
                warn(
                    f"resource template '{uri}' uses an RFC 6570 operator, which "
                    f"overstep cannot substitute — declare it by hand with a plain "
                    f"{{placeholder}} URI if it is worth testing"
                )
            continue
        entry = _template_entry(
            template, server_name=server_name, taken=taken, owner_attrs=owner_attrs
        )
        if entry is None:
            continue
        taken.add(entry["name"])
        resources.append(entry)
        # Reads are never mutating, so the starter policy is the object one: an
        # owner may read their own, an admin anyone's.
        policy[entry["name"]] = (
            {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]}
            if entry["type"] == "object"
            else {"allow": [{"role": "admin"}]}
        )

    # Two user subjects, not one: a cross-owner (BOLA) probe only exists when two
    # subjects own *different* objects, so a single placeholder user would
    # scaffold a matrix that cannot exercise the tool's headline check. The
    # suffixed placeholders say the two must not be filled in with the same id.
    def _user(index: int) -> Dict[str, Any]:
        subject: Dict[str, Any] = {
            "name": f"user{index}",
            "role": "user",
            "token": f"PASTE_USER{index}_TOKEN",
        }
        if owner_attrs:
            subject["attributes"] = {a: f"REPLACE_ME_{index}" for a in sorted(owner_attrs)}
        return subject

    matrix = {
        "roles": ["anonymous", "user", "admin"],
        "servers": [{"name": server_name, "url": server_url}],
        "mcp_access": {"is_error_is_deny": True, "jsonrpc_error_is_deny": True},
        "subjects": [
            {"name": "anon", "role": "anonymous", "token": None},
            _user(1),
            _user(2),
            {"name": "admin1", "role": "admin", "token": "PASTE_ADMIN_TOKEN"},
        ],
        "resources": resources,
        "policy": policy,
    }
    return yaml.safe_dump(matrix, sort_keys=False, allow_unicode=True)
