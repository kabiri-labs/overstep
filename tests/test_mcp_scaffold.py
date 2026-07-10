"""Tests for scaffolding a starter matrix from an MCP server's tools/list."""
import json

import httpx
import yaml

from overstep.loaders.mcp import (
    fetch_tools,
    guess_owner_arg,
    is_mutating,
    load_tools_from_file,
    scaffold_matrix_from_tools,
)
from overstep.matrix import Matrix

_TOOLS = [
    {
        "name": "get_document",
        "description": "Read a document",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
    {"name": "list_widgets", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "delete_record",
        "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}}},
        "annotations": {"destructiveHint": True},
    },
    {"name": "send_email", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}}}},
]


# --- heuristics -------------------------------------------------------------

def test_guess_owner_arg_from_id_like_argument():
    assert guess_owner_arg(_TOOLS[0]) == "doc_id"
    assert guess_owner_arg(_TOOLS[2]) == "record_id"
    assert guess_owner_arg(_TOOLS[1]) is None       # no id-like argument -> function


def test_is_mutating_from_annotations():
    assert is_mutating(_TOOLS[2]) is True            # destructiveHint
    assert is_mutating(_TOOLS[0]) is False           # readOnlyHint


def test_is_mutating_from_name_when_no_annotation():
    assert is_mutating(_TOOLS[3]) is True            # "send_email" -> send
    assert is_mutating(_TOOLS[1]) is False           # "list_widgets" -> read-ish


# --- scaffold output --------------------------------------------------------

def test_scaffold_produces_a_valid_matrix():
    text = scaffold_matrix_from_tools(_TOOLS, server_name="docs", server_url="http://mcp.test/mcp")
    doc = yaml.safe_load(text)
    m = Matrix(**doc)
    assert m.validate_refs() == []
    assert m.server_map()["docs"].url == "http://mcp.test/mcp"


def test_scaffold_maps_object_and_function_and_mutating():
    doc = yaml.safe_load(scaffold_matrix_from_tools(_TOOLS, server_name="docs", server_url="u"))
    by_name = {r["name"]: r for r in doc["resources"]}

    assert by_name["get_document"]["type"] == "object"
    assert by_name["get_document"]["owner_arg"] == "doc_id"
    assert "mutating" not in by_name["get_document"]["call"]

    assert by_name["list_widgets"]["type"] == "function"

    assert by_name["delete_record"]["type"] == "object"
    assert by_name["delete_record"]["call"]["mutating"] is True

    assert by_name["send_email"]["type"] == "function"
    assert by_name["send_email"]["call"]["mutating"] is True


def test_scaffold_policy_defaults():
    doc = yaml.safe_load(scaffold_matrix_from_tools(_TOOLS, server_name="docs", server_url="u"))
    # Object tools default to owner-scope for users; function tools to admin-only.
    assert {"role": "user", "scope": "own"} in doc["policy"]["get_document"]["allow"]
    assert doc["policy"]["list_widgets"]["allow"] == [{"role": "admin"}]


# --- loading tools ----------------------------------------------------------

def test_load_tools_from_file_accepts_shapes(tmp_path):
    p = tmp_path / "tools.json"
    p.write_text(json.dumps({"result": {"tools": _TOOLS}}))
    assert [t["name"] for t in load_tools_from_file(str(p))] == [t["name"] for t in _TOOLS]

    p.write_text(json.dumps({"tools": _TOOLS}))
    assert len(load_tools_from_file(str(p))) == 4

    p.write_text(json.dumps(_TOOLS))
    assert len(load_tools_from_file(str(p))) == 4


def test_fetch_tools_over_http():
    """Operational: initialize + tools/list against an in-process MCP server."""

    def handler(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {}},
                                  headers={"Mcp-Session-Id": "s1"})
        if msg.get("method") == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": _TOOLS}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": "x"}})

    import overstep.loaders.mcp as mcpld

    orig = httpx.Client

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return orig(*a, **kw)

    mcpld.httpx.Client = factory
    try:
        tools = fetch_tools("http://mcp.test/mcp")
    finally:
        mcpld.httpx.Client = orig

    assert [t["name"] for t in tools] == [t["name"] for t in _TOOLS]
