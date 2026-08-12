"""Tests for scaffolding a starter matrix from an MCP server's tools/list."""
import json

import httpx
import pytest
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


def test_scaffold_emits_two_distinct_user_subjects():
    """A cross-owner probe needs two subjects owning different objects, so a
    single placeholder user would scaffold a matrix that cannot test BOLA."""
    doc = yaml.safe_load(
        scaffold_matrix_from_tools(_TOOLS, server_name="docs", server_url="http://mcp.test/mcp")
    )

    users = [s for s in doc["subjects"] if s["role"] == "user"]
    assert len(users) == 2
    ids = [tuple(sorted(s.get("attributes", {}).items())) for s in users]
    assert ids[0] != ids[1], "both users carry the same placeholder object id"
    assert len({s["token"] for s in users}) == 2


# --- resource templates -----------------------------------------------------

_TEMPLATES = [
    {"uriTemplate": "doc://acme/{doc_id}", "name": "document", "mimeType": "text/plain"},
    {"uriTemplate": "config://settings", "name": "settings"},
    {"uriTemplate": "repo://{owner}/{repo}/tree", "name": "tree",
     "description": "A repository tree"},
]


def test_guess_owner_uri_prefers_an_id_like_placeholder():
    from overstep.loaders.mcp import guess_owner_uri

    assert guess_owner_uri("doc://acme/{doc_id}") == "doc_id"
    assert guess_owner_uri("repo://{org_id}/{branch}") == "org_id"
    # A single placeholder needs no judgement: it is the variable part.
    assert guess_owner_uri("s3://bucket/{key}") == "key"
    # Several, none of them an id — the scaffold does not pick a winner.
    assert guess_owner_uri("repo://{owner}/{repo}/tree") is None
    assert guess_owner_uri("config://settings") is None


def test_operator_templates_are_reported_not_drafted():
    """Ownership is plain {name} substitution, so an operator cannot be filled."""
    from overstep.loaders.mcp import has_uri_operator

    assert has_uri_operator("file:///{+path}") is True
    assert has_uri_operator("search://x{?q,lang}") is True
    assert has_uri_operator("doc://acme/{doc_id}") is False

    warnings = []
    doc = yaml.safe_load(scaffold_matrix_from_tools(
        [], templates=[{"uriTemplate": "file:///{+path}", "name": "file"}],
        warn=warnings.append,
    ))
    assert doc["resources"] == []
    assert any("RFC 6570 operator" in w for w in warnings)


def test_a_template_becomes_a_read_resource():
    doc = yaml.safe_load(
        scaffold_matrix_from_tools(_TOOLS, templates=_TEMPLATES, server_name="docs")
    )
    by_name = {r["name"]: r for r in doc["resources"]}

    document = by_name["document"]
    assert document["read"] == {"server": "docs", "uri": "doc://acme/{doc_id}"}
    assert document["type"] == "object"
    assert document["owner_uri"] == "doc_id"
    assert "call" not in document
    assert doc["policy"]["document"]["allow"][0] == {"role": "user", "scope": "own"}


def test_a_template_with_no_placeholder_is_a_function():
    doc = yaml.safe_load(scaffold_matrix_from_tools([], templates=_TEMPLATES))
    settings = {r["name"]: r for r in doc["resources"]}["settings"]
    assert settings["type"] == "function"
    assert "owner_uri" not in settings and "ownership" not in settings


def test_every_placeholder_gets_an_injection_when_none_is_the_object():
    """Each one still has to be filled, or the URI goes out with a literal brace."""
    doc = yaml.safe_load(scaffold_matrix_from_tools([], templates=_TEMPLATES))
    tree = {r["name"]: r for r in doc["resources"]}["tree"]
    assert tree["ownership"]["injections"] == [
        {"location": "mcp_resource_uri", "selector": "owner", "owner_attr": "owner"},
        {"location": "mcp_resource_uri", "selector": "repo", "owner_attr": "repo"},
    ]
    attrs = {s["name"]: s.get("attributes", {}) for s in doc["subjects"]}
    assert set(attrs["user1"]) >= {"owner", "repo"}


def test_a_template_sharing_a_tools_name_does_not_replace_it():
    tools = [{"name": "document", "inputSchema": {"type": "object", "properties": {}}}]
    doc = yaml.safe_load(scaffold_matrix_from_tools(
        tools, templates=[{"uriTemplate": "doc://a/{doc_id}", "name": "document"}]
    ))
    names = [r["name"] for r in doc["resources"]]
    assert names == ["document", "document_resource"]
    assert set(doc["policy"]) == {"document", "document_resource"}


def test_the_scaffolded_read_matrix_is_structurally_valid():
    """Only the placeholder values should be left to fill in."""
    doc = yaml.safe_load(
        scaffold_matrix_from_tools(_TOOLS, templates=_TEMPLATES, server_name="docs")
    )
    problems = [
        p for p in Matrix(**doc).validate_refs()
        if "placeholder" not in p and "no two subjects" not in p
    ]
    assert problems == []


def test_load_resource_templates_from_file(tmp_path):
    from overstep.loaders.mcp import load_resource_templates_from_file

    p = tmp_path / "listing.json"
    p.write_text(json.dumps({"result": {"resourceTemplates": _TEMPLATES}}))
    assert [t["name"] for t in load_resource_templates_from_file(str(p))] == [
        "document", "settings", "tree"
    ]
    # One capture may hold both listings, and a tools-only one yields no templates.
    p.write_text(json.dumps({"tools": _TOOLS}))
    assert load_resource_templates_from_file(str(p)) == []


def test_fetch_resource_templates_over_http():
    from overstep.loaders.mcp import fetch_resource_templates

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        seen.append(msg.get("method"))
        if msg.get("method") == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}},
                                  headers={"Mcp-Session-Id": "s1"})
        if msg.get("method") == "notifications/initialized":
            return httpx.Response(202)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2,
                                         "result": {"resourceTemplates": _TEMPLATES}})

    import overstep.loaders.mcp as mod

    orig = httpx.Client

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return orig(*a, **kw)

    mod.httpx.Client = factory
    try:
        templates = fetch_resource_templates("http://mcp.test/mcp")
    finally:
        mod.httpx.Client = orig

    assert [t["name"] for t in templates] == ["document", "settings", "tree"]
    # The lifecycle is completed, so a server that enforces it answers the listing.
    assert "notifications/initialized" in seen


def test_a_server_with_no_resources_still_scaffolds_its_tools():
    doc = yaml.safe_load(scaffold_matrix_from_tools(_TOOLS, templates=[]))
    assert [r["name"] for r in doc["resources"]] == [t["name"] for t in _TOOLS]


# --- listing failures and pagination ----------------------------------------

def _listing_server(pages, *, method="resources/templates/list", key="resourceTemplates"):
    """A server that paginates one listing method via nextCursor."""
    def handler(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        if msg.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if msg.get("method") != method:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2,
                                             "error": {"code": -32601, "message": "unknown"}})
        cursor = (msg.get("params") or {}).get("cursor")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": pages[cursor]})
    return handler


def _with_server(handler, fn, *args, **kwargs):
    import overstep.loaders.mcp as mod

    orig = httpx.Client
    mod.httpx.Client = lambda *a, **kw: orig(*a, transport=httpx.MockTransport(handler), **kw)
    try:
        return fn(*args, **kwargs)
    finally:
        mod.httpx.Client = orig


def test_a_paginated_listing_is_followed_to_the_end():
    """This count is a denominator: a template on page two is not one that
    does not exist, and `coverage --fail-under` must not treat it as absent."""
    from overstep.loaders.mcp import fetch_resource_templates

    pages = {
        None: {"resourceTemplates": [{"uriTemplate": "a://{id}"}], "nextCursor": "p2"},
        "p2": {"resourceTemplates": [{"uriTemplate": "b://{id}"}], "nextCursor": "p3"},
        "p3": {"resourceTemplates": [{"uriTemplate": "c://{id}"}]},
    }
    got = _with_server(_listing_server(pages), fetch_resource_templates, "http://t/mcp")
    assert [t["uriTemplate"] for t in got] == ["a://{id}", "b://{id}", "c://{id}"]


def test_tools_paginate_too():
    from overstep.loaders.mcp import fetch_tools

    pages = {
        None: {"tools": [{"name": "one"}], "nextCursor": "p2"},
        "p2": {"tools": [{"name": "two"}]},
    }
    handler = _listing_server(pages, method="tools/list", key="tools")
    got = _with_server(handler, fetch_tools, "http://t/mcp")
    assert [t["name"] for t in got] == ["one", "two"]


def test_a_cursor_that_never_terminates_does_not_hang():
    from overstep.loaders.mcp import fetch_tools

    pages = {None: {"tools": [{"name": "x"}], "nextCursor": "always"},
             "always": {"tools": [{"name": "x"}], "nextCursor": "always"}}
    handler = _listing_server(pages, method="tools/list", key="tools")
    got = _with_server(handler, fetch_tools, "http://t/mcp")
    assert 0 < len(got) <= 21


def test_a_server_without_resources_returns_none_rather_than_raising():
    """Which is why an exception from this call means a real failure to read."""
    from overstep.loaders.mcp import fetch_resource_templates

    handler = _listing_server({None: {"tools": []}}, method="tools/list", key="tools")
    assert _with_server(handler, fetch_resource_templates, "http://t/mcp") == []


def test_a_transport_failure_while_listing_is_not_silently_empty():
    from overstep.loaders.mcp import fetch_resource_templates

    def broken(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") in ("initialize", "notifications/initialized"):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        raise httpx.ConnectError("connection reset")

    with pytest.raises(httpx.HTTPError):
        _with_server(broken, fetch_resource_templates, "http://t/mcp")
