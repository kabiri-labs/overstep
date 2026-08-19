"""Tests for the MCP ``resources/read`` surface.

Tools are one half of what an MCP server exposes; resources, addressed by URI,
are the other. The URI is an object-level surface in the same sense a path
parameter is, so a server can enforce ownership perfectly on every tool and hand
the same data out through a read. These cover the planning of that probe, the
oracle that reads the result, validation, and a run against a server that has
exactly that split.
"""
import base64
import json

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.mcp_matching import contents_text, contents_uris
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan


def _matrix(servers=None, **overrides) -> Matrix:
    data = dict(
        modules={"mcp": {
            "servers": servers or [{"name": "docs", "url": "http://docs.test/mcp"}],
            # not what these tests are about
            "probes": {"session_binding": False},
        }},
        roles=["anonymous", "user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token",
             "marker": "alice@corp.example", "attributes": {"doc_id": "alice"}},
            {"name": "bob", "role": "user", "token": "bob-token",
             "marker": "bob@corp.example", "attributes": {"doc_id": "bob"}},
        ],
        resources=[
            {"name": "read_doc", "read": {"server": "docs", "uri": "doc://acme/{doc_id}"},
             "type": "object", "owner_uri": "doc_id", "owner_attr": "doc_id"},
        ],
        policy={"read_doc": {"allow": [{"role": "user", "scope": "own"}]}},
    )
    data.update(overrides)
    return Matrix(**data)


# --- the oracle -------------------------------------------------------------

def test_contents_text_is_the_body_and_nothing_else():
    """The URI is carried separately; see the BOPLA test below for why."""
    entry = [{"uri": "doc://acme/bob", "text": "bob@corp.example"}]
    assert contents_text(entry) == "bob@corp.example"
    assert contents_uris(entry) == ["doc://acme/bob"]


def test_a_json_body_stays_parseable():
    """What the BOPLA check needs: the body alone, still valid JSON.

    Prepending the URI turns a perfectly good JSON document into something
    `json.loads` rejects, and `_json_keys` returns nothing for a body it cannot
    parse — so forbidden-field detection would switch itself off for every
    resource read that returns JSON, which is most of them.
    """
    body = '{"owner": "bob", "password_hash": "x"}'
    assert json.loads(contents_text([{"uri": "doc://acme/bob", "text": body}]))


def test_contents_text_decodes_a_utf8_blob():
    """A text document served base64 still carries its owner's marker."""
    blob = base64.b64encode("bob@corp.example".encode()).decode()
    assert contents_text([{"uri": "doc://acme/bob", "blob": blob}]) == "bob@corp.example"


def test_contents_text_leaves_an_undecodable_blob_out():
    """Binary noise must not become something a marker or regex matches by luck."""
    blob = base64.b64encode(b"\xff\xfe\x00\x01").decode()
    assert contents_text([{"uri": "doc://acme/bob", "blob": blob}]) == ""


# --- planning ---------------------------------------------------------------

def test_the_uri_is_the_bola_surface():
    cases = {c.id: c for c in plan(_matrix())}

    own = cases["read_doc::alice::self"]
    assert own.method == "resources/read"
    assert own.mcp.uri == "doc://acme/alice"
    assert own.path_template == "doc://acme/{doc_id}"     # the surface as declared
    assert own.expected == Effect.ALLOW

    other = cases["read_doc::alice::other"]
    assert other.mcp.uri == "doc://acme/bob"              # a victim's object
    assert other.expected == Effect.DENY
    assert other.expect_markers == ["bob@corp.example"]   # for the content oracle


def test_the_whole_uri_can_be_the_object():
    """A URI with no template structure of its own is one placeholder."""
    m = _matrix(resources=[{
        "name": "read_doc", "read": {"server": "docs", "uri": "{doc}"},
        "type": "object", "owner_uri": "doc",
        "objects": {"alice": "s3://bucket/a.txt", "bob": "file:///srv/b.txt"},
    }])
    cases = {c.id: c for c in plan(m)}
    assert cases["read_doc::alice::self"].mcp.uri == "s3://bucket/a.txt"
    assert cases["read_doc::alice::other"].mcp.uri == "file:///srv/b.txt"


def test_a_read_is_never_skipped_under_read_only():
    """Reading has no side effects, so there is nothing to protect against."""
    case = next(c for c in plan(_matrix()) if c.variant == Variant.SELF)
    assert case.mcp.mutating is False


def test_the_request_body_is_a_resources_read():
    from overstep.transports.mcp import jsonrpc_request

    case = next(c for c in plan(_matrix()) if c.id == "read_doc::alice::other")
    payload = jsonrpc_request(case.mcp)
    assert payload["method"] == "resources/read"
    assert payload["params"] == {"uri": "doc://acme/bob"}


# --- validation -------------------------------------------------------------

def test_a_resource_cannot_both_call_and_read():
    """Two bodies leave the module ambiguous, so the matrix cannot be planned."""
    m = _matrix()
    m.resources[0].call = {"server": "docs", "tool": "read_doc"}

    problems = m.validate_refs()

    assert any("makes one kind of request" in p for p in problems)
    assert any("call and read" in p for p in problems)


def test_neither_call_nor_read_is_an_error():
    """And no body at all leaves nothing to send."""
    m = _matrix()
    m.resources[0].read = None
    m.resources[0].owner_uri = None

    assert any("declares no request" in p for p in m.validate_refs())


def test_an_unknown_server_on_a_read_is_caught():
    m = _matrix()
    m.resources[0].read.server = "ghost"
    assert any("unknown server 'ghost'" in p for p in m.validate_refs())


def test_a_uri_injection_must_name_a_placeholder_in_the_uri():
    """Without it nothing is substituted and every subject reads one fixed URI."""
    m = _matrix()
    m.resources[0].owner_uri = "wrong_name"
    assert any(
        "uri injection 'wrong_name' is not a placeholder" in p for p in m.validate_refs()
    )


def test_a_read_cannot_carry_a_tool_argument_injection():
    m = _matrix(resources=[{
        "name": "read_doc", "read": {"server": "docs", "uri": "doc://acme/{doc_id}"},
        "type": "object",
        "ownership": {"injections": [{"location": "mcp_argument", "selector": "doc_id"}]},
    }])
    assert any("lives in the URI" in p for p in m.validate_refs())


def test_a_tool_call_cannot_carry_a_uri_injection():
    m = _matrix(resources=[{
        "name": "call_doc", "call": {"server": "docs", "tool": "read_doc"},
        "type": "object",
        "ownership": {"injections": [{"location": "mcp_resource_uri", "selector": "doc_id"}]},
    }], policy={"call_doc": {"allow": [{"role": "user", "scope": "own"}]}})
    assert any("lives in an argument" in p for p in m.validate_refs())


def test_an_http_resource_cannot_carry_a_uri_injection():
    m = _matrix(resources=[{
        "name": "get_doc", "request": {"method": "GET", "path": "/docs/{id}"},
        "type": "object",
        "ownership": {"injections": [{"location": "mcp_resource_uri", "selector": "id"}]},
    }], policy={"get_doc": {"allow": [{"role": "user", "scope": "own"}]}})
    assert any("cannot use an 'mcp_resource_uri' injection" in p for p in m.validate_refs())


# --- operational end-to-end -------------------------------------------------

_DOCS = {
    "doc://acme/alice": '{"owner": "alice", "email": "alice@corp.example", "body": "Q3 plan"}',
    "doc://acme/bob": '{"owner": "bob", "email": "bob@corp.example", "body": "salary review"}',
}


def _server_enforcing_tools_but_not_resources(request: httpx.Request) -> httpx.Response:
    """The split this whole feature exists for.

    `tools/call` checks ownership properly. `resources/read` serves any URI to
    any authenticated caller, so the same documents leak through the second door
    while the first one reports clean.
    """
    msg = json.loads(request.content)
    method, req_id = msg.get("method"), msg.get("id")
    params = msg.get("params") or {}
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""

    if method == "initialize":
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}})
    if method == "notifications/initialized":
        return httpx.Response(202)
    if not token:
        return httpx.Response(401, json={"detail": "Not authenticated"})

    if method == "resources/read":                 # no ownership check at all
        uri = params.get("uri")
        if uri not in _DOCS:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "error": {"code": -32002, "message": "not found"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {
            "contents": [{"uri": uri, "mimeType": "text/plain", "text": _DOCS[uri]}],
        }})

    if method == "tools/call":                     # correctly enforced
        owner = {"alice-token": "alice", "bob-token": "bob"}.get(token)
        wanted = (params.get("arguments") or {}).get("doc_id")
        if wanted != owner:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": "permission denied"}], "isError": True,
            }})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": _DOCS[f"doc://acme/{owner}"]}],
        }})

    return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}})


def _run(matrix):
    import overstep.transports.mcp as mcpmod

    transport = httpx.MockTransport(_server_enforcing_tools_but_not_resources)
    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(matrix)
    finally:
        mcpmod.httpx.AsyncClient = orig


def test_a_bola_through_resources_read_is_found_and_confirmed():
    result = _run(_matrix())
    finding = next(f for f in result.findings if f.test_id == "read_doc::alice::other")
    assert finding.vuln_class == VulnClass.BOLA
    assert finding.confidence == "confirmed"      # bob's marker came back
    assert "bob@corp.example" in finding.evidence.matched_markers
    assert finding in result.vulnerabilities


def test_the_tool_half_of_the_same_server_reports_clean():
    """Which is the point: testing only tools would have found nothing here."""
    m = _matrix(resources=[
        {"name": "read_doc", "read": {"server": "docs", "uri": "doc://acme/{doc_id}"},
         "type": "object", "owner_uri": "doc_id", "owner_attr": "doc_id"},
        {"name": "get_doc_tool", "call": {"server": "docs", "tool": "get_doc"},
         "type": "object", "owner_arg": "doc_id", "owner_attr": "doc_id"},
    ], policy={
        "read_doc": {"allow": [{"role": "user", "scope": "own"}]},
        "get_doc_tool": {"allow": [{"role": "user", "scope": "own"}]},
    })
    result = _run(m)
    classes = {f.test_id: f.vuln_class for f in result.findings}
    assert classes.get("read_doc::alice::other") == VulnClass.BOLA
    assert "get_doc_tool::alice::other" not in classes


def test_the_repro_names_the_uri_that_leaked():
    result = _run(_matrix())
    finding = next(f for f in result.findings if f.test_id == "read_doc::alice::other")
    assert "resources/read" in finding.curl
    assert "doc://acme/bob" in finding.curl
    assert "alice-token" not in finding.curl        # credential masked
    assert finding.request["uri"] == "doc://acme/bob"


def test_forbidden_fields_are_detected_in_a_resource_read():
    """BOPLA over a read: the body must reach the classifier as parseable JSON."""
    m = _matrix(resources=[{
        "name": "read_doc", "read": {"server": "docs", "uri": "doc://acme/{doc_id}"},
        "type": "object", "owner_uri": "doc_id", "owner_attr": "doc_id",
        "forbidden_fields": ["email"],
    }])
    result = _run(m)
    bopla = [f for f in result.findings if f.vuln_class == VulnClass.BOPLA]
    # alice's own read is allowed and still over-shares, which is the BOPLA shape.
    assert "read_doc::alice::self" in {f.test_id for f in bopla}
    assert "email" in bopla[0].detail


def test_the_victims_uri_still_confirms_a_leak():
    """Kept out of the body, but not lost: markers are searched in both."""
    m = _matrix(subjects=[
        {"name": "alice", "role": "user", "token": "alice-token",
         "marker": "doc://acme/alice", "attributes": {"doc_id": "alice"}},
        {"name": "bob", "role": "user", "token": "bob-token",
         "marker": "doc://acme/bob", "attributes": {"doc_id": "bob"}},
    ])
    result = _run(m)
    finding = next(f for f in result.findings if f.test_id == "read_doc::alice::other")
    assert finding.confidence == "confirmed"
    assert finding.evidence.matched_markers == ["doc://acme/bob"]


def test_a_stdio_read_records_the_uri_it_read():
    """Structured evidence has to say which resource was read; stdio has no tool."""
    from overstep.models import Subject
    from overstep.repro import request_record

    m = _matrix(servers=[{"name": "docs", "command": ["python", "server.py"]}])
    case = next(c for c in plan(m) if c.id == "read_doc::alice::other")
    assert case.mcp.kind == "stdio"
    record = request_record("", Subject(name="alice", token="alice-token"), case)
    assert record["transport"] == "stdio"
    assert record["uri"] == "doc://acme/bob"


def test_the_read_surface_counts_towards_probe_coverage():
    result = _run(_matrix())
    assert result.coverage.object_resources == 1
    assert result.coverage.probed == 1
    assert result.coverage.unprobed == []
