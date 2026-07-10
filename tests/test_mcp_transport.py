"""Tests for the MCP tool-call transport.

Covers the MCP matcher (no-403 oracle), the planner's MCP branch (owner_arg fill,
markers, expected effects), matrix validation, and a full operational run against
an in-process MCP server implemented with httpx.MockTransport.
"""
import json

import httpx
import pytest

from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.mcp_matching import content_text, evaluate_mcp
from overstep.models import Effect, McpMatcher, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan
from overstep.transports import get_transport


# --- matcher ----------------------------------------------------------------

def test_matcher_jsonrpc_error_is_deny():
    m = McpMatcher()
    assert evaluate_mcp(m, jsonrpc_error={"code": -32601, "message": "x"}, is_error=False) == Effect.DENY


def test_matcher_is_error_is_deny():
    assert evaluate_mcp(McpMatcher(), jsonrpc_error=None, is_error=True) == Effect.DENY


def test_matcher_plain_result_is_allow():
    assert evaluate_mcp(McpMatcher(), jsonrpc_error=None, is_error=False, text="ok") == Effect.ALLOW


def test_matcher_deny_content_regex_wins():
    m = McpMatcher(deny_content_regex="permission denied")
    assert evaluate_mcp(m, jsonrpc_error=None, is_error=False, text="permission denied") == Effect.DENY


def test_content_text_flattens_blocks():
    assert content_text([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]) == "a\nb"


# --- fixtures ---------------------------------------------------------------

def _mcp_matrix() -> Matrix:
    return Matrix(
        roles=["anonymous", "user", "admin"],
        servers=[{"name": "docs", "url": "http://mcp.test/mcp"}],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token", "marker": "alice@corp.example", "attributes": {"doc_id": "d-alice"}},
            {"name": "bob", "role": "user", "token": "bob-token", "marker": "bob@corp.example", "attributes": {"doc_id": "d-bob"}},
            {"name": "root", "role": "admin", "token": "admin-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_document", "transport": "mcp",
             "call": {"server": "docs", "tool": "read_document"},
             "type": "object", "owner_arg": "doc_id", "owner_attr": "doc_id"},
            {"name": "list_all_users", "transport": "mcp",
             "call": {"server": "docs", "tool": "list_all_users"}, "type": "function"},
            {"name": "reset_tenant", "transport": "mcp",
             "call": {"server": "docs", "tool": "reset_tenant", "mutating": True}, "type": "function"},
        ],
        policy={
            "read_document": {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]},
            "list_all_users": {"allow": [{"role": "admin"}]},
            "reset_tenant": {"allow": [{"role": "admin"}]},
        },
    )


# --- planner ----------------------------------------------------------------

def test_mcp_transport_is_registered():
    spec = get_transport("mcp")
    assert spec.name == "mcp"
    assert callable(spec.execute)


def test_planner_builds_mcp_invocation_with_owner_arg():
    m = _mcp_matrix()
    cases = {c.id: c for c in plan(m)}
    self_case = cases["read_document::alice::self"]
    assert self_case.transport == "mcp"
    assert self_case.method == "tools/call"
    assert self_case.mcp is not None
    assert self_case.mcp.tool == "read_document"
    assert self_case.mcp.url == "http://mcp.test/mcp"
    # SELF fills the owner_arg with alice's own object.
    assert self_case.mcp.arguments["doc_id"] == "d-alice"
    assert self_case.expected == Effect.ALLOW

    other = cases["read_document::alice::other"]
    assert other.mcp.arguments["doc_id"] == "d-bob"      # a victim's object
    assert other.expected == Effect.DENY
    assert other.expect_markers == ["bob@corp.example"]   # victim marker for the oracle


def test_planner_marks_mutating_and_function_resources():
    m = _mcp_matrix()
    cases = {c.id: c for c in plan(m)}
    assert cases["reset_tenant::alice::na"].mcp.mutating is True
    assert cases["list_all_users::alice::na"].variant == Variant.NA


# --- validation -------------------------------------------------------------

def test_validate_flags_mcp_resource_without_call():
    m = _mcp_matrix()
    m.resources[0].call = None
    problems = m.validate_refs()
    assert any("must set a 'call'" in p for p in problems)


def test_validate_flags_unknown_server():
    m = _mcp_matrix()
    m.resources[0].call.server = "ghost"
    problems = m.validate_refs()
    assert any("unknown server 'ghost'" in p for p in problems)


def test_validate_flags_object_without_owner_arg():
    m = _mcp_matrix()
    m.resources[0].owner_arg = None
    problems = m.validate_refs()
    assert any("must set owner_arg" in p for p in problems)


# --- operational end-to-end -------------------------------------------------

_DOCS = {
    "d-alice": {"owner": "alice", "email": "alice@corp.example"},
    "d-bob": {"owner": "bob", "email": "bob@corp.example"},
}


def _mcp_server_handler(request: httpx.Request) -> httpx.Response:
    """A tiny intentionally-vulnerable in-process MCP server."""
    msg = json.loads(request.content)
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    role = {"alice-token": "user", "bob-token": "user", "admin-token": "admin"}.get(token, "anonymous")

    if method == "initialize":
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {"capabilities": {}}},
                              headers={"Mcp-Session-Id": "s1"})

    name = params.get("name")
    args = params.get("arguments") or {}

    def result(text, is_error=False):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                         "result": {"content": [{"type": "text", "text": text}], "isError": is_error}})

    if name == "read_document":            # BOLA: no ownership check
        doc = _DOCS.get(args.get("doc_id"))
        if not doc:
            return result("not found", is_error=True)
        return result(json.dumps({"owner": doc["owner"], "email": doc["email"]}))
    if name == "list_all_users":           # BFLA: no role check
        return result(json.dumps({"users": ["alice", "bob"]}))
    if name == "reset_tenant":             # correctly enforced
        if role != "admin":
            return result("permission denied", is_error=True)
        return result(json.dumps({"status": "reset"}))
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "unknown"}})


def _run_pipeline_against_mock(matrix, **kwargs):
    import overstep.transports.mcp as mcpmod

    transport = httpx.MockTransport(_mcp_server_handler)
    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(matrix, **kwargs)
    finally:
        mcpmod.httpx.AsyncClient = orig


def test_end_to_end_finds_bola_bfla_and_respects_correct_denials():
    result = _run_pipeline_against_mock(_mcp_matrix())
    by_id = {f.test_id: f for f in result.findings}

    # BOLA: alice reads bob's document and the victim's marker leaks -> confirmed.
    bola = by_id.get("read_document::alice::other")
    assert bola is not None
    assert bola.vuln_class == VulnClass.BOLA
    assert bola.confidence == "confirmed"

    # BFLA / privilege escalation: a plain user reaching the admin-only tool.
    priv = by_id.get("list_all_users::alice::na")
    assert priv is not None
    assert priv.vuln_class == VulnClass.PRIVILEGE_ESCALATION

    # reset_tenant is correctly enforced -> the negative test is NOT a finding.
    assert "reset_tenant::alice::na" not in by_id
    assert "reset_tenant::anon::na" not in by_id


def test_end_to_end_read_only_skips_mutating_tool():
    result = _run_pipeline_against_mock(_mcp_matrix(), read_only=True)
    skipped = [o for o in result.observations if o.test_id.startswith("reset_tenant") and o.skipped]
    assert skipped, "mutating reset_tenant calls should be skipped under read_only"


def test_finding_repro_is_an_mcp_call():
    result = _run_pipeline_against_mock(_mcp_matrix())
    bola = next(f for f in result.findings if f.test_id == "read_document::alice::other")
    assert "tools/call" in bola.curl
    assert "http://mcp.test/mcp" in bola.curl
    assert "alice-token" not in bola.curl          # token masked
    assert bola.request["tool"] == "read_document"


def test_example_mcp_matrix_loads_and_validates():
    from overstep.matrix import load_matrix

    m = load_matrix("examples/mcp_api/matrix.yaml")
    assert m.validate_refs() == []
