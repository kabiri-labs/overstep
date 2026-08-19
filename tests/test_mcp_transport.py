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


def test_subject_token_overrides_a_server_level_authorization():
    """A credential on `servers[]` belongs to nobody, so it must not stand in.

    Letting it survive would authenticate every subject as the same identity:
    each one's own token would be dropped, every request would carry the server's
    credential, and the whole matrix would be testing one caller under many names.
    """
    from overstep.models import McpInvocation, Subject
    from overstep.transports.mcp import mcp_headers

    inv = McpInvocation(tool="t", headers={"Authorization": "Bearer server-key"})
    headers = mcp_headers(inv, Subject(name="alice", token="alice-token"))
    assert headers["Authorization"] == "Bearer alice-token"


def test_only_one_authorization_is_ever_sent_over_mcp():
    """The same case-insensitivity trap as the HTTP path.

    A lowercase `authorization` on the server plus an assigned `Authorization`
    for the subject sends both, and the server picks — possibly the shared one,
    which puts every subject back on a single identity.
    """
    from overstep.models import McpInvocation, Subject
    from overstep.transports.mcp import mcp_headers

    for server_key in ("Authorization", "authorization", "AUTHORIZATION"):
        for subject in (
            Subject(name="a", token="t"),
            Subject(name="a", headers={"authorization": "Token x"}),
            Subject(name="a", headers={"Authorization": "Token x"}),
        ):
            inv = McpInvocation(tool="t", headers={server_key: "Bearer shared"})
            sent = [v for k, v in mcp_headers(inv, subject).items() if k.lower() == "authorization"]
            assert len(sent) == 1, (server_key, subject.headers)
            assert sent[0] != "Bearer shared"


def test_a_subjects_own_authorization_is_still_never_clobbered():
    """Choosing a non-bearer scheme per identity stays a deliberate choice."""
    from overstep.models import McpInvocation, Subject
    from overstep.transports.mcp import mcp_headers

    inv = McpInvocation(tool="t", headers={"Authorization": "Bearer server-key"})
    subject = Subject(name="svc", token="ignored", headers={"Authorization": "Basic abc"})
    assert mcp_headers(inv, subject)["Authorization"] == "Basic abc"


def test_an_anonymous_invocation_carries_no_credential_of_any_kind():
    from overstep.models import McpInvocation, Subject
    from overstep.transports.mcp import mcp_headers

    inv = McpInvocation(
        tool="t", anonymous=True,
        headers={"Authorization": "Bearer k", "X-Api-Key": "k2", "X-Trace": "on"},
    )
    headers = mcp_headers(inv, Subject(name="alice", token="alice-token"))
    assert "Authorization" not in headers and "X-Api-Key" not in headers
    assert headers["X-Trace"] == "on"


def test_content_text_flattens_blocks():
    assert content_text([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]) == "a\nb"


def test_matcher_http_401_without_a_jsonrpc_body_is_deny():
    """A spec-compliant refusal carries no in-band deny signal.

    The MCP authorization spec has an unauthorized request answered with 401 and
    a WWW-Authenticate header; the body need not be a JSON-RPC message, and for
    a Starlette/FastAPI server it is `{"detail": "Not authenticated"}`. Nothing
    in that has an `error` member or `isError`, so without the status the oracle
    falls through to "the tool ran" and reports the denial as access granted.
    """
    assert evaluate_mcp(
        McpMatcher(), jsonrpc_error=None, is_error=False, text="", status=401
    ) == Effect.DENY


def test_matcher_http_5xx_is_deny():
    assert evaluate_mcp(
        McpMatcher(), jsonrpc_error=None, is_error=False, text="", status=503
    ) == Effect.DENY


def test_matcher_http_200_still_reads_the_body():
    assert evaluate_mcp(
        McpMatcher(), jsonrpc_error=None, is_error=False, text="ok", status=200
    ) == Effect.ALLOW
    assert evaluate_mcp(
        McpMatcher(), jsonrpc_error={"code": -32601, "message": "x"}, is_error=False, status=200
    ) == Effect.DENY


def test_matcher_content_regex_still_wins_over_status():
    """An explicit allow marker is the author's own statement about the server."""
    m = McpMatcher(allow_content_regex="granted")
    assert evaluate_mcp(m, jsonrpc_error=None, is_error=False, text="granted", status=403) == Effect.ALLOW


def test_matcher_deny_status_can_be_disabled():
    m = McpMatcher(deny_status=[])
    assert evaluate_mcp(m, jsonrpc_error=None, is_error=False, text="", status=401) == Effect.ALLOW


def test_matcher_stdio_passes_no_status():
    """stdio has no HTTP leg, so the default keeps its in-band behaviour."""
    assert evaluate_mcp(McpMatcher(), jsonrpc_error=None, is_error=False, text="ok") == Effect.ALLOW


# --- fixtures ---------------------------------------------------------------

def _mcp_matrix() -> Matrix:
    return Matrix(
        modules={"mcp": {"servers": [{"name": "docs", "url": "http://mcp.test/mcp"}]}},
        roles=["anonymous", "user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token", "marker": "alice@corp.example", "attributes": {"doc_id": "d-alice"}},
            {"name": "bob", "role": "user", "token": "bob-token", "marker": "bob@corp.example", "attributes": {"doc_id": "d-bob"}},
            {"name": "root", "role": "admin", "token": "admin-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_document", "call": {"server": "docs", "tool": "read_document"},
             "type": "object", "owner_arg": "doc_id", "owner_attr": "doc_id"},
            {"name": "list_all_users", "call": {"server": "docs", "tool": "list_all_users"}, "type": "function"},
            {"name": "reset_tenant", "call": {"server": "docs", "tool": "reset_tenant", "mutating": True}, "type": "function"},
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
    """A resource stripped of its body has no module and nothing to send."""
    m = _mcp_matrix()
    m.resources[0].call = None

    problems = m.validate_refs()

    assert any("declares no request" in p for p in problems)


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


def _run_pipeline_against_mock(matrix, handler=None, **kwargs):
    import overstep.transports.mcp as mcpmod

    transport = httpx.MockTransport(handler or _mcp_server_handler)
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


def _oauth_guarded_handler(request: httpx.Request) -> httpx.Response:
    """An MCP server that rejects at the HTTP leg, the way the spec asks it to.

    Unauthenticated requests get a 401 with WWW-Authenticate and a body that is
    not a JSON-RPC message — the shape a Starlette/FastAPI server produces. Every
    authenticated caller is then served, so the only denials in a run against
    this server are the HTTP ones.
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return httpx.Response(
            401,
            json={"detail": "Not authenticated"},
            headers={"WWW-Authenticate": 'Bearer resource_metadata="http://mcp.test/.well-known/oauth-protected-resource"'},
        )
    return _mcp_server_handler(request)


def test_http_401_is_not_reported_as_a_vulnerability():
    """The regression this guards: a correct refusal read as access granted.

    Every negative test for `anon` is answered with a 401 carrying no in-band
    deny signal. Read on the JSON-RPC body alone that is indistinguishable from
    a tool that ran, so each one used to surface as a BOLA/BFLA finding — a false
    positive on the most ordinary case there is, an unauthenticated caller
    against a server that rejects it.
    """
    result = _run_pipeline_against_mock(_mcp_matrix(), handler=_oauth_guarded_handler)

    anon = [f for f in result.findings if f.subject == "anon"]
    assert anon == [], f"a 401 refusal must not be a finding, got {[f.test_id for f in anon]}"

    for obs in result.observations:
        if obs.test_id.endswith("::anon::na") or "::anon::" in obs.test_id:
            assert obs.status == 401
            assert obs.effect == Effect.DENY

    # The authenticated subjects still reach the server's real bugs, so the fix
    # suppresses the false positives without muting the true ones.
    assert any(f.test_id == "read_document::alice::other" for f in result.findings)


def test_a_wholly_401_run_is_inconclusive_rather_than_clean():
    """With no credential accepted anywhere, the run must not report success."""
    def all_401(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Not authenticated"})

    result = _run_pipeline_against_mock(_mcp_matrix(), handler=all_401)
    assert result.findings == [] or all(
        f.vuln_class == VulnClass.UNEXPECTED_DENY for f in result.findings
    )
    assert result.health.inconclusive, "a run where nothing was authenticated proves nothing"


def test_example_mcp_matrix_loads_and_validates():
    from overstep.matrix import load_matrix

    m = load_matrix("examples/mcp_api/matrix.yaml")
    assert m.validate_refs() == []
