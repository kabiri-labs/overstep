"""Tests for the session-binding and tool-enumeration probes.

Both ask about the connection rather than about a declared operation: whether an
`Mcp-Session-Id` can stand in for a credential, and what a server is willing to
list to a caller who may not invoke it.
"""
import json

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan
from overstep.taxonomy import taxon

_SESSION = "sess-alice-1"


def _matrix(**overrides) -> Matrix:
    data = dict(
        roles=["anonymous", "user", "admin"],
        servers=[{"name": "docs", "url": "http://docs.test/mcp"}],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token"},
            {"name": "root", "role": "admin", "token": "admin-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_document", "transport": "mcp",
             "call": {"server": "docs", "tool": "read_document"}, "type": "function"},
            {"name": "reset_tenant", "transport": "mcp",
             "call": {"server": "docs", "tool": "reset_tenant"}, "type": "function"},
        ],
        policy={
            "read_document": {"allow": [{"role": "user"}, {"role": "admin"}]},
            "reset_tenant": {"allow": [{"role": "admin"}]},
        },
    )
    data.update(overrides)
    return Matrix(**data)


def _cases(matrix, variant):
    return [c for c in plan(matrix) if c.variant == variant]


def _run(matrix, handler):
    import overstep.transports.mcp as mcpmod

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(matrix)
    finally:
        mcpmod.httpx.AsyncClient = orig


# --- a configurable server --------------------------------------------------

_ALL_TOOLS = [{"name": "read_document"}, {"name": "reset_tenant"}, {"name": "undeclared_tool"}]


def _server(*, session_is_auth: bool, stateless: bool = False, public_list: bool = False,
            tools=None):
    """One MCP server with the behaviours these probes are meant to tell apart.

    `session_is_auth` accepts any request carrying a session id, credential or
    not — the defect. `public_list` serves tools/list to anyone, session or not,
    which is the confounder the probe's control exists to rule out. `stateless`
    issues no session id at all, so there is nothing to hijack.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        def unauthorized():
            return httpx.Response(401, json={"detail": "Not authenticated"})

        if method == "initialize":
            if not token:
                return unauthorized()
            headers = {} if stateless else {"Mcp-Session-Id": _SESSION}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                                  headers=headers)

        authenticated = bool(token) or (session_is_auth and bool(session))
        if method == "tools/list":
            if not (authenticated or public_list):
                return unauthorized()
            listed = _ALL_TOOLS if tools is None else tools
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "result": {"tools": listed}})

        if not authenticated:
            return unauthorized()
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })
    return handle


# --- session binding: planning ----------------------------------------------

def test_a_session_probe_per_credentialed_subject():
    ids = [c.id for c in _cases(_matrix(), Variant.SESSION)]
    assert ids == ["mcp:docs::alice::session", "mcp:docs::root::session"]


def test_no_session_probe_for_a_subject_with_no_identity():
    """anon opens no session worth stealing."""
    assert "anon" not in {c.subject for c in _cases(_matrix(), Variant.SESSION)}


def test_the_session_probe_carries_the_identity_only_on_the_handshake():
    case = _cases(_matrix(), Variant.SESSION)[0]
    assert case.expected == Effect.DENY
    assert case.mcp.method == "tools/list"
    assert case.mcp.anonymous is True
    assert case.mcp.handshake_headers == {"Authorization": "Bearer alice-token"}


def test_session_probe_can_be_switched_off():
    assert _cases(_matrix(probe_session_binding=False), Variant.SESSION) == []


# --- session binding: operational -------------------------------------------

def test_a_session_accepted_as_a_credential_is_reported():
    result = _run(_matrix(), _server(session_is_auth=True))
    finding = next(f for f in result.findings if f.test_id == "mcp:docs::alice::session")
    assert finding.vuln_class == VulnClass.SESSION_HIJACK
    assert finding.severity == "high"
    assert "anyone who obtains the id becomes alice" in finding.detail
    assert finding in result.vulnerabilities
    assert taxon(VulnClass.SESSION_HIJACK).cwe == "CWE-287"


def test_a_server_that_rechecks_the_credential_is_not_reported():
    result = _run(_matrix(), _server(session_is_auth=False))
    assert not [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]


def test_a_public_endpoint_is_not_mistaken_for_a_hijackable_session():
    """The control: served without the session too, so the session proved nothing."""
    result = _run(_matrix(), _server(session_is_auth=True, public_list=True))
    assert not [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    obs = next(o for o in result.observations if o.test_id == "mcp:docs::alice::session")
    assert obs.effect == Effect.DENY
    assert "succeeded without the session id too" in (obs.error or "")


def test_a_stateless_server_is_skipped_rather_than_judged():
    result = _run(_matrix(), _server(session_is_auth=True, stateless=True))
    obs = next(o for o in result.observations if o.test_id == "mcp:docs::alice::session")
    assert obs.skipped is True
    assert "no session id" in (obs.error or "")
    assert not [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]


# --- tool enumeration -------------------------------------------------------

def test_enumeration_is_off_by_default():
    assert _cases(_matrix(), Variant.ENUMERATE) == []


def test_enumeration_probes_every_subject_when_enabled():
    ids = [c.id for c in _cases(_matrix(probe_tool_enumeration=True), Variant.ENUMERATE)]
    assert ids == [
        "mcp:docs::alice::enumerate",
        "mcp:docs::root::enumerate",
        "mcp:docs::anon::enumerate",
    ]


def test_a_tool_listed_to_someone_who_may_not_invoke_it_is_reported():
    result = _run(_matrix(probe_tool_enumeration=True), _server(session_is_auth=False))
    leaked = [f for f in result.findings if f.vuln_class == VulnClass.TOOL_ENUMERATION]

    # alice is a user: reset_tenant is admin-only, read_document is hers to call.
    assert [f.test_id for f in leaked] == ["mcp:docs::alice::enumerate::reset_tenant"]
    assert leaked[0].severity == "medium"
    assert "has no allow rule for it" in leaked[0].detail
    assert leaked[0].curl                      # the repro is the probe itself
    assert taxon(VulnClass.TOOL_ENUMERATION).cwe == "CWE-200"


def test_an_undeclared_tool_is_not_an_enumeration_finding():
    """That gap is coverage's to report; silence about a tool is not a denial."""
    result = _run(_matrix(probe_tool_enumeration=True), _server(session_is_auth=False))
    assert not [f for f in result.findings if "undeclared_tool" in f.test_id]


def test_a_subject_denied_the_listing_produces_nothing():
    """anon cannot list at all — no disclosure, and no over-restriction either."""
    result = _run(_matrix(probe_tool_enumeration=True), _server(session_is_auth=False))
    assert not [f for f in result.findings if f.test_id.startswith("mcp:docs::anon::enumerate")]
    obs = next(o for o in result.observations if o.test_id == "mcp:docs::anon::enumerate")
    assert obs.effect == Effect.DENY
    assert obs.listed_tools == []


def test_an_admin_shown_every_tool_is_not_a_finding():
    result = _run(_matrix(probe_tool_enumeration=True), _server(session_is_auth=False))
    assert not [f for f in result.findings if f.test_id.startswith("mcp:docs::root::enumerate")]


def test_listed_tools_are_recorded_on_the_observation():
    """Read from the result, not parsed back out of a truncated snippet."""
    result = _run(_matrix(probe_tool_enumeration=True), _server(session_is_auth=False))
    obs = next(o for o in result.observations if o.test_id == "mcp:docs::alice::enumerate")
    assert obs.listed_tools == ["read_document", "reset_tenant", "undeclared_tool"]


def test_a_long_catalogue_survives_body_truncation():
    """The snippet is capped at 2048 chars; the tool list must not be read from it."""
    many = [{"name": f"tool_{i}", "description": "x" * 200} for i in range(60)]
    result = _run(_matrix(probe_tool_enumeration=True),
                  _server(session_is_auth=False, tools=many + [{"name": "reset_tenant"}]))
    obs = next(o for o in result.observations if o.test_id == "mcp:docs::alice::enumerate")
    assert len(obs.body_snippet) == 2048
    assert "reset_tenant" in obs.listed_tools
    assert [f.test_id for f in result.findings if f.vuln_class == VulnClass.TOOL_ENUMERATION] == [
        "mcp:docs::alice::enumerate::reset_tenant"
    ]
