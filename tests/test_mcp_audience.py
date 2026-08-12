"""Tests for the token-audience probe.

An MCP server must refuse a token that was not issued for it. These cover which
probes the planner generates (and, as much as it matters, which it refuses to
generate), how an accepted credential is classified and graded, and a full run
against two in-process servers — one that validates the audience and one that
does not.
"""
import json

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import _same_audience, plan
from overstep.taxonomy import taxon


def _two_server_matrix(**overrides) -> Matrix:
    """Two MCP servers; alice's token is bound to 'docs', so 'billing' is foreign."""
    data = dict(
        roles=["anonymous", "user", "admin"],
        servers=[
            {"name": "docs", "url": "http://docs.test/mcp"},
            {"name": "billing", "url": "http://billing.test/mcp"},
        ],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token", "token_audience": "docs"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_docs", "transport": "mcp",
             "call": {"server": "docs", "tool": "read_docs"}, "type": "function"},
            {"name": "read_invoices", "transport": "mcp",
             "call": {"server": "billing", "tool": "read_invoices"}, "type": "function"},
        ],
        policy={
            "read_docs": {"allow": [{"role": "user"}]},
            "read_invoices": {"allow": [{"role": "user"}]},
        },
    )
    data.update(overrides)
    return Matrix(**data)


def _audience_cases(matrix):
    return [c for c in plan(matrix) if c.variant == Variant.AUDIENCE]


# --- audience resolution ----------------------------------------------------

@pytest.mark.parametrize("audience", [
    "docs",                          # the matrix name
    "http://docs.test/mcp",          # the endpoint URL
    "http://docs.test/mcp/",         # ... with a trailing slash
    "http://docs.test",              # the origin, as Protected Resource Metadata reports it
])
def test_audience_spellings_that_identify_the_server(audience):
    server = _two_server_matrix().servers[0]
    assert _same_audience(server, audience) is True


@pytest.mark.parametrize("audience", [
    "billing",
    "http://billing.test/mcp",
    "http://docs.test.evil.example",   # a prefix in text, not in path structure
])
def test_audience_spellings_that_do_not(audience):
    server = _two_server_matrix().servers[0]
    assert _same_audience(server, audience) is False


# --- which probes get generated ---------------------------------------------

def test_probe_targets_only_the_foreign_server():
    cases = _audience_cases(_two_server_matrix())
    assert len(cases) == 1
    case = cases[0]
    assert case.id == "mcp:billing::alice::audience"
    assert case.subject == "alice"
    assert case.audience == "docs"
    assert case.expected == Effect.DENY
    assert case.method == "tools/list"
    assert case.path == "billing"          # what the method acts on: the server
    assert case.mcp.url == "http://billing.test/mcp"
    assert case.mcp.method == "tools/list"
    assert case.mcp.tool == ""


def test_no_probe_without_a_declared_audience():
    m = _two_server_matrix()
    m.subjects[0].token_audience = None
    assert _audience_cases(m) == []


def test_no_probe_for_a_subject_with_no_token():
    """anon carries nothing to replay."""
    m = _two_server_matrix()
    m.subjects[1].token_audience = "docs"
    assert [c.subject for c in _audience_cases(m)] == ["alice"]


def test_probe_can_be_switched_off():
    assert _audience_cases(_two_server_matrix(probe_token_audience=False)) == []


def test_stdio_servers_are_not_probed():
    """Identity on stdio is an environment variable, so there is no audience."""
    m = _two_server_matrix()
    m.servers[1] = type(m.servers[1])(name="billing", command=["python", "server.py"])
    assert _audience_cases(m) == []


def _matrix_with_provider(**provider) -> Matrix:
    """The same matrix, with alice authenticating through a provider instead."""
    m = _two_server_matrix()
    return _two_server_matrix(
        auth={"providers": [dict({"name": "oauth", "type": "oauth2_client_credentials",
                                  "client_id": "c"}, **provider)]},
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token",
             "auth": {"provider": "oauth"}},
            m.subjects[1].model_dump(),
        ],
    )


def test_audience_is_inferred_from_a_discovering_auth_provider():
    """A provider that discovers from a server obtains a token bound to it."""
    cases = _audience_cases(_matrix_with_provider(discover_from="docs"))
    assert [c.id for c in cases] == ["mcp:billing::alice::audience"]
    assert cases[0].audience == "docs"


def test_a_credential_in_headers_is_still_a_credential():
    """The shape `authenticate()` actually leaves behind.

    A provider writes what it obtained into `subject.headers` under its
    token_header and leaves `token` unset, so a subject that authenticated
    through the discovered-OAuth flow — the identity this probe exists for — has
    no `token` at plan time. Reading only `token` generated no probe at all.
    """
    m = _two_server_matrix(
        subjects=[
            {"name": "alice", "role": "user", "token_audience": "docs",
             "headers": {"Authorization": "Bearer alice-token"}},   # no `token`
        ],
    )
    assert [c.id for c in _audience_cases(m)] == ["mcp:billing::alice::audience"]


def test_a_subject_with_no_credential_at_all_is_not_probed():
    """A non-secret header is not an identity — X-Tenant authenticates nobody."""
    m = _two_server_matrix(
        subjects=[
            {"name": "nobody", "role": "user", "token_audience": "docs",
             "headers": {"X-Tenant": "t1"}},
        ],
    )
    assert _audience_cases(m) == []


def test_a_server_level_credential_is_dropped_from_the_probe():
    """Otherwise the target's own key authenticates the call and we report it.

    With a credential declared on `servers[]`, the request would be authorized by
    something other than the credential under test, and a served `tools/list`
    would be recorded as the foreign token having been accepted.
    """
    m = _two_server_matrix(
        servers=[
            {"name": "docs", "url": "http://docs.test/mcp"},
            {"name": "billing", "url": "http://billing.test/mcp",
             "headers": {"Authorization": "Bearer billing-gateway-key",
                         "X-Api-Version": "2"}},
        ],
    )
    inv = _audience_cases(m)[0].mcp
    assert "Authorization" not in inv.headers
    assert inv.headers["X-Api-Version"] == "2"      # transport headers stay


def test_an_explicit_resource_indicator_is_the_audience():
    """RFC 8707: the resource the token was requested for is what it is bound to."""
    cases = _audience_cases(
        _matrix_with_provider(discover_from="docs", resource="http://docs.test/mcp")
    )
    assert [c.audience for c in cases] == ["http://docs.test/mcp"]


def test_a_provider_with_a_hardcoded_token_url_says_nothing_about_audience():
    assert _audience_cases(_matrix_with_provider(token_url="http://idp.test/token")) == []


def test_audience_probes_do_not_disturb_the_existing_plan():
    """Every id a matrix produced before still has its exact spelling."""
    m = _two_server_matrix()
    before = {c.id for c in plan(_two_server_matrix(probe_token_audience=False))}
    after = {c.id for c in plan(m)}
    assert after - before == {"mcp:billing::alice::audience"}


# --- validation -------------------------------------------------------------

def test_validate_flags_a_token_audience_that_names_nothing():
    m = _two_server_matrix()
    m.subjects[0].token_audience = "dcos"      # a typo, not a URI
    problems = m.validate_refs()
    assert any("token_audience 'dcos'" in p for p in problems)


def test_validate_accepts_an_audience_uri_for_no_declared_server():
    m = _two_server_matrix()
    m.subjects[0].token_audience = "https://elsewhere.example/api"
    assert m.validate_refs() == []


# --- operational end-to-end -------------------------------------------------

_TOOLS = [{"name": "read_invoices", "inputSchema": {"type": "object", "properties": {}}}]


def _handler(*, billing_validates_audience: bool, billing_lists: list):
    """Two servers behind one mock transport, told apart by host."""
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        is_billing = request.url.host == "billing.test"

        # billing only ever sees its own token when it checks the audience.
        if is_billing and billing_validates_audience and token != "billing-token":
            return httpx.Response(401, json={"detail": "Not authenticated"},
                                  headers={"WWW-Authenticate": "Bearer"})
        if not token:
            return httpx.Response(401, json={"detail": "Not authenticated"})

        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}})
        if method == "tools/list":
            tools = billing_lists if is_billing else [{"name": "read_docs"}]
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "result": {"tools": tools}})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })
    return handle


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


def test_a_server_that_takes_a_foreign_token_is_reported():
    result = _run(
        _two_server_matrix(),
        _handler(billing_validates_audience=False, billing_lists=_TOOLS),
    )
    finding = next(f for f in result.findings if f.test_id == "mcp:billing::alice::audience")
    assert finding.vuln_class == VulnClass.TOKEN_AUDIENCE
    assert finding.severity == "high"
    assert finding.confidence == "confirmed"          # the catalogue came back
    assert "issued for 'docs'" in finding.detail
    assert finding in result.vulnerabilities          # so it gates a pipeline
    assert taxon(VulnClass.TOKEN_AUDIENCE).cwe == "CWE-863"


def test_a_server_that_validates_the_audience_is_not_reported():
    """The refusal is an HTTP 401 with no JSON-RPC body — the case fixed in 0.27.2."""
    result = _run(
        _two_server_matrix(),
        _handler(billing_validates_audience=True, billing_lists=_TOOLS),
    )
    assert not [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_AUDIENCE]
    obs = next(o for o in result.observations if o.test_id == "mcp:billing::alice::audience")
    assert obs.status == 401
    assert obs.effect == Effect.DENY


def test_an_empty_catalogue_is_suspected_rather_than_confirmed():
    """Some servers answer an unauthorized caller with nothing instead of an error."""
    result = _run(
        _two_server_matrix(),
        _handler(billing_validates_audience=False, billing_lists=[]),
    )
    finding = next(f for f in result.findings if f.vuln_class == VulnClass.TOKEN_AUDIENCE)
    assert finding.confidence == "suspected"
    assert "listed no tools" in finding.detail


def test_the_repro_is_a_tools_list_call_at_the_foreign_server():
    result = _run(
        _two_server_matrix(),
        _handler(billing_validates_audience=False, billing_lists=_TOOLS),
    )
    finding = next(f for f in result.findings if f.vuln_class == VulnClass.TOKEN_AUDIENCE)
    assert "tools/list" in finding.curl
    assert "http://billing.test/mcp" in finding.curl
    assert "alice-token" not in finding.curl            # credential masked
    assert finding.request["method"] == "tools/list"
