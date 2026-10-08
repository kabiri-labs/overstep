"""Two shapes a real MCP server has that a hand-written fixture does not.

Both came out of pointing overstep at a live FastMCP server — the default
Streamable HTTP implementation for Python, and so the one most third-party
servers are — and both made the tool wrong rather than merely inconvenient:

* it mounts the endpoint at ``/mcp/`` and answers ``/mcp`` with a **307**. The
  transport did not follow it, so a matrix one character short reached nothing
  and said so with an error about the response body;
* it requires an ``Mcp-Session-Id`` on **every** request and refuses one that
  carries none with a protocol error. The session-binding probe's control was
  "the same request without the session id", which such a server refuses for a
  reason that has nothing to do with authority — so the control could never
  clear the probe and every subject produced a confirmed, high-severity
  ``session-hijack`` finding for free.

The second is the dangerous one. A tool that cries wolf gets switched off, and
these findings were indistinguishable from the real thing.
"""
import json

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.modules.mcp.transport import redirect_target, same_origin
from overstep.pipeline import run_pipeline
from overstep.planner import plan

SUBJECT_SESSION = "sess-subject"
ANON_SESSION = "sess-anon"


def _matrix(url: str = "http://docs.test/mcp") -> Matrix:
    return Matrix(
        modules={"mcp": {"servers": [{"name": "docs", "url": url}]}},
        roles=["anonymous", "user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_document", "call": {"server": "docs", "tool": "read_document"},
             "type": "function"},
        ],
        policy={"read_document": {"allow": [{"role": "user"}, {"role": "admin"}]}},
    )


def _run(matrix, handler):
    import overstep.modules.mcp.transport as mcpmod

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


def _session_observations(result):
    sessions = {c.id for c in result.cases if c.variant == Variant.SESSION}
    return [o for o in result.observations if o.test_id in sessions]


# --------------------------------------------------------------------------
# A stateful server that lets anyone open a session
# --------------------------------------------------------------------------


def _fastmcp_shaped(*, anonymous_may_initialize: bool):
    """A server that requires a session id on every request.

    ``anonymous_may_initialize`` is the whole question. When an anonymous caller
    can obtain a session of its own, riding the subject's session gains it
    nothing and there is no hijack — the endpoint simply needs no credential.
    When it cannot, the subject's session carries authority the caller could not
    get alone, which is the defect.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            if not token and not anonymous_may_initialize:
                return httpx.Response(401, json={"detail": "Not authenticated"})
            issued = SUBJECT_SESSION if token else ANON_SESSION
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers={"Mcp-Session-Id": issued},
            )

        # The protocol refusal that the old control mistook for an
        # authorization one: no session id, no service, credential or not.
        if not session:
            return httpx.Response(
                400,
                json={"jsonrpc": "2.0", "id": "server-error",
                      "error": {"code": -32600, "message": "Bad Request: Missing session ID"}},
            )

        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "result": {"tools": [{"name": "read_document"}]}})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })
    return handle


def test_no_hijack_is_reported_when_anyone_may_open_a_session():
    """The false positive: 3 of 14 findings on a live server, all high severity."""
    result = _run(_matrix(), _fastmcp_shaped(anonymous_may_initialize=True))

    assert [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK] == []

    observations = _session_observations(result)
    assert observations, "the session probe did not run at all"
    for obs in observations:
        assert obs.skipped, "reported as a pass rather than as a question not answered"
        assert "opened its own session" in (obs.error or "")


def test_a_real_hijack_is_still_reported():
    """The other direction, and the one that must not be lost to the fix.

    Here the anonymous caller cannot obtain a session, so the subject's session
    carried authority it could not get alone — which is the defect the probe
    exists for.
    """
    result = _run(_matrix(), _fastmcp_shaped(anonymous_may_initialize=False))

    hijacks = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert hijacks, "the genuine finding was suppressed along with the false one"
    assert {f.subject for f in hijacks} == {"alice"}


def test_a_skipped_session_probe_does_not_make_the_run_inconclusive():
    """Skipping one probe is disclosure, not a verdict on the whole run."""
    result = _run(_matrix(), _fastmcp_shaped(anonymous_may_initialize=True))

    assert not result.health.inconclusive, result.health.reasons


# --------------------------------------------------------------------------
# The endpoint is at /mcp/ and /mcp redirects to it
# --------------------------------------------------------------------------


def _redirecting(*, location: str, real_path: str = "/mcp/"):
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path != real_path:
            return httpx.Response(307, headers={"location": location})
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                                  headers={"Mcp-Session-Id": SUBJECT_SESSION})
        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "result": {"tools": [{"name": "read_document"}]}})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })

    handle.seen = seen
    return handle


def test_a_same_origin_redirect_is_followed():
    """The matrix says /mcp, the server serves /mcp/, and the run still happens."""
    handler = _redirecting(location="http://docs.test/mcp/")

    result = _run(_matrix("http://docs.test/mcp"), handler)

    assert any(url.endswith("/mcp/") for url in handler.seen), "the redirect was not followed"
    # Every declared case was delivered: nothing recorded as a transport failure.
    assert result.health.transport_errors == 0
    assert not result.health.inconclusive, result.health.reasons


def test_the_handshake_follows_the_redirect_too():
    """A session belongs to the endpoint that issued it.

    Hopping only on the call would capture no session id, and the call would
    then be refused for having none — a protocol failure recorded as a denial,
    which is the shape of a passing negative test.
    """
    handler = _redirecting(location="http://docs.test/mcp/")

    _run(_matrix("http://docs.test/mcp"), handler)

    initialized = [u for u in handler.seen if u.endswith("/mcp/")]
    assert len(initialized) > 1, "only one leg reached the real endpoint"


def test_a_cross_origin_redirect_is_not_followed():
    """A credential must not be replayed at a host the matrix never named."""
    handler = _redirecting(location="http://elsewhere.test/mcp/")

    _run(_matrix("http://docs.test/mcp"), handler)

    assert not any("elsewhere.test" in url for url in handler.seen), (
        "a credential was sent to a host the matrix did not declare"
    )


# --------------------------------------------------------------------------
# The helpers themselves
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("http://docs.test/mcp", "http://docs.test/mcp/", True),
        # Spelling is seen through: a server may normalise its own URL.
        ("http://docs.test/mcp", "http://DOCS.test/mcp/", True),
        ("http://docs.test:80/mcp", "http://docs.test/mcp/", True),
        # Anything that moves the request to another network location is not.
        ("http://docs.test/mcp", "https://docs.test/mcp/", False),
        ("http://docs.test/mcp", "http://other.test/mcp/", False),
        ("http://docs.test/mcp", "http://docs.test:8080/mcp/", False),
    ],
)
def test_same_origin(a, b, expected):
    assert same_origin(a, b) is expected


def test_redirect_target_declines_a_cross_origin_hop():
    url = "http://docs.test/mcp"
    cross = httpx.Response(307, headers={"location": "http://evil.test/mcp/"})
    same = httpx.Response(307, headers={"location": "/mcp/"})
    not_a_redirect = httpx.Response(200)

    assert redirect_target(cross, url) is None
    assert redirect_target(same, url) == "http://docs.test/mcp/"
    assert redirect_target(not_a_redirect, url) is None


def test_redirect_target_declines_a_redirect_with_no_location():
    assert redirect_target(httpx.Response(307), "http://docs.test/mcp") is None
