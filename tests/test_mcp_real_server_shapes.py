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
from overstep.modules.mcp.transport import (
    UnfollowedRedirect,
    redirect_refusal,
    redirect_target,
    same_origin,
)
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


def _redirecting(*, location: str, real_path: str = "/mcp/", status: int = 307):
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path != real_path:
            return httpx.Response(status, headers={"location": location})
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
# A server that lets anyone open a session but filters what it lists
# --------------------------------------------------------------------------


ADMIN_ONLY_TOOL = "list_all_users"


def _filtered_catalogue():
    """Anyone may open a session; the listing depends on who opened it.

    The case that reduces to ALLOW on both sides while the victim's session is
    worth strictly more: the anonymous caller gets the public catalogue, the
    stolen session gets alice's. Comparing effects alone calls that "nothing
    gained" and drops a real hijack.
    """
    owner = {SUBJECT_SESSION: "alice", ANON_SESSION: None}

    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            issued = SUBJECT_SESSION if token else ANON_SESSION
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers={"Mcp-Session-Id": issued},
            )

        if not session:
            return httpx.Response(
                400,
                json={"jsonrpc": "2.0", "id": "server-error",
                      "error": {"code": -32600, "message": "Bad Request: Missing session ID"}},
            )

        if method == "tools/list":
            tools = [{"name": "read_document"}]
            if owner.get(session):
                tools.append({"name": ADMIN_ONLY_TOOL})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                             "result": {"tools": tools}})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })
    return handle


def test_a_hijack_is_reported_when_the_session_returns_more_than_the_caller_could_reach():
    """Both requests are allowed, and the session is still worth stealing.

    The anonymous caller can open a session, so the effects match; what differs
    is the catalogue. Those extra tool names are privilege the caller had no way
    to learn alone, which is exactly the defect.
    """
    result = _run(_matrix(), _filtered_catalogue())

    hijacks = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert hijacks, "a session that discloses more of the catalogue was waved through"
    assert {f.subject for f in hijacks} == {"alice"}
    assert any(ADMIN_ONLY_TOOL in (o.listed_tools or []) for o in _session_observations(result))


def test_no_hijack_when_the_two_sessions_see_the_same_catalogue():
    """The negative control for the comparison: equal access is still no finding."""
    result = _run(_matrix(), _fastmcp_shaped(anonymous_may_initialize=True))

    assert [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK] == []


# --------------------------------------------------------------------------
# The second control has to actually answer
# --------------------------------------------------------------------------


def _anonymous_handshake_answers(status: int):
    """A server whose anonymous `initialize` answers with `status`.

    A 401 is a real answer -- the caller may not open a session, so the stolen
    one carried authority and the hijack stands. A 503 is not an answer at all.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            if not token:
                return httpx.Response(status, json={"detail": "no"})
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers={"Mcp-Session-Id": SUBJECT_SESSION},
            )

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


def test_a_transient_failure_on_the_control_does_not_become_a_finding():
    """A dropped control must not be read as a refusal.

    Without this, a 503 on one handshake emits a confirmed, high-severity
    session-hijack finding for every credentialed subject.
    """
    result = _run(_matrix(), _anonymous_handshake_answers(503))

    assert [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK] == []
    observations = _session_observations(result)
    assert observations
    for obs in observations:
        assert obs.skipped
        assert "could not tell" in (obs.error or "")


def test_a_refused_control_still_confirms_the_hijack():
    """401 is an answer: the caller may not open a session of its own."""
    result = _run(_matrix(), _anonymous_handshake_answers(401))

    hijacks = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert hijacks, "an explicit refusal was mistaken for an unanswered control"
    assert {f.subject for f in hijacks} == {"alice"}


# --------------------------------------------------------------------------
# Only method-preserving redirects are replayed
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303])
def test_a_redirect_that_does_not_preserve_the_method_is_not_replayed(status):
    """303 means "GET the other URI"; 301 and 302 are rewritten to GET by convention.

    Replaying a JSON-RPC POST to any of them is not what the server asked for,
    and if the first endpoint already dispatched a mutating `tools/call` before
    answering, it would run the operation twice.
    """
    handler = _redirecting(location="http://docs.test/mcp/", status=status)

    _run(_matrix("http://docs.test/mcp"), handler)

    assert not any(url.endswith("/mcp/") for url in handler.seen), (
        f"a POST was replayed after a {status}"
    )


@pytest.mark.parametrize("status", [307, 308])
def test_a_method_preserving_redirect_is_replayed(status):
    handler = _redirecting(location="http://docs.test/mcp/", status=status)

    result = _run(_matrix("http://docs.test/mcp"), handler)

    assert any(url.endswith("/mcp/") for url in handler.seen)
    assert result.health.transport_errors == 0


# --------------------------------------------------------------------------
# A control that could not answer is not a refusal
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_no_finding_when_the_anonymous_handshake_could_not_answer(status):
    """A broken or busy server has not refused anything.

    Only 429 and 503 were treated as unanswered, so a 500, 502 or 504 fell
    through and reported a confirmed hijack for every credentialed subject.
    """
    result = _run(_matrix(), _anonymous_handshake_answers(status))

    assert [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK] == []
    for obs in _session_observations(result):
        assert obs.skipped
        assert "could not tell" in (obs.error or "")


def _control_request_fails(status: int):
    """Anyone may open a session; the request on an anonymous one then fails.

    The second half of the same mistake: the handshake answers, so the control
    looks runnable, and the failure of its *request* is read as "the anonymous
    session is denied this" — which is the evidence that confirms a hijack.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            issued = SUBJECT_SESSION if token else ANON_SESSION
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers={"Mcp-Session-Id": issued},
            )
        if not session:
            return httpx.Response(
                400,
                json={"jsonrpc": "2.0", "id": "server-error",
                      "error": {"code": -32600, "message": "Bad Request: Missing session ID"}},
            )
        if session == ANON_SESSION:
            return httpx.Response(status, json={"detail": "later"})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                         "result": {"tools": [{"name": "read_document"}]}})
    return handle


@pytest.mark.parametrize("status", [429, 503, 500])
def test_no_finding_when_the_control_request_could_not_answer(status):
    result = _run(_matrix(), _control_request_fails(status))

    assert [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK] == []
    for obs in _session_observations(result):
        assert obs.skipped
        assert "control request" in (obs.error or "")


def test_a_handshake_that_answers_and_issues_no_session_still_confirms():
    """The answer that is not a refusal, and the one the narrow rule missed.

    A server may accept the anonymous handshake and simply issue no
    `Mcp-Session-Id` — a 200 whose whole message is the absent header. That is
    as explicit as a 401: this caller holds no session of its own, so the
    subject's session carried authority it could not obtain. Reading only 401
    and 403 as answers turned the bundled demo's three real findings into
    skipped probes.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            headers = {"Mcp-Session-Id": SUBJECT_SESSION} if token else {}
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req_id, "result": {}}, headers=headers
            )
        if not session:
            return httpx.Response(
                400,
                json={"jsonrpc": "2.0", "id": "server-error",
                      "error": {"code": -32600, "message": "Bad Request: Missing session ID"}},
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                         "result": {"tools": [{"name": "read_document"}]}})

    result = _run(_matrix(), handle)

    hijacks = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert hijacks, "a 200 that issues no session was mistaken for an unanswered control"
    assert {f.subject for f in hijacks} == {"alice"}


# --------------------------------------------------------------------------
# A redirect that is not followed never arrived
# --------------------------------------------------------------------------


def test_a_cross_origin_redirect_is_recorded_as_undelivered():
    """It used to be scored as the server's answer.

    A body-less 3xx carries no in-band deny signal and no deny status, so the
    matcher read it as *allowed*: every negative case against such an endpoint
    became a finding, and the run called itself conclusive while nothing had
    been delivered.
    """
    handler = _redirecting(location="http://elsewhere.test/mcp/")

    result = _run(_matrix("http://docs.test/mcp"), handler)

    # No vulnerability is invented. An expected-allow case that never arrived is
    # still reported as `unexpected-deny`, which is the correct signal and the
    # one that says the matrix or the target is wrong.
    assert result.vulnerabilities == [], [
        (f.test_id, f.vuln_class.value) for f in result.vulnerabilities
    ]
    assert result.health.transport_errors > 0
    assert result.health.inconclusive
    sent = [o for o in result.observations if not o.skipped]
    assert sent and all(o.status == 0 for o in sent)
    assert any("different origin" in (o.error or "") for o in sent)


def test_the_unfollowed_redirect_error_names_both_ends():
    url = "http://docs.test/mcp"
    resp = httpx.Response(307, headers={"location": "http://evil.test/mcp/"})

    message = redirect_refusal(resp, url)

    assert message is not None
    assert "evil.test" in message and url in message
    # It travels as an HTTPError so every leg already records status 0 for it.
    assert issubclass(UnfollowedRedirect, httpx.HTTPError)


# --------------------------------------------------------------------------
# Both catalogues are compared in full, not page by page
# --------------------------------------------------------------------------


def _paginated_catalogue():
    """The victim-only tool sits on the second page.

    Page one is identical for both sessions, so a comparison that reads only the
    first page finds containment and waves the hijack through.
    """
    owner = {SUBJECT_SESSION: "alice", ANON_SESSION: None}

    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        params = msg.get("params") or {}
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        session = request.headers.get("mcp-session-id", "")

        if method == "initialize":
            issued = SUBJECT_SESSION if token else ANON_SESSION
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers={"Mcp-Session-Id": issued},
            )
        if not session:
            return httpx.Response(
                400,
                json={"jsonrpc": "2.0", "id": "server-error",
                      "error": {"code": -32600, "message": "Bad Request: Missing session ID"}},
            )
        if method == "tools/list":
            privileged = bool(owner.get(session))
            if params.get("cursor") == "page2":
                tools = [{"name": ADMIN_ONLY_TOOL}] if privileged else []
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id,
                                                 "result": {"tools": tools}})
            # Page one is the same whoever asks.
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {
                "tools": [{"name": "read_document"}], "nextCursor": "page2",
            }})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
        })
    return handle


def test_a_hijack_hidden_on_the_second_page_is_still_reported():
    result = _run(_matrix(), _paginated_catalogue())

    hijacks = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert hijacks, "the comparison stopped at the first page"
    assert {f.subject for f in hijacks} == {"alice"}
    assert any(
        ADMIN_ONLY_TOOL in (o.listed_tools or []) for o in _session_observations(result)
    ), "the second page was never read"


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


@pytest.mark.parametrize("status,followed", [
    (307, True), (308, True),
    (301, False), (302, False), (303, False),
])
def test_only_method_preserving_statuses_are_targets(status, followed):
    resp = httpx.Response(status, headers={"location": "/mcp/"})
    target = redirect_target(resp, "http://docs.test/mcp")
    assert (target is not None) is followed


def test_redirect_target_declines_a_redirect_with_no_location():
    assert redirect_target(httpx.Response(307), "http://docs.test/mcp") is None
