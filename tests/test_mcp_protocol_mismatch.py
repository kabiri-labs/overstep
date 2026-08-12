"""A server whose protocol overstep cannot speak must not read as a clean run.

MCP 2026-07-28 retired the ``initialize``/``initialized`` exchange and the
``Mcp-Session-Id`` header. A server on that revision refuses the handshake this
transport performs, and then refuses everything built on it — at the protocol
layer, before authorization is consulted. Recorded as denials those refusals are
indistinguishable from a server that forbids everything, which is the shape of a
*passing* negative test: the fail-open a security gate cannot have.

The tests here pin both directions. A protocol overstep cannot drive has to end
the run as inconclusive even when the matrix has no positive control to lose,
and a merely lax server that ignores the lifecycle and answers anyway has to
stay testable.
"""
import json

import httpx

from overstep.matrix import Matrix, Severity
from overstep.models import Effect, Variant
from overstep.pipeline import run_pipeline
from overstep.planner import plan
from overstep.preflight import check

_SUPPORTED = "2025-06-18"
_RETIRED = "2026-07-28"


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


def _all_negative_matrix() -> Matrix:
    """A matrix whose subjects are allowed nothing, so it has no positive control.

    :mod:`overstep.health` deliberately does not condemn a target for denying
    everything when the matrix never expected an allow — an intentionally
    all-negative suite has nothing to lose. That rule assumes the denials came
    from authorization, which is exactly the assumption a protocol mismatch
    breaks, so this is the shape where a silent pass was possible.
    """
    return _matrix(
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        policy={
            "read_document": {"allow": [{"role": "admin"}]},
            "reset_tenant": {"allow": [{"role": "admin"}]},
        },
    )


def _with_transport(handler, fn):
    import overstep.transports.mcp as mcpmod

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return fn()
    finally:
        mcpmod.httpx.AsyncClient = orig


def _run(matrix, handler):
    return _with_transport(handler, lambda: run_pipeline(matrix))


def _stateless_server(request: httpx.Request) -> httpx.Response:
    """MCP 2026-07-28: no initialize, and Mcp-Method/Mcp-Name required."""
    body = json.loads(request.content or b"{}")
    method = body.get("method", "")
    if method in ("initialize", "notifications/initialized"):
        return httpx.Response(400, json={
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32601, "message": "method not found: initialize"},
        })
    if "Mcp-Method" not in request.headers or "Mcp-Name" not in request.headers:
        return httpx.Response(400, json={
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32600, "message": "missing required Mcp-Method/Mcp-Name"},
        })
    return httpx.Response(200, json={
        "jsonrpc": "2.0", "id": body.get("id"),
        "result": {"content": [{"type": "text", "text": "ok"}]},
    })


def _ok(body) -> httpx.Response:
    return httpx.Response(200, json={
        "jsonrpc": "2.0", "id": body.get("id"),
        "result": {"content": [{"type": "text", "text": "ok"}]},
    })


def test_a_retired_handshake_is_a_delivery_failure_not_a_denial():
    result = _run(_matrix(), _stateless_server)

    assert result.health.inconclusive
    sent = [o for o in result.observations if not o.skipped]
    # Status 0 is what every transport reserves for "never reached the target",
    # and it is what keeps these out of the allow/deny evidence entirely.
    assert sent and all(o.status == 0 for o in sent)
    assert result.health.transport_errors == len(sent)


def test_the_reason_names_the_protocol_rather_than_the_credentials():
    result = _run(_matrix(), _stateless_server)

    reason = " ".join(result.health.reasons)
    assert _SUPPORTED in reason and "initialize" in reason
    # The old diagnosis sent the reader to debug tokens that were never at fault.
    assert "credentials or the matrix are wrong" not in reason


def test_an_all_negative_matrix_cannot_pass_against_a_protocol_it_cannot_speak():
    """The regression: no positive control used to mean nothing to condemn."""
    result = _run(_all_negative_matrix(), _stateless_server)

    assert result.health.positive_tests == 0
    assert result.health.inconclusive
    assert result.findings == []


def test_a_method_not_found_under_200_is_still_a_refusal():
    """A spec-correct server reports the retired method in-band, under a 200."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if body.get("method") == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "error": {"code": -32601, "message": "method not found"},
            })
        return httpx.Response(400, json={
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32600, "message": "missing required Mcp-Method"},
        })

    result = _run(_matrix(), handler)

    assert result.health.inconclusive
    assert "method not found" in " ".join(result.health.reasons)


def test_a_negotiated_version_overstep_does_not_implement_is_refused():
    """The handshake can also succeed *into* a protocol this transport is not."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if body.get("method") == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"protocolVersion": _RETIRED, "capabilities": {}},
            })
        return httpx.Response(400, json={
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32600, "message": "missing required Mcp-Method"},
        })

    result = _run(_matrix(), handler)

    assert result.health.inconclusive
    assert _RETIRED in " ".join(result.health.reasons)


def test_a_server_that_ignores_the_handshake_but_answers_is_still_tested():
    """Backward compatibility: a lax server's answers are real answers.

    The refusal is a suspicion, not a verdict — confirmed against the request
    that follows. A server that never implemented the lifecycle but serves
    tool-calls happily must keep producing allow/deny results as before.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if body.get("method") == "initialize":
            return httpx.Response(404, text="no such endpoint")
        if body.get("params", {}).get("name") == "reset_tenant":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": "denied"}], "isError": True},
            })
        return _ok(body)

    result = _run(_matrix(), handler)

    assert not result.health.inconclusive
    sent = [o for o in result.observations if not o.skipped]
    assert all(o.status != 0 for o in sent)
    assert any(o.effect == Effect.ALLOW for o in sent)


def test_an_unauthorized_handshake_stays_an_authorization_result():
    """401 is the server talking about the caller, which is the run's subject."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, text="")

    result = _run(_matrix(), handler)

    sent = [o for o in result.observations if not o.skipped]
    # Not a delivery failure: the request reached a server that answered about
    # the credential, so it stays on the allow/deny path with its real status.
    assert sent and all(o.status == 401 for o in sent)
    assert result.health.transport_errors == 0
    assert "initialize" not in " ".join(result.health.reasons)


def test_the_session_probe_names_the_protocol_it_could_not_open():
    result = _run(_matrix(), _stateless_server)

    session_ids = {c.id for c in plan(_matrix()) if c.variant == Variant.SESSION}
    probes = [o for o in result.observations if o.test_id in session_ids]
    assert probes
    for obs in probes:
        # Still a skip — there genuinely is no session to ride — but the reason
        # is the protocol, not a conclusion that the server is stateless by design.
        assert obs.skipped
        assert "initialize" in (obs.error or "")


def test_preflight_names_the_protocol_before_a_run_is_sent():
    """`validate --live` inherits the signal: the check reads the same evidence."""
    problems = _with_transport(
        _stateless_server,
        lambda: check(_matrix(), "", authenticator=lambda m, **kw: None),
    )

    errors = [p for p in problems if p.severity is Severity.ERROR]
    assert errors
    assert any("initialize" in p.message for p in errors)
