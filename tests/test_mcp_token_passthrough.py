"""Does the server hand the caller's own credential to an upstream API?

The authorization specification is a flat MUST NOT on this in both revisions
that have one, and it says what the server should do instead: act as an OAuth
client to the upstream API and use a separate token of its own. Both halves
matter here, and the second is the one that decides whether this probe is worth
shipping. A server that forwards the caller's token is the defect; a server that
mints its own is the specification being obeyed, and reporting it would be the
precision failure that makes a tool like this unusable. So the false-positive
direction gets as much of this module as the true-positive one.

Nothing in the protocol says what a server sent upstream, so the matrix supplies
the observation point: a declared tool that takes a URL, and a canary at that
URL which echoes the request it received. The fake server below plays both the
MCP server and the canary, which is exactly what the operator's own fixture does
in a tier-1 run.
"""
import json

import httpx
import pytest

from overstep.classifier import classify
from overstep.matrix import Matrix, Severity
from overstep.models import Effect, Observation, RunResult, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan

CANARY = "https://canary.example/echo"
# What the operator's canary puts in what it echoes. Seeing it is how the run
# knows the echo is the canary's and not a tool reflecting its own request.
CANARY_MARKER = "overstep-canary-7f3a"
ALICE_TOKEN = "alice-token-do-not-forward"
SERVICE_TOKEN = "the-servers-own-upstream-token"


def _matrix(*, probe=True, canary=None, subjects=None, **overrides) -> Matrix:
    upstream = {
        "url": CANARY, "resource": "fetch_page",
        "argument": "url", "marker": CANARY_MARKER,
    }
    if canary is not None:
        upstream = canary
    data = dict(
        modules={"mcp": {
            "servers": [{"name": "docs", "url": "http://docs.test/mcp"}],
            "probes": {"conformance": {"token_passthrough": probe}},
            "canary": {"upstream": upstream} if probe or canary is not None else {},
        }},
        roles=["anonymous", "user"],
        subjects=subjects if subjects is not None else [
            {"name": "alice", "role": "user", "token": ALICE_TOKEN},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[{
            "name": "fetch_page",
            "call": {"server": "docs", "tool": "fetch_page", "arguments": {"url": ""}},
            "type": "function",
        }],
        policy={"fetch_page": {"allow": [{"role": "user"}]}},
    )
    data.update(overrides)
    return Matrix(**data)


def _passthrough(matrix):
    return [c for c in plan(matrix) if c.variant == Variant.PASSTHROUGH]


# --- which probes get generated ---------------------------------------------


def test_one_probe_per_subject_that_has_a_credential():
    """`anon` has nothing to forward, so there is nothing to ask about it."""
    cases = _passthrough(_matrix())

    assert [c.subject for c in cases] == ["alice"]
    assert cases[0].resource == "mcp:docs"
    assert cases[0].mcp.arguments["url"] == CANARY
    assert cases[0].mcp.tool == "fetch_page"


def test_the_probe_looks_for_both_the_credential_and_the_canary():
    """Two markers, because the finding needs both.

    The canary's marker says the echo came from the canary; the credential says
    what arrived there. Either alone decides nothing.
    """
    case = _passthrough(_matrix())[0]

    assert set(case.expect_markers) == {ALICE_TOKEN, CANARY_MARKER}
    assert case.canary_marker == CANARY_MARKER


def test_the_call_is_expected_to_succeed():
    """The question is not whether alice may call the tool.

    A refusal teaches nothing about credential handling, so the probe expects
    the allow and reads the body instead of the decision.
    """
    assert _passthrough(_matrix())[0].expected == Effect.ALLOW


def test_the_probe_is_off_unless_the_matrix_asks_for_it():
    assert _passthrough(_matrix(probe=False)) == []


def test_the_probe_never_vouches_for_credentials():
    """It expects an allow, and must still not count as a positive control.

    The probe is pointed at whichever declared tool happens to take a URL, and
    that may be one the policy lets anybody call. A probe that can answer
    without a credential must not be the thing that proves credentials work —
    the same trap the enumeration probe is kept out of.
    """
    assert _passthrough(_matrix())[0].is_positive_control is False


def test_a_stdio_server_has_no_inbound_header_to_forward():
    matrix = _matrix(
        modules={"mcp": {
            "servers": [{
                "name": "docs",
                "command": ["python", "server.py"],
                "token_env": "MCP_TOKEN",
            }],
            "probes": {"conformance": {"token_passthrough": True}},
            "canary": {"upstream": {
                "url": CANARY, "resource": "fetch_page",
                "argument": "url", "marker": CANARY_MARKER,
            }},
        }},
    )

    assert _passthrough(matrix) == []


# --- what the matrix refuses -------------------------------------------------


def test_the_probe_without_a_canary_is_refused_at_load():
    with pytest.raises(Exception) as excinfo:
        Matrix(
            modules={"mcp": {"probes": {"conformance": {"token_passthrough": True}}}},
            roles=["user"],
            subjects=[{"name": "alice", "role": "user", "token": ALICE_TOKEN}],
            resources=[],
        )

    assert "canary.upstream" in str(excinfo.value)


def test_the_probe_without_a_canary_marker_is_refused_at_load():
    """Three of the four is not enough: the echo has to be recognisable.

    Without a marker the probe cannot tell its credential arriving at the canary
    from the same credential reflected by a tool that called nothing — and a
    tool that reflects its request is exactly what a canary gets pointed at.
    """
    with pytest.raises(Exception) as excinfo:
        _matrix(canary={"url": CANARY, "resource": "fetch_page", "argument": "url"})

    assert "'marker'" in str(excinfo.value)


def test_a_canary_pointed_at_an_unknown_resource_is_an_error():
    matrix = _matrix(canary={
        "url": CANARY, "resource": "nope", "argument": "url", "marker": CANARY_MARKER,
    })

    problems = matrix.diagnose()

    offending = [p for p in problems if "unknown resource 'nope'" in p.message]
    assert offending, [p.message for p in problems]
    assert offending[0].severity is Severity.ERROR


def test_a_canary_pointed_at_a_rest_resource_is_an_error():
    """There is no tool argument on an HTTP request to put a URL in."""
    matrix = _matrix(
        canary={
            "url": CANARY, "resource": "get_page",
            "argument": "url", "marker": CANARY_MARKER,
        },
        resources=[{
            "name": "get_page",
            "request": {"method": "GET", "path": "/page"},
            "type": "function",
        }],
        policy={"get_page": {"allow": [{"role": "user"}]}},
    )

    problems = matrix.diagnose()

    offending = [p for p in problems if "is not an MCP tool call" in p.message]
    assert offending, [p.message for p in problems]
    assert offending[0].severity is Severity.ERROR


def test_an_argument_the_tool_does_not_declare_is_a_warning():
    """Usually a typo, and a probe that reaches no canary reports nothing."""
    matrix = _matrix(canary={
        "url": CANARY, "resource": "fetch_page",
        "argument": "ulr", "marker": CANARY_MARKER,
    })

    problems = matrix.diagnose()

    offending = [p for p in problems if "'ulr' is not among the declared" in p.message]
    assert offending, [p.message for p in problems]
    assert offending[0].severity is Severity.WARNING, (
        "a probably-mistyped argument should not stop a run that may still work"
    )


# --- operational end-to-end --------------------------------------------------


def _handler(
    *,
    forwards_caller_token: bool,
    returns_body: bool = True,
    allow: bool = True,
    reaches_canary: bool = True,
    refusal_echoes_credential: bool = False,
):
    """One fake that is both the MCP server and the canary it calls.

    `forwards_caller_token` is the whole experiment. When it is on, the server
    passes the caller's Authorization header to the canary and the canary's echo
    carries it back; when it is off, the server uses a token of its own, which
    is what the specification asks of it.
    """
    def handle(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        method, req_id = msg.get("method"), msg.get("id")
        auth = request.headers.get("authorization", "")
        caller_token = auth[7:] if auth.lower().startswith("bearer ") else ""

        if not caller_token:
            return httpx.Response(401, json={"detail": "Not authenticated"})
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": {}})
        if method == "tools/list":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": req_id,
                "result": {"tools": [{"name": "fetch_page"}]},
            })

        if not allow:
            # Some servers quote the credential they would not accept. The
            # transport matches markers on whatever came back, so a refusal can
            # carry the caller's token without anything having been forwarded.
            detail = (
                f"Forbidden for credential {caller_token}"
                if refusal_echoes_credential
                else "Forbidden"
            )
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": detail}], "isError": True},
            })

        # What the canary at `url` echoed back about the request it received.
        sent = caller_token if forwards_caller_token else SERVICE_TOKEN
        echo = {"canary": CANARY_MARKER, "received_authorization": f"Bearer {sent}"}
        if reaches_canary is False:
            # A tool that reflects its own request and calls nothing: the
            # caller's credential is in the result, the canary's marker is not.
            echo = {"echo_of_your_request": {"authorization": f"Bearer {caller_token}"}}
        content = [] if not returns_body else [{"type": "text", "text": json.dumps(echo)}]
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": content, "isError": False},
        })
    return handle


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


def test_a_server_that_forwards_the_callers_token_is_reported():
    result = _run(_matrix(), _handler(forwards_caller_token=True))

    findings = [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH]
    assert len(findings) == 1, [f.vuln_class for f in result.findings]
    finding = findings[0]
    assert finding.subject == "alice"
    assert finding.severity == "high"
    assert finding.confidence == "confirmed"
    assert finding.variant == Variant.PASSTHROUGH


def test_a_server_that_uses_its_own_upstream_token_is_not_reported():
    """The half that decides whether this probe can ship.

    The specification tells the server to act as an OAuth client to the upstream
    API with a separate token. A probe that cannot tell that apart from
    forwarding would report every well-behaved server in the world.
    """
    result = _run(_matrix(), _handler(forwards_caller_token=False))

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []


def test_the_forwarded_credential_does_not_reach_the_report():
    """The finding keeps its proof; the document does not carry the secret.

    The marker this probe matches on *is* the caller's credential, so the
    evidence is searched whole — `matched_markers` included, which is where it
    would otherwise sit in the clear beside a redacted body.
    """
    result = _run(_matrix(), _handler(forwards_caller_token=True))
    finding = next(f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH)

    serialized = json.dumps(finding.model_dump(mode="json"))

    assert ALICE_TOKEN not in serialized
    assert finding.evidence.matched_markers  # the proof is still recorded
    assert finding.detail  # and the sentence still says what happened


def test_a_refused_call_is_inconclusive_rather_than_clean():
    """The server never reached the canary, so nothing was learned."""
    result = _run(_matrix(), _handler(forwards_caller_token=True, allow=False))

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []
    assert any(
        "never called the canary" in reason for reason in result.health.reasons
    ), result.health.reasons


def test_an_empty_result_is_inconclusive_rather_than_clean():
    """Allowed, but there was no echo to read."""
    result = _run(
        _matrix(), _handler(forwards_caller_token=True, returns_body=False)
    )

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []
    assert any(
        "returned no content" in reason for reason in result.health.reasons
    ), result.health.reasons


def test_a_sound_server_is_not_called_inconclusive_for_being_sound():
    """The other direction of the same rule, and the easy mistake.

    A body that came back without the caller's credential in it is the
    specification being obeyed. Raising a reason there would make every clean
    run read as a run that proved nothing.
    """
    result = _run(_matrix(), _handler(forwards_caller_token=False))

    assert not any("passthrough" in reason for reason in result.health.reasons)


def test_the_finding_gates_a_run():
    """Unlike the open-registration probe beside it, this one is a defect."""
    result = _run(_matrix(), _handler(forwards_caller_token=True))

    classes = {f.vuln_class for f in RunResult(
        base_url="x", findings=result.findings
    ).vulnerabilities}

    assert VulnClass.TOKEN_PASSTHROUGH in classes


def test_classification_ignores_markers_on_other_variants():
    """A guard on the branch itself, not on the run that reaches it."""
    matrix = _matrix()
    case = _passthrough(matrix)[0]
    case.variant = Variant.NA
    obs = Observation(
        test_id=case.id, status=200, effect=Effect.ALLOW,
        matched_markers=[ALICE_TOKEN],
    )

    findings = classify(matrix, [case], [obs], base_url="http://docs.test")

    assert [f for f in findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []


# --- what the review of this change turned up --------------------------------


def test_a_refusal_that_quotes_the_credential_is_not_a_finding():
    """The first false positive, and the one with a contradiction in it.

    Some servers quote the credential they would not accept, and the transport
    matches markers on whatever came back — so a refusal can carry the caller's
    token without the server having forwarded anything anywhere. The branch used
    to report it, and the finding it produced claimed `observed=allow` while its
    own evidence recorded `effect=deny`. The two halves of this change also
    disagreed: `health` already called a refusal "nothing was learned".
    """
    result = _run(
        _matrix(),
        _handler(
            forwards_caller_token=True, allow=False, refusal_echoes_credential=True
        ),
    )

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []
    assert any("never called the canary" in r for r in result.health.reasons), (
        result.health.reasons
    )


def test_a_tool_that_reflects_its_own_request_is_not_a_finding():
    """The second false positive, and the likelier of the two.

    A tool that echoes its arguments and headers back to the caller is exactly
    the shape of tool a canary gets pointed at. Its result carries the caller's
    credential and nothing was sent anywhere. Only the canary's own marker
    separates the two, which is why it is required.
    """
    result = _run(
        _matrix(), _handler(forwards_caller_token=True, reaches_canary=False)
    )

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []
    assert any("did not reach the canary" in r for r in result.health.reasons), (
        result.health.reasons
    )


def test_the_canary_being_reached_without_the_credential_is_a_clean_pass():
    """The fourth outcome, and the one that must *not* be inconclusive.

    The canary's marker came back and the caller's credential did not: the
    server used a separate upstream token, which is what the specification asks
    of it. Reporting this as "nothing was learned" would make the probe useless
    on every target worth keeping.
    """
    result = _run(_matrix(), _handler(forwards_caller_token=False))

    assert [f for f in result.findings if f.vuln_class == VulnClass.TOKEN_PASSTHROUGH] == []
    assert not any("passthrough" in r for r in result.health.reasons), result.health.reasons


def test_an_object_level_canary_tool_gets_the_callers_own_object():
    """The probe has to be able to reach the tool before it can watch it.

    A canary may well be pointed at an object-level tool. Built with NA the
    ownership injections were switched off, so the probe sent the template's
    empty owner argument and was refused before the server called anything —
    while the matrix held this caller's own object id the whole time.
    """
    matrix = _matrix(
        resources=[{
            "name": "fetch_page",
            "call": {
                "server": "docs", "tool": "fetch_page",
                "arguments": {"url": "", "doc_id": ""},
            },
            "type": "object",
            "owner": "doc_id",
            "owner_attr": "doc_id",
        }],
        subjects=[{
            "name": "alice", "role": "user", "token": ALICE_TOKEN,
            "attributes": {"doc_id": "alice-doc"},
        }],
        policy={"fetch_page": {"allow": [{"role": "user", "scope": "own"}]}},
    )

    case = _passthrough(matrix)[0]

    assert case.mcp.arguments["doc_id"] == "alice-doc"
    # And the canary URL is still written over the top.
    assert case.mcp.arguments["url"] == CANARY
