"""A user delegates to an agent: did the agent's authority shrink?

Two classes live here and they rest on different things, which is the first
thing to get right about them.

`scope-escalation` is a violation of the operator's declared chain, not of a
specification. RFC 8693 places no attenuation requirement on a token exchange —
the word does not appear in it, and the `scope` parameter it defines is called a
suggested mitigation in the security considerations. So `expect.denied` names
resources outright rather than deriving them from scopes: deriving would need a
mapping from OAuth scope to resource that this matrix does not have, and would
make the author restate in scope terms what the policy already says in role
terms. The finding gates for the same reason BOLA does — a boundary somebody
wrote down did not hold.

`delegation-opacity` rests on nothing in any specification. RFC 8693 defines the
`act` claim and leaves issuing it to the authorization server's discretion, so
its absence breaks no rule. It is reported only when asked for, scored lowest in
the table, and never gates.

The one thing the RFC does give is an oracle the run would otherwise have had to
guess at: section 2.2.1 requires the exchange response to carry `scope` whenever
the issued scope differs from the requested one. An absent `scope` therefore
means the request was honoured, and a present one is the server saying what it
actually granted — which is what the probes are reasoned from.
"""
import json

import httpx
import pytest

from overstep.auth import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, authenticate
from overstep.classifier import classify
from overstep.matrix import Matrix, Severity
from overstep.models import Effect, RunResult, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan

MCP = "http://docs.test/mcp"
EXCHANGE = "https://as.test/token"
ALICE_TOKEN = "alice-the-human"
# A JWT-shaped delegated token. The payload is what `_act_claim_present` reads;
# nothing here is signed and nothing pretends to be.
DELEGATED_WITH_ACT = "eyJhIjoxfQ.eyJhY3QiOnsic3ViIjoiYWdlbnQifX0.sig"
DELEGATED_NO_ACT = "eyJhIjoxfQ.eyJzdWIiOiJhZ2VudCJ9.sig"


def _matrix(*, denied=("read_salary",), actor_claim="ignored", scopes=("docs.read",)) -> Matrix:
    return Matrix(
        modules={"mcp": {
            "servers": [{"name": "docs", "url": MCP}],
            "delegation": [{
                "name": "agent-for-alice",
                "delegator": "alice",
                "actor": "support-agent",
                "grant": {"provider": "agent-exchange", "scopes": list(scopes)},
                "expect": {"denied": list(denied), "actor_claim": actor_claim},
            }],
        }},
        roles=["user", "admin"],
        auth={"providers": [{
            "name": "agent-exchange",
            "type": "oauth2_token_exchange",
            "token_url": EXCHANGE,
            "client_id": "overstep",
        }]},
        subjects=[
            {"name": "alice", "role": "admin", "token": ALICE_TOKEN,
             "marker": "alice@corp", "attributes": {"doc_id": "d-alice"}},
            {"name": "support-agent", "role": "admin"},
        ],
        resources=[
            {"name": "read_salary",
             "call": {"server": "docs", "tool": "read_salary"},
             "type": "object", "owner": "doc_id", "owner_attr": "doc_id"},
            {"name": "list_all_users",
             "call": {"server": "docs", "tool": "list_all_users"},
             "type": "function"},
        ],
        policy={
            "read_salary": {"allow": [{"role": "admin", "scope": "any"}]},
            "list_all_users": {"allow": [{"role": "admin"}]},
        },
    )


class Exchange:
    """The authorization server's token endpoint, and what it chooses to grant."""

    def __init__(self, *, token=DELEGATED_WITH_ACT, granted=None):
        self.token = token
        # None means "do not send `scope`", which RFC 8693 section 2.2.1 says
        # means the issued scope is identical to the one requested.
        self.granted = granted
        self.requests = []

    def handler(self, request: httpx.Request):
        from urllib.parse import parse_qs

        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.requests.append(form)
        body = {"access_token": self.token, "token_type": "N_A",
                "issued_token_type": ACCESS_TOKEN_TYPE}
        if self.granted is not None:
            body["scope"] = self.granted
        return httpx.Response(200, json=body)


@pytest.fixture
def exchange():
    """Install a token endpoint for the duration of one test."""
    import overstep.auth as au

    original = httpx.Client
    made = []

    def install(**kwargs):
        server = Exchange(**kwargs)

        def factory(*a, **kw):
            kw["transport"] = httpx.MockTransport(server.handler)
            return original(*a, **kw)

        au.httpx.Client = factory
        made.append(server)
        return server

    try:
        yield install
    finally:
        au.httpx.Client = original


# --- the exchange request ----------------------------------------------------


def test_the_exchange_sends_what_rfc_8693_requires(exchange):
    server = exchange()

    authenticate(_matrix(), base_url="http://docs.test")

    form = server.requests[0]
    assert form["grant_type"] == TOKEN_EXCHANGE_GRANT
    assert form["subject_token"] == ALICE_TOKEN
    assert form["subject_token_type"] == ACCESS_TOKEN_TYPE
    assert form["scope"] == "docs.read"


def test_the_exchange_sends_no_actor_token_type_without_an_actor_token(exchange):
    """Section 2.1: REQUIRED when `actor_token` is present, MUST NOT be otherwise.

    overstep sends no actor token, so sending the type would be the spec
    violation — in a tool whose findings are about specifications.
    """
    server = exchange()

    authenticate(_matrix(), base_url="http://docs.test")

    assert "actor_token" not in server.requests[0]
    assert "actor_token_type" not in server.requests[0]


def test_the_actor_gets_the_credential_the_exchange_returned(exchange):
    exchange()
    matrix = _matrix()

    authenticate(matrix, base_url="http://docs.test")

    actor = next(s for s in matrix.subjects if s.name == "support-agent")
    assert actor.token == DELEGATED_WITH_ACT


def test_an_absent_scope_in_the_response_means_the_request_was_honoured(exchange):
    """RFC 8693 section 2.2.1, and the reason the run can trust it."""
    exchange(granted=None)
    matrix = _matrix()

    authenticate(matrix, base_url="http://docs.test")
    chain = matrix.modules.mcp.delegation[0]

    assert chain._granted_scopes == ["docs.read"]
    assert chain._scope_was_declined is False


def test_a_different_scope_in_the_response_is_the_server_declining(exchange):
    exchange(granted="docs.read docs.write")
    matrix = _matrix()

    authenticate(matrix, base_url="http://docs.test")
    chain = matrix.modules.mcp.delegation[0]

    assert chain._granted_scopes == ["docs.read", "docs.write"]
    assert chain._scope_was_declined is True


# --- what the planner generates ----------------------------------------------


def _delegated(matrix):
    return [c for c in plan(matrix) if c.variant == Variant.DELEGATED]


def test_one_probe_per_denied_resource_sent_as_the_actor(exchange):
    exchange()
    matrix = _matrix(denied=("read_salary", "list_all_users"))
    authenticate(matrix, base_url="http://docs.test")

    cases = _delegated(matrix)

    assert [c.resource for c in cases] == ["read_salary", "list_all_users"]
    assert {c.subject for c in cases} == {"support-agent"}
    assert {c.expected for c in cases} == {Effect.DENY}
    assert {c.delegation for c in cases} == {"agent-for-alice"}


def test_an_object_resource_is_probed_at_the_delegators_object(exchange):
    """The interesting reach: the agent getting at the human's document."""
    exchange()
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")

    case = _delegated(matrix)[0]

    assert case.victim == "alice"
    assert case.mcp.arguments["doc_id"] == "d-alice"
    assert case.expect_markers == ["alice@corp"]


def test_a_function_resource_has_no_marker_to_confirm_with(exchange):
    exchange()
    matrix = _matrix(denied=("list_all_users",))
    authenticate(matrix, base_url="http://docs.test")

    case = _delegated(matrix)[0]

    assert case.victim is None
    assert case.expect_markers == []


def test_no_delegation_means_no_probes():
    matrix = _matrix()
    matrix.modules.mcp.delegation = []

    assert _delegated(matrix) == []


# --- classification ----------------------------------------------------------


def _observed(case, *, effect, markers=()):
    from overstep.models import Observation

    return Observation(
        test_id=case.id, status=200, effect=effect, matched_markers=list(markers),
        body_snippet="{}",
    )


def test_a_reached_resource_is_reported_and_confirmed_by_the_marker(exchange):
    exchange()
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]

    findings = classify(
        matrix, [case], [_observed(case, effect=Effect.ALLOW, markers=["alice@corp"])],
        base_url="http://docs.test",
    )

    assert [f.vuln_class for f in findings] == [VulnClass.SCOPE_ESCALATION]
    assert findings[0].confidence == "confirmed"
    assert findings[0].severity == "high"
    assert "agent-for-alice" in findings[0].detail
    assert "RFC 8693 requires no attenuation" in findings[0].detail


def test_a_refused_resource_is_the_pass(exchange):
    exchange()
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]

    findings = classify(
        matrix, [case], [_observed(case, effect=Effect.DENY)], base_url="http://docs.test"
    )

    assert findings == []


def test_a_reach_without_a_marker_is_suspected_not_confirmed(exchange):
    exchange()
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]

    findings = classify(
        matrix, [case], [_observed(case, effect=Effect.ALLOW)], base_url="http://docs.test"
    )

    assert findings[0].confidence == "suspected"
    assert findings[0].severity == "medium"


def test_a_function_resource_is_decided_on_the_outcome_alone(exchange):
    """No marker is configurable, so the finding says it is unverified."""
    exchange()
    matrix = _matrix(denied=("list_all_users",))
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]

    findings = classify(
        matrix, [case], [_observed(case, effect=Effect.ALLOW)], base_url="http://docs.test"
    )

    assert findings[0].confidence == "unverified"


def test_scope_escalation_gates_and_opacity_does_not(exchange):
    exchange(token=DELEGATED_NO_ACT)
    matrix = _matrix(denied=("read_salary",), actor_claim="required")
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]

    findings = classify(
        matrix, [case], [_observed(case, effect=Effect.ALLOW, markers=["alice@corp"])],
        base_url="http://docs.test",
    )
    gating = {f.vuln_class for f in RunResult(base_url="x", findings=findings).vulnerabilities}

    assert VulnClass.SCOPE_ESCALATION in gating
    assert VulnClass.DELEGATION_OPACITY not in gating


# --- the attribution note ----------------------------------------------------


def test_a_missing_actor_claim_is_reported_once_per_chain(exchange):
    """It is a property of the credential, not of each probe."""
    exchange(token=DELEGATED_NO_ACT)
    matrix = _matrix(denied=("read_salary", "list_all_users"), actor_claim="required")
    authenticate(matrix, base_url="http://docs.test")
    cases = _delegated(matrix)

    findings = classify(
        matrix, cases, [_observed(c, effect=Effect.DENY) for c in cases],
        base_url="http://docs.test",
    )

    opacity = [f for f in findings if f.vuln_class == VulnClass.DELEGATION_OPACITY]
    assert len(opacity) == 1, [f.test_id for f in opacity]
    assert opacity[0].severity == "low"
    assert "not an exploit" in opacity[0].detail


def test_a_credential_that_carries_an_actor_claim_is_not_reported(exchange):
    exchange(token=DELEGATED_WITH_ACT)
    matrix = _matrix(denied=("read_salary",), actor_claim="required")
    authenticate(matrix, base_url="http://docs.test")
    cases = _delegated(matrix)

    findings = classify(
        matrix, cases, [_observed(c, effect=Effect.DENY) for c in cases],
        base_url="http://docs.test",
    )

    assert [f for f in findings if f.vuln_class == VulnClass.DELEGATION_OPACITY] == []


def test_the_claim_is_not_asked_about_unless_the_matrix_asks(exchange):
    """Its absence breaks no rule, so silence is the default."""
    exchange(token=DELEGATED_NO_ACT)
    matrix = _matrix(denied=("read_salary",), actor_claim="ignored")
    authenticate(matrix, base_url="http://docs.test")
    cases = _delegated(matrix)

    findings = classify(
        matrix, cases, [_observed(c, effect=Effect.DENY) for c in cases],
        base_url="http://docs.test",
    )

    assert findings == []


# --- the credential this run minted ------------------------------------------


def test_the_delegated_credential_does_not_reach_a_finding(exchange):
    """The run obtained it, so `credential_values` has to know it.

    Same shape as the minted `client_secret` and the forwarded token before it:
    a credential that did not exist when the run started is the kind the masking
    has historically missed.
    """
    from overstep.models import Observation

    exchange()
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    case = _delegated(matrix)[0]
    # The target echoes back what it was given, which is the shape that has
    # caught this out before. Without putting the token in the evidence the
    # assertion below would pass whether or not anything masked it.
    leaky = Observation(
        test_id=case.id, status=200, effect=Effect.ALLOW,
        matched_markers=["alice@corp"],
        body_snippet=json.dumps({"you_sent": DELEGATED_WITH_ACT}),
    )

    findings = classify(matrix, [case], [leaky], base_url="http://docs.test")
    serialized = json.dumps(findings[0].model_dump(mode="json"))

    assert DELEGATED_WITH_ACT not in serialized, "the delegated credential leaked"
    assert ALICE_TOKEN not in serialized
    assert "alice@corp" in serialized, "the marker is the proof and must survive"


# --- health ------------------------------------------------------------------


def test_a_declined_scope_is_said_out_loud(exchange):
    """The probes still mean something; the chain they tested is not the declared one."""
    from overstep.health import assess

    exchange(granted="docs.read docs.write")
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    cases = _delegated(matrix)

    health = assess(cases, [_observed(c, effect=Effect.DENY) for c in cases])

    assert any("did not get the scope it asked for" in r for r in health.reasons), (
        health.reasons
    )


def test_a_granted_scope_says_nothing(exchange):
    from overstep.health import assess

    exchange(granted=None)
    matrix = _matrix(denied=("read_salary",))
    authenticate(matrix, base_url="http://docs.test")
    cases = _delegated(matrix)

    health = assess(cases, [_observed(c, effect=Effect.DENY) for c in cases])

    assert not any("scope it asked for" in r for r in health.reasons), health.reasons


# --- what the matrix refuses --------------------------------------------------


def _problems(**overrides):
    base = dict(
        name="d1", delegator="alice", actor="support-agent",
        grant={"provider": "agent-exchange", "scopes": ["docs.read"]},
        expect={"denied": ["read_salary"]},
    )
    base.update(overrides)
    matrix = _matrix()
    matrix.modules.mcp.delegation = [
        type(matrix.modules.mcp.delegation[0])(**base)
    ]
    return matrix.diagnose()


def test_an_unknown_delegator_is_an_error():
    found = [p for p in _problems(delegator="nobody") if "unknown delegator" in p.message]
    assert found and found[0].severity is Severity.ERROR


def test_delegating_to_yourself_tests_nothing():
    found = [p for p in _problems(actor="alice") if "to itself" in p.message]
    assert found and found[0].severity is Severity.ERROR


def test_a_provider_of_the_wrong_type_is_an_error():
    matrix = _matrix()
    matrix.auth.providers[0].type = "oauth2_client_credentials"

    found = [p for p in matrix.diagnose() if "oauth2_token_exchange" in p.message]

    assert found and found[0].severity is Severity.ERROR


def test_an_actor_with_its_own_credential_is_an_error():
    """One identity, two credentials, and no way to say which one got in."""
    matrix = _matrix()
    next(s for s in matrix.subjects if s.name == "support-agent").token = "its-own"

    found = [p for p in matrix.diagnose() if "two credentials" in p.message]

    assert found and found[0].severity is Severity.ERROR


def test_an_unknown_denied_resource_is_an_error():
    found = [p for p in _problems(expect={"denied": ["ghost"]}) if "ghost" in p.message]
    assert found and found[0].severity is Severity.ERROR


def test_a_chain_with_nothing_denied_is_a_warning():
    """Legitimate if you only want the actor claim checked, and worth saying."""
    found = [p for p in _problems(expect={"denied": []}) if "no expect.denied" in p.message]
    assert found and found[0].severity is Severity.WARNING
