"""The two server-side MUSTs overstep checks beyond audience and session.

Both are questions about the server rather than about the policy, and they fail
in opposite directions, which is why they are pinned together.

`metadata_identity` was already being checked — discovery refuses a document
that names somebody else before it will send a credential there — and the
refusal used to end the run with a console line and no documents at all. A gate
that stops and writes nothing is indistinguishable, in a CI log a week later,
from one that ran and found nothing, which is the failure `overstep.health`
exists to remove. So the assertions below are in two halves: the run still
aborts and the secret still does not move, *and* a report now exists saying why.

`open_registration` is the only write overstep aims at a third party, so the
tests spend most of their effort on when it must **not** fire: an endpoint that
demands a credential, one that answers 200 with no client, a server advertising
no registration endpoint at all, and `--read-only`. Each of those must be
visibly "not asked" rather than quietly clean.
"""
import httpx
import pytest

from overstep.auth import AuthError, authenticate
from overstep.matrix import Matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.modules.mcp import conformance
from overstep.pipeline import run_pipeline

HONEST = "https://honest.test/as"
ATTACKER = "https://attacker.test/as"
MCP = "https://mcp.test/mcp"
CANARY = "https://canary.example/cb"

_UNSET = object()


class Backend:
    """A PRM + AS metadata + token + registration endpoint, each misbehaving on request.

    Modelled on `tests/test_oauth_discovery_trust.py`'s backend and kept separate
    from it: that one exists to prove the secret does not move, this one to prove
    the refusal is reported, and merging them would make both harder to read.

    `token_requests` is the leak assertion for every test here. A conformance
    finding is worth nothing if the run paid for it with the credential.
    """

    def __init__(
        self,
        *,
        claimed_issuer=_UNSET,
        claimed_resource=_UNSET,
        redirect_metadata_to=None,
        token_endpoint=None,
        registration_endpoint=_UNSET,
        registration_status=201,
        registration_body=_UNSET,
    ):
        self.claimed_issuer = HONEST if claimed_issuer is _UNSET else claimed_issuer
        self.claimed_resource = MCP if claimed_resource is _UNSET else claimed_resource
        self.redirect_metadata_to = redirect_metadata_to
        self.token_endpoint = token_endpoint or f"{HONEST}/token"
        self.registration_endpoint = (
            f"{HONEST}/register" if registration_endpoint is _UNSET else registration_endpoint
        )
        self.registration_status = registration_status
        self.registration_body = (
            {"client_id": "minted-by-anyone", "client_secret": "s3cr3t"}
            if registration_body is _UNSET
            else registration_body
        )
        self.token_requests = []
        self.registrations = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json={
                "resource": self.claimed_resource,
                "authorization_servers": [HONEST],
            })
        if "/.well-known/openid-configuration" in path:
            return httpx.Response(404)
        if "/.well-known/oauth-authorization-server" in path:
            if self.redirect_metadata_to and request.url.host == "honest.test":
                return httpx.Response(302, headers={"Location": self.redirect_metadata_to})
            meta = {"issuer": self.claimed_issuer, "token_endpoint": self.token_endpoint}
            if self.registration_endpoint:
                meta["registration_endpoint"] = self.registration_endpoint
            return httpx.Response(200, json=meta)
        if path.endswith("/register"):
            self.registrations.append({
                "body": request.content.decode() or "",
                "authorization": request.headers.get("authorization"),
            })
            if self.registration_body is None:
                return httpx.Response(self.registration_status)
            return httpx.Response(self.registration_status, json=self.registration_body)
        if path.endswith("/token"):
            self.token_requests.append(request.content.decode())
            return httpx.Response(200, json={"access_token": "tok-1"})
        return httpx.Response(404)


@pytest.fixture
def backend_factory():
    """Install a backend for the duration of one test.

    `modules.mcp.auth` and `overstep.auth` both hold the real `httpx` module
    object, so replacing `Client` on either replaces it for every caller —
    including the conformance transport, which opens its own.
    """
    import overstep.modules.mcp.auth as ma

    original = httpx.Client
    installed = []

    def install(**kwargs):
        backend = Backend(**kwargs)

        def factory(*a, **kw):
            kw["transport"] = httpx.MockTransport(backend.handler)
            return original(*a, **kw)

        ma.httpx.Client = factory
        installed.append(backend)
        return backend

    try:
        yield install
    finally:
        ma.httpx.Client = original


def _matrix(**mcp_extra) -> Matrix:
    """A matrix whose one subject authenticates through discovery."""
    mcp = {"servers": [{"name": "docs", "url": MCP}]}
    mcp.update(mcp_extra)
    return Matrix(
        modules={"rest": {"base_url": "https://mcp.test"}, "mcp": mcp},
        roles=["user"],
        auth={"providers": [{
            "name": "idp",
            "type": "oauth2_client_credentials",
            "discover_from": "docs",
            "client_id": "overstep",
            "client_secret": "s3cr3t-do-not-leak",
        }]},
        subjects=[{"name": "alice", "role": "user", "auth": {"provider": "idp"}}],
        resources=[{
            "name": "read_doc",
            "call": {"server": "docs", "tool": "read_doc"},
            "type": "function",
        }],
        policy={"read_doc": {"allow": [{"role": "user"}]}},
    )


# --- metadata_identity --------------------------------------------------------


SPOOFS = {
    "issuer-mismatch": {"claimed_issuer": ATTACKER},
    "resource-mismatch": {"claimed_resource": "https://elsewhere.test/mcp"},
    "cross-origin-redirect": {
        "redirect_metadata_to": "https://attacker.test/.well-known/oauth-authorization-server"
    },
    "insecure-transport": {"token_endpoint": "http://honest.test/token"},
}


@pytest.mark.parametrize("kind", sorted(SPOOFS))
def test_a_refused_metadata_document_is_reported_as_a_finding(backend_factory, kind):
    """Each of the four identity rules produces one `metadata-spoof`."""
    backend = backend_factory(**SPOOFS[kind])

    result = run_pipeline(_matrix())

    spoofs = [f for f in result.findings if f.vuln_class == VulnClass.METADATA_SPOOF]
    assert len(spoofs) == 1, [f.vuln_class for f in result.findings]
    finding = spoofs[0]
    assert finding.resource == "mcp:docs"
    assert finding.variant == Variant.METADATA
    assert finding.confidence == "confirmed"
    # The detail is the defect's own sentence, not a generic access-control one.
    assert "mcp:docs" not in finding.detail
    assert finding.detail.endswith(".")


@pytest.mark.parametrize("kind", sorted(SPOOFS))
def test_a_refused_document_still_aborts_before_any_credential_moves(backend_factory, kind):
    """The finding is the addition; the refusal is unchanged.

    This is the half that must not regress. Reporting the defect would be a bad
    trade if it were bought by continuing far enough to hand `client_secret` to
    a host that just failed the check.
    """
    backend = backend_factory(**SPOOFS[kind])

    result = run_pipeline(_matrix())

    assert backend.token_requests == []
    assert result.cases and all(c.variant == Variant.METADATA for c in result.cases)


def test_a_halted_run_is_inconclusive_however_loud_the_finding(backend_factory):
    """A finding is not a tested authorization surface.

    Nothing about the policy was observed — no request was ever sent to the MCP
    server — so a run that reports one `metadata-spoof` and nothing else must
    still say it proved nothing about authorization.
    """
    backend_factory(claimed_issuer=ATTACKER)

    result = run_pipeline(_matrix())

    assert result.health.inconclusive
    assert any("no authorization test ran" in reason for reason in result.health.reasons)


def test_the_reproduction_for_a_spoof_carries_no_credential(backend_factory):
    """The artifact that makes a finding worth forwarding to its owner."""
    backend_factory(claimed_issuer=ATTACKER)

    result = run_pipeline(_matrix())
    finding = next(f for f in result.findings if f.vuln_class == VulnClass.METADATA_SPOOF)

    assert finding.curl.startswith("curl -sS ")
    assert "Authorization" not in finding.curl
    assert "s3cr3t-do-not-leak" not in finding.curl
    assert finding.request["method"] == "GET"
    assert finding.request["headers"] == {}


def test_turning_the_probe_off_removes_the_finding_and_not_the_abort(backend_factory):
    """`metadata_identity: false` is permission to stay quiet, not to proceed.

    The check protects the run before it reports on the target, so switching the
    report off must not switch the protection off with it.
    """
    backend = backend_factory(claimed_issuer=ATTACKER)
    matrix = _matrix(probes={"conformance": {"metadata_identity": False}})

    with pytest.raises(AuthError):
        run_pipeline(matrix)
    assert backend.token_requests == []


def test_an_honest_server_produces_no_conformance_finding(backend_factory):
    """The secure half of the pair: discovery succeeds and nothing is reported."""
    backend = backend_factory()

    authenticate(_matrix(), base_url="https://mcp.test", verify_tls=True)

    assert len(backend.token_requests) == 1


def test_a_halted_run_writes_its_documents_and_exits_inconclusive(
    backend_factory, tmp_path
):
    """The whole point of the change, at the level a CI job sees it.

    Before this release the command printed `setup error:` and wrote nothing, so
    the artifact a pipeline uploads was missing exactly when something was
    wrong. The documents now exist and name the defect, and the run is reported
    for what it is: inconclusive, which is exit 3 rather than the 2 a setup
    error used to produce.
    """
    import json

    from typer.testing import CliRunner
    from overstep.cli import app

    backend_factory(claimed_issuer=ATTACKER)
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(_MATRIX_YAML, encoding="utf-8")
    out = tmp_path / "out"

    result = CliRunner().invoke(
        app, ["run", str(matrix_path), "--out", str(out)]
    )

    assert result.exit_code == 3, result.output
    written = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert [f["vuln_class"] for f in written["findings"]] == ["metadata-spoof"]
    assert (out / "overstep.sarif").exists()


_MATRIX_YAML = f"""
roles: [user]
modules:
  rest:
    base_url: https://mcp.test
  mcp:
    servers:
      - {{ name: docs, url: {MCP} }}
auth:
  providers:
    - name: idp
      type: oauth2_client_credentials
      discover_from: docs
      client_id: overstep
      client_secret: s3cr3t-do-not-leak
subjects:
  - {{ name: alice, role: user, auth: {{ provider: idp }} }}
resources:
  - name: read_doc
    call: {{ server: docs, tool: read_doc }}
    type: function
policy:
  read_doc:
    allow:
      - {{ role: user }}
"""


def test_an_ordinary_login_failure_is_still_just_an_error(backend_factory):
    """Only a defect of the target's making turns an abort into a report.

    A provider nobody declared is the operator's mistake, and it must keep
    behaving as it always has rather than acquiring a finding.
    """
    backend_factory()
    matrix = _matrix()
    matrix.subjects[0].auth.provider = "no-such-provider"

    with pytest.raises(AuthError) as excinfo:
        run_pipeline(matrix)
    assert excinfo.value.defect is None


# --- open_registration --------------------------------------------------------


def _registration_matrix(**canary) -> Matrix:
    return _matrix(
        probes={"conformance": {"open_registration": True}},
        canary=canary or {"redirect_uri": CANARY},
    )


def _run_registration(matrix):
    """Plan and deliver the registration probe without a live MCP server."""
    cases = conformance.plan_cases(matrix, {})
    observations = conformance.execute("https://mcp.test", matrix.subjects, cases)
    return cases, observations


def test_an_open_registration_endpoint_is_reported(backend_factory):
    backend = backend_factory()
    matrix = _registration_matrix()

    cases, observations = _run_registration(matrix)

    assert len(cases) == 1
    assert observations[0].effect == Effect.ALLOW
    assert observations[0].matched_markers == ["minted-by-anyone"]
    assert backend.registrations[0]["authorization"] is None
    # The resolved endpoint lands on the case, so the finding can name it.
    assert cases[0].path == f"{HONEST}/register"


def test_the_registration_probe_classifies_as_open_registration(backend_factory):
    from overstep.classifier import classify

    backend_factory()
    matrix = _registration_matrix()
    cases, observations = _run_registration(matrix)

    findings = classify(matrix, cases, observations, base_url="https://mcp.test")

    assert [f.vuln_class for f in findings] == [VulnClass.OPEN_REGISTRATION]
    assert findings[0].confidence == "confirmed"
    assert findings[0].subject == conformance.ANONYMOUS_SUBJECT
    assert "Authorization" not in findings[0].curl
    assert findings[0].curl.startswith("curl -sS -X POST ")


def test_an_endpoint_that_demands_a_credential_is_not_a_finding(backend_factory):
    backend_factory(registration_status=401, registration_body={"error": "unauthorized"})
    matrix = _registration_matrix()

    _, observations = _run_registration(matrix)

    assert observations[0].effect == Effect.DENY
    assert observations[0].skipped is False


def test_a_success_without_a_client_id_is_not_a_registration(backend_factory):
    """RFC 7591 makes `client_id` the field that says a client exists.

    A gateway answering 200 to anything would otherwise be reported as an open
    registry, which is the guess-from-status this tool refuses to make.
    """
    backend_factory(registration_status=200, registration_body={"status": "ok"})
    matrix = _registration_matrix()

    _, observations = _run_registration(matrix)

    assert observations[0].effect == Effect.DENY


def test_no_registration_endpoint_is_recorded_as_not_asked(backend_factory):
    """"Nothing to probe" and "probed and clean" must not read alike."""
    backend_factory(registration_endpoint=None)
    matrix = _registration_matrix()

    _, observations = _run_registration(matrix)

    assert observations[0].skipped is True
    assert "no registration_endpoint" in observations[0].error


def test_read_only_skips_the_one_write_this_tool_sends(backend_factory):
    backend = backend_factory()
    matrix = _registration_matrix()
    cases = conformance.plan_cases(matrix, {})

    observations = conformance.execute(
        "https://mcp.test", matrix.subjects, cases, read_only=True
    )

    assert observations[0].skipped is True
    assert "--read-only" in observations[0].error
    assert backend.registrations == []


def test_the_probe_is_off_unless_the_matrix_asks_for_it():
    assert conformance.plan_cases(_matrix(), {}) == []


def test_a_registration_probe_without_a_canary_is_refused():
    """A probe that cannot recognise its own client cannot decide anything."""
    with pytest.raises(Exception) as excinfo:
        _matrix(probes={"conformance": {"open_registration": True}})

    assert "canary.redirect_uri" in str(excinfo.value)


def test_the_registration_body_asks_for_nothing_extra(backend_factory):
    """Only what RFC 7591 needs and what the operator supplied.

    A field added to coax a reluctant server into accepting would make the
    finding a statement about overstep's persistence rather than the policy.
    """
    import json

    backend = backend_factory()
    _run_registration(_registration_matrix())

    sent = json.loads(backend.registrations[0]["body"])
    assert sent["redirect_uris"] == [CANARY]
    assert sent["client_name"] == conformance.CLIENT_NAME
    assert set(sent) == {
        "client_name", "redirect_uris", "grant_types",
        "response_types", "token_endpoint_auth_method",
    }
