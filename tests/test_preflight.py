"""Tests for the live pre-flight check behind `validate --live`.

The executor is injected throughout, so every case here is deterministic and
touches no network.
"""
from typer.testing import CliRunner

from overstep.auth import AuthError
from overstep.cli import app
from overstep.matrix import Matrix, Severity
from overstep.models import Effect, Observation
from overstep.preflight import check

MATRIX = Matrix(
    modules={"rest": {"base_url": "http://t"}},
    roles=["anonymous", "user", "admin"],
    subjects=[
        {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1"}},
        {"name": "bob", "role": "user", "token": "b", "attributes": {"user_id": "u2"}},
        {"name": "anon", "role": "anonymous", "token": None},
    ],
    resources=[{
        "name": "get_user",
        "request": {"method": "GET", "path": "/users/{id}"},
        "type": "object",
        "owner": "id",
        "owner_attr": "user_id",
    }],
    policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
)


def _executor(build):
    """Wrap a per-case observation factory in the transport's signature."""
    def execute(base_url, subjects, cases, **kwargs):
        execute.seen = list(cases)
        execute.kwargs = kwargs
        return [build(c) for c in cases]
    execute.seen = []
    execute.kwargs = {}
    return execute


def _noop_auth(matrix, **kwargs):
    return None


def _allowed(case):
    return Observation(test_id=case.id, status=200, effect=Effect.ALLOW)


def test_a_healthy_target_produces_no_problems():
    assert check(MATRIX, "http://t", executor=_executor(_allowed), authenticator=_noop_auth) == []


def test_a_rejected_credential_is_an_error():
    def denied(case):
        return Observation(test_id=case.id, status=401, effect=Effect.DENY)

    problems = check(MATRIX, "http://t", executor=_executor(denied), authenticator=_noop_auth)

    assert problems and all(p.severity is Severity.ERROR for p in problems)
    assert any("alice" in p.message and "401" in p.message for p in problems)


def test_an_undelivered_probe_is_reported_as_unreachable_not_as_a_bad_token():
    """Status 0 is the transports' delivery-failure convention; it is not a denial."""
    def dead(case):
        return Observation(
            test_id=case.id, status=0, effect=Effect.DENY, error="connection refused"
        )

    problems = check(MATRIX, "http://t", executor=_executor(dead), authenticator=_noop_auth)

    assert all("did not answer" in p.message for p in problems)
    assert not any("credential is rejected" in p.message for p in problems)


def test_a_skipped_mutating_probe_is_a_warning_not_a_verdict():
    def skipped(case):
        return Observation(
            test_id=case.id, status=0, effect=Effect.DENY, skipped=True, error="skipped"
        )

    problems = check(MATRIX, "http://t", executor=_executor(skipped), authenticator=_noop_auth)

    assert problems and all(p.severity is Severity.WARNING for p in problems)
    assert any("rather than tested destructively" in p.message for p in problems)


def test_probes_are_sent_read_only():
    """A check is not entitled to change state."""
    executor = _executor(_allowed)
    check(MATRIX, "http://t", executor=executor, authenticator=_noop_auth)

    assert executor.kwargs["read_only"] is True


def test_one_probe_per_subject_that_has_a_positive_control():
    executor = _executor(_allowed)
    check(MATRIX, "http://t", executor=executor, authenticator=_noop_auth)

    assert sorted(c.subject for c in executor.seen) == ["alice", "bob"]


def test_non_mutating_probes_are_preferred():
    """So a subject is verified with its GET rather than skipped on its DELETE."""
    m = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user"],
        subjects=[{"name": "a", "role": "user", "token": "t", "attributes": {"user_id": "u1"}}],
        resources=[
            # Declared first, so picking the DELETE would be the natural mistake.
            {"name": "del_user", "request": {"method": "DELETE", "path": "/users/{id}"},
             "type": "object", "owner": "id", "owner_attr": "user_id"},
            {"name": "get_user", "request": {"method": "GET", "path": "/users/{id}"},
             "type": "object", "owner": "id", "owner_attr": "user_id"},
        ],
        policy={
            "del_user": {"allow": [{"role": "user", "scope": "own"}]},
            "get_user": {"allow": [{"role": "user", "scope": "own"}]},
        },
    )
    executor = _executor(_allowed)
    check(m, "http://t", executor=executor, authenticator=_noop_auth)

    assert [c.method for c in executor.seen] == ["GET"]


def test_an_anonymous_subject_is_not_reported_as_unverifiable():
    """It carries no credential, so having no positive control is its normal shape."""
    problems = check(MATRIX, "http://t", executor=_executor(_allowed), authenticator=_noop_auth)

    assert not any("anon" in p.message for p in problems)


def test_a_credentialled_subject_with_no_positive_control_warns():
    """A token nothing exercises is a token that can rot unnoticed."""
    m = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["anonymous", "user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1"}},
            # Holds a credential, but its role is allowed nothing.
            {"name": "ghost", "role": "anonymous", "token": "g", "attributes": {"user_id": "u2"}},
        ],
        resources=[{
            "name": "get_user",
            "request": {"method": "GET", "path": "/users/{id}"},
            "type": "object",
            "owner": "id",
            "owner_attr": "user_id",
        }],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )
    problems = check(m, "http://t", executor=_executor(_allowed), authenticator=_noop_auth)

    assert any("ghost" in p.message and p.severity is Severity.WARNING for p in problems)


def test_a_failed_login_short_circuits_before_any_probe():
    """Every probe would be denied for a reason unrelated to authorization."""
    def failing_auth(matrix, **kwargs):
        raise AuthError("token endpoint returned 500")

    executor = _executor(_allowed)
    problems = check(MATRIX, "http://t", executor=executor, authenticator=failing_auth)

    assert executor.seen == []
    assert len(problems) == 1
    assert "could not obtain credentials" in problems[0].message


def test_errors_sort_before_warnings():
    def mixed(case):
        if case.subject == "alice":
            return Observation(test_id=case.id, status=403, effect=Effect.DENY)
        return Observation(
            test_id=case.id, status=0, effect=Effect.DENY, skipped=True, error="skipped"
        )

    problems = check(MATRIX, "http://t", executor=_executor(mixed), authenticator=_noop_auth)

    assert [p.severity for p in problems] == [Severity.ERROR, Severity.WARNING]


# --- CLI wiring -------------------------------------------------------------

LIVE_MATRIX = """
modules:
  rest:
    base_url: http://127.0.0.1:1
roles: [user, admin]
subjects:
  - { name: a, role: user, token: t1, attributes: { user_id: u1 } }
  - { name: b, role: user, token: t2, attributes: { user_id: u2 } }
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner: id
    owner_attr: user_id
policy:
  get_user: { allow: [{ role: user, scope: own }] }
"""


def test_live_against_a_dead_target_fails_validate(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(LIVE_MATRIX, encoding="utf-8")

    result = CliRunner().invoke(app, ["validate", str(path), "--live"])

    assert result.exit_code == 1
    assert "did not answer" in result.stdout


def test_without_live_the_same_matrix_passes_offline(tmp_path):
    """The static check must not start depending on a reachable target."""
    path = tmp_path / "matrix.yaml"
    path.write_text(LIVE_MATRIX, encoding="utf-8")

    result = CliRunner().invoke(app, ["validate", str(path)])

    assert result.exit_code == 0
    assert "did not answer" not in result.stdout
