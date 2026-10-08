"""What a run is allowed to claim about the requests it never sent.

Three ways a run can report "no vulnerabilities" while having tested less than
the summary suggests, each covered here:

* the **matrix** could not describe a usable test — a scaffold placeholder
  nobody filled in, a policy naming a resource that does not exist. Every
  request such a matrix sends is refused, so each negative test passes for the
  wrong reason;
* requests were **deliberately skipped** under ``--read-only``, leaving no
  finding, which in every count looks exactly like a probe that ran and found
  the endpoint sound;
* the previous run's **documents** were left in ``--out`` by a run that died
  before writing its own, where they read as current.

The first is the fail-open :mod:`overstep.health` exists to remove, arriving
through the file rather than the network; the other two are disclosure. Each
test here is the one that would have caught the behaviour before it was fixed.
"""
import json
import os

import pytest
from typer.testing import CliRunner

from overstep.cli import EXIT_INCONCLUSIVE, app
from overstep.fixtures import SetupError
from overstep.health import assess
from overstep.models import Effect, Observation, ResourceType, TestCase, Variant
from overstep.pipeline import PipelineError, clear_reports, run_pipeline
from overstep.report import all_reporters
from overstep.report.base import summarize

DEAD_TARGET = "http://127.0.0.1:1"

PLACEHOLDER_MATRIX = """
roles: [anonymous, user]
modules:
  rest:
    base_url: http://127.0.0.1:1
subjects:
  - { name: alice, role: user, token: "PASTE_ALICE_TOKEN", attributes: { user_id: REPLACE_ME_1 } }
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner: id
    owner_attr: user_id
policy:
  get_user:
    allow:
      - { role: user, scope: own }
"""


def _case(case_id: str, expected: Effect, *, resource: str = "r", method: str = "GET") -> TestCase:
    return TestCase(
        id=case_id,
        resource=resource,
        subject="s",
        role="user",
        method=method,
        path_template="/x/{id}",
        path="/x/1",
        variant=Variant.NA,
        expected=expected,
        resource_type=ResourceType.FUNCTION,
    )


def _healthy(cases):
    """Observations from a target that answered every case as the matrix expects."""
    return [
        Observation(
            test_id=c.id,
            status=200 if c.expected == Effect.ALLOW else 403,
            effect=c.expected,
        )
        for c in cases
    ]


# --------------------------------------------------------------------------
# The matrix itself voids the run
# --------------------------------------------------------------------------


def test_a_matrix_error_makes_an_otherwise_healthy_run_inconclusive():
    """The fail-open through the file: this used to exit 0 with "0 vulnerabilities"."""
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]

    health = assess(
        cases,
        _healthy(cases),
        blocking_problems=["subjects[0].token is still the scaffold placeholder"],
    )

    assert health.inconclusive
    assert any("does not describe a usable test" in r for r in health.reasons)
    assert any("scaffold placeholder" in r for r in health.reasons)


def test_a_clean_matrix_is_not_condemned():
    """The negative control: the new path must not fire on a healthy run.

    Without this, making the verdict stricter could quietly declare every run
    inconclusive, which fails *closed* on every target and teaches the reader to
    pass --allow-inconclusive permanently — at which point neither half of the
    check means anything.
    """
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]

    assert not assess(cases, _healthy(cases)).inconclusive
    assert not assess(cases, _healthy(cases), blocking_problems=[]).inconclusive


def test_a_matrix_error_survives_a_run_that_sent_nothing():
    """Recorded before the delivery checks, so the early return still carries it."""
    health = assess([], [], blocking_problems=["policy references unknown resource 'x'"])

    assert health.inconclusive
    assert any("unknown resource" in r for r in health.reasons)


def test_matrix_errors_reach_the_verdict_through_the_pipeline(matrix):
    result = run_pipeline(
        matrix,
        "http://testserver",
        matrix_errors=["subjects[1].attributes.user_id is still 'REPLACE_ME_2'"],
        executor=lambda base_url, subjects, cases, **kw: _healthy(cases),
    )

    assert result.health.inconclusive
    assert result.vulnerabilities == []
    assert summarize(result)["inconclusive"] is True


def test_run_reports_a_placeholder_matrix_as_inconclusive(tmp_path):
    """End to end: the exit code, and the reason that names the value to replace."""
    path = tmp_path / "matrix.yaml"
    path.write_text(PLACEHOLDER_MATRIX, encoding="utf-8")

    result = CliRunner().invoke(app, ["run", str(path), "--out", str(tmp_path / "out")])

    assert result.exit_code == EXIT_INCONCLUSIVE
    assert "does not describe a usable test" in result.stdout
    assert "PASTE_ALICE_TOKEN" in result.stdout


def test_snapshot_refuses_a_baseline_from_a_broken_matrix(tmp_path):
    """A baseline is what every later run is measured against, so this matters more.

    One recorded from a placeholder matrix says "everything is denied", and the
    first healthy run after it is then reported as wholesale authorization
    drift.
    """
    path = tmp_path / "matrix.yaml"
    path.write_text(PLACEHOLDER_MATRIX, encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    result = CliRunner().invoke(app, ["snapshot", str(path), "--out", str(baseline)])

    assert result.exit_code == EXIT_INCONCLUSIVE
    assert not os.path.exists(baseline), "a baseline was written from a matrix that cannot test"


def test_a_warning_does_not_void_a_run(matrix):
    """Only errors reach the verdict.

    A warning describes a matrix that tests less than it looks like — a
    legitimate file with a gap worth naming — and condemning those would make
    the verdict useless by crying wolf on files that work.
    """
    result = run_pipeline(
        matrix,
        "http://testserver",
        matrix_errors=[],
        executor=lambda base_url, subjects, cases, **kw: _healthy(cases),
    )

    assert not result.health.inconclusive


# --------------------------------------------------------------------------
# Skipped requests are disclosed
# --------------------------------------------------------------------------


def test_skipped_requests_are_counted_and_their_surfaces_named():
    cases = [
        _case("get", Effect.ALLOW, resource="user", method="GET"),
        _case("del-self", Effect.DENY, resource="user", method="DELETE"),
        _case("del-other", Effect.DENY, resource="user", method="DELETE"),
    ]
    observations = [
        Observation(test_id="get", status=200, effect=Effect.ALLOW),
        Observation(test_id="del-self", status=0, effect=Effect.DENY, skipped=True),
        Observation(test_id="del-other", status=0, effect=Effect.DENY, skipped=True),
    ]

    health = assess(cases, observations)

    assert health.skipped == 2
    assert health.skipped_surfaces == ["user DELETE"]
    # Skipping is deliberate, so it is disclosure and not a verdict.
    assert not health.inconclusive


def test_a_surface_with_one_request_sent_is_not_called_skipped():
    """The threshold is *every* case, for the same reason it is in untested_surfaces.

    A resource whose GET went out and whose DELETE was skipped was exercised;
    naming it would bury the surface that got nothing at all.
    """
    cases = [
        _case("sent", Effect.DENY, resource="user", method="GET"),
        _case("skipped", Effect.DENY, resource="user", method="GET"),
    ]
    observations = [
        Observation(test_id="sent", status=403, effect=Effect.DENY),
        Observation(test_id="skipped", status=0, effect=Effect.DENY, skipped=True),
    ]

    health = assess(cases, observations)

    assert health.skipped == 1
    assert health.skipped_surfaces == []


def test_read_only_is_recorded_on_the_result_and_in_the_summary(matrix):
    """A --read-only run and a full one used to write identical documents."""

    def _skip_mutating(base_url, subjects, cases, *, read_only=False, **kw):
        return [
            Observation(
                test_id=c.id,
                status=0 if (read_only and c.method != "GET") else 200,
                effect=Effect.DENY if (read_only and c.method != "GET") else c.expected,
                skipped=bool(read_only and c.method != "GET"),
            )
            for c in cases
        ]

    full = run_pipeline(matrix, "http://testserver", executor=_skip_mutating)
    limited = run_pipeline(
        matrix, "http://testserver", read_only=True, executor=_skip_mutating
    )

    assert summarize(full)["read_only"] is False
    assert summarize(limited)["read_only"] is True
    assert "skipped_tests" in summarize(limited)
    assert "skipped_surfaces" in summarize(limited)


def test_the_json_report_distinguishes_a_read_only_run(tmp_path, matrix):
    from overstep.pipeline import write_reports

    result = run_pipeline(
        matrix,
        "http://testserver",
        read_only=True,
        executor=lambda base_url, subjects, cases, **kw: [
            Observation(test_id=c.id, status=0, effect=Effect.DENY, skipped=True)
            for c in cases
        ],
    )
    write_reports(result, str(tmp_path))

    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["read_only"] is True
    assert payload["summary"]["skipped_tests"] == len(result.cases)


# --------------------------------------------------------------------------
# Stale documents from a previous run
# --------------------------------------------------------------------------


def test_clear_reports_removes_every_reporter_owned_file(tmp_path):
    names = [spec.filename for spec in all_reporters()]
    for name in names:
        (tmp_path / name).write_text("stale", encoding="utf-8")
    (tmp_path / "notes.md").write_text("mine", encoding="utf-8")

    removed = clear_reports(str(tmp_path))

    assert sorted(os.path.basename(p) for p in removed) == sorted(names)
    for name in names:
        assert not (tmp_path / name).exists()
    # A directory the user keeps their own files in survives.
    assert (tmp_path / "notes.md").read_text(encoding="utf-8") == "mine"


def test_clear_reports_is_content_with_a_directory_that_does_not_exist(tmp_path):
    assert clear_reports(str(tmp_path / "nope")) == []


def test_clear_reports_refuses_to_leave_a_document_it_could_not_remove(tmp_path):
    """Carrying on would leave exactly the document the function exists to remove."""
    blocker = tmp_path / all_reporters()[0].filename
    blocker.mkdir()

    with pytest.raises(PipelineError) as exc:
        clear_reports(str(tmp_path))

    assert blocker.name in str(exc.value)
    assert "--out" in str(exc.value)


def test_a_run_that_dies_in_setup_leaves_no_stale_report(tmp_path, monkeypatch):
    """The regression: exit 2 used to leave last week's findings.json in place.

    They are indistinguishable from the run the reader just watched fail, and
    the clean ones are the dangerous half — stale findings at least look like
    work to do, while a stale "Vulnerabilities 0" reads as a pass.
    """
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "findings.json"
    stale.write_text('{"summary": {"vulnerabilities": 0}}', encoding="utf-8")

    path = tmp_path / "matrix.yaml"
    path.write_text(PLACEHOLDER_MATRIX, encoding="utf-8")

    def _explode(*args, **kwargs):
        raise SetupError("setup step 'POST /fixtures' returned 500")

    monkeypatch.setattr("overstep.cli.run_pipeline", _explode)

    result = CliRunner().invoke(app, ["run", str(path), "--out", str(out)])

    assert result.exit_code == 2
    assert not stale.exists(), "the previous run's report survived a failed run"


# --------------------------------------------------------------------------
# plan could not read a matrix that keeps its credentials out of the file
# --------------------------------------------------------------------------


def test_plan_reads_credentials_from_an_env_file(tmp_path):
    """Every other command took --env-file; the one meant to be read first did not."""
    path = tmp_path / "matrix.yaml"
    path.write_text(
        """
roles: [anonymous, user]
modules:
  rest:
    base_url: http://testserver
subjects:
  - { name: alice, role: user, token: "${PLAN_ALICE_TOKEN}", attributes: { user_id: u1 } }
  - { name: bob,   role: user, token: "${PLAN_BOB_TOKEN}",   attributes: { user_id: u2 } }
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner: id
    owner_attr: user_id
policy:
  get_user:
    allow:
      - { role: user, scope: own }
""",
        encoding="utf-8",
    )
    env = tmp_path / "creds.env"
    env.write_text("PLAN_ALICE_TOKEN=a\nPLAN_BOB_TOKEN=b\n", encoding="utf-8")

    without = CliRunner().invoke(app, ["plan", str(path)])
    assert without.exit_code == 2, "a missing variable must still fail loudly"

    with_env = CliRunner().invoke(app, ["plan", str(path), "--env-file", str(env)])
    assert with_env.exit_code == 0
    assert "GET /users/u2" in with_env.stdout.replace("\n", "")
