"""Tests for CLI-level behaviour: the --fail-on gate, its validation, and the
refusal to report success for a run that never reached the target."""
import json
import os

import pytest
import typer
from typer.testing import CliRunner

from overstep.cli import EXIT_INCONCLUSIVE, FAIL_ON_CHOICES, _exit_code, _validate_fail_on, app
from overstep.models import (
    Effect,
    Finding,
    Observation,
    RunResult,
    Variant,
    VulnClass,
)


def _finding(vuln_class: VulnClass) -> Finding:
    obs = Observation(test_id="t", status=200, effect=Effect.ALLOW)
    return Finding(
        test_id="t",
        vuln_class=vuln_class,
        severity="high",
        resource="r",
        subject="s",
        role="user",
        method="GET",
        path="/x",
        expected=Effect.DENY,
        observed=Effect.ALLOW,
        status=200,
        variant=Variant.OTHER,
        detail="d",
        evidence=obs,
    )


def _result(*vuln_classes: VulnClass) -> RunResult:
    return RunResult(base_url="http://t", findings=[_finding(v) for v in vuln_classes])


def test_never_is_always_zero():
    assert _exit_code(_result(VulnClass.BOLA), "never") == 0
    assert _exit_code(_result(), "never") == 0


def test_vuln_fails_only_on_vulnerabilities():
    assert _exit_code(_result(VulnClass.BOLA), "vuln") == 1
    assert _exit_code(_result(VulnClass.AUTHORIZATION_DRIFT), "vuln") == 0
    assert _exit_code(_result(VulnClass.UNEXPECTED_DENY), "vuln") == 0
    assert _exit_code(_result(), "vuln") == 0


def test_drift_fails_only_on_drift():
    # The key fix: a pre-existing vulnerability must NOT trip --fail-on drift.
    assert _exit_code(_result(VulnClass.BOLA), "drift") == 0
    assert _exit_code(_result(VulnClass.AUTHORIZATION_DRIFT), "drift") == 1
    assert _exit_code(_result(), "drift") == 0


def test_vuln_or_drift_fails_on_either():
    assert _exit_code(_result(VulnClass.BOLA), "vuln-or-drift") == 1
    assert _exit_code(_result(VulnClass.AUTHORIZATION_DRIFT), "vuln-or-drift") == 1
    assert _exit_code(_result(VulnClass.UNEXPECTED_DENY), "vuln-or-drift") == 0
    assert _exit_code(_result(), "vuln-or-drift") == 0


def test_any_fails_on_any_active_finding():
    assert _exit_code(_result(VulnClass.UNEXPECTED_DENY), "any") == 1
    assert _exit_code(_result(VulnClass.BOLA), "any") == 1
    assert _exit_code(_result(), "any") == 0


def test_fail_on_is_case_insensitive():
    assert _exit_code(_result(VulnClass.AUTHORIZATION_DRIFT), "DRIFT") == 1


def test_validate_fail_on_accepts_every_documented_choice():
    for choice in FAIL_ON_CHOICES:
        _validate_fail_on(choice)  # must not raise
    _validate_fail_on("VULN-OR-DRIFT")  # case-insensitive


def test_validate_fail_on_rejects_unknown_value():
    with pytest.raises(typer.Exit) as exc:
        _validate_fail_on("sometimes")
    assert exc.value.exit_code == 2


# Port 1 is privileged and never bound, so a connection there is refused
# immediately — a dead target with no network dependency and no waiting.
DEAD_TARGET = "http://127.0.0.1:1"

MATRIX = """
base_url: http://127.0.0.1:1
roles: [anonymous, user, admin]
subjects:
  - { name: alice, role: user, token: a, attributes: { user_id: u1 } }
  - { name: root, role: admin, token: r, attributes: { user_id: u9 } }
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner_param: id
    owner_attr: user_id
policy:
  get_user:
    allow:
      - { role: user, scope: own }
      - { role: admin, scope: any }
"""


@pytest.fixture
def matrix_file(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    return path


def test_run_against_a_dead_target_exits_inconclusive(matrix_file, tmp_path):
    """The fail-open regression: this used to print "0 vulnerabilities" and exit 0."""
    result = CliRunner().invoke(
        app, ["run", str(matrix_file), "--base", DEAD_TARGET, "--out", str(tmp_path / "out")]
    )

    assert result.exit_code == EXIT_INCONCLUSIVE
    assert "inconclusive run" in result.stdout


def test_inconclusive_beats_fail_on_never(matrix_file, tmp_path):
    """--fail-on governs findings; it cannot vouch for a run that never happened."""
    result = CliRunner().invoke(
        app,
        ["run", str(matrix_file), "--base", DEAD_TARGET, "--out", str(tmp_path / "out"),
         "--fail-on", "never"],
    )

    assert result.exit_code == EXIT_INCONCLUSIVE


def test_allow_inconclusive_restores_the_old_exit_code(matrix_file, tmp_path):
    result = CliRunner().invoke(
        app,
        ["run", str(matrix_file), "--base", DEAD_TARGET, "--out", str(tmp_path / "out"),
         "--allow-inconclusive"],
    )

    assert result.exit_code == 0
    # Still reported, so the escape hatch does not hide the problem.
    assert "inconclusive run" in result.stdout


def test_inconclusive_verdict_reaches_the_json_report(matrix_file, tmp_path):
    out = tmp_path / "out"
    CliRunner().invoke(
        app,
        ["run", str(matrix_file), "--base", DEAD_TARGET, "--out", str(out),
         "--allow-inconclusive"],
    )

    payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["vulnerabilities"] == 0
    assert payload["summary"]["inconclusive"] is True
    assert payload["summary"]["inconclusive_reasons"]


def test_snapshot_against_a_dead_target_writes_no_baseline(matrix_file, tmp_path):
    baseline = tmp_path / "baseline.json"
    result = CliRunner().invoke(
        app, ["snapshot", str(matrix_file), "--base", DEAD_TARGET, "--out", str(baseline)]
    )

    assert result.exit_code == EXIT_INCONCLUSIVE
    assert not os.path.exists(baseline), "a false 'all denied' baseline was written"
