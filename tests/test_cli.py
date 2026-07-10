"""Tests for CLI-level behaviour: the --fail-on gate and its validation."""
import pytest
import typer

from overstep.cli import FAIL_ON_CHOICES, _exit_code, _validate_fail_on
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
