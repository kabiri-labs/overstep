"""Tests for the orchestration pipeline and the reporter registry."""
import json

import pytest

from overstep.models import Effect, Observation, RunResult, VulnClass
from overstep.pipeline import (
    PipelineError,
    resolve_base_url,
    run_pipeline,
    snapshot_pipeline,
    write_reports,
)
from overstep.planner import plan
from overstep.report import all_reporters


def _fake_executor(overrides=None):
    """Build an executor stub that echoes the matrix expectation, with overrides."""
    overrides = overrides or {}

    def _exec(base_url, subjects, cases, *, concurrency=10, verify_tls=True, **kwargs):
        obs = []
        for c in cases:
            status = overrides.get(c.id, 200 if c.expected == Effect.ALLOW else 403)
            effect = Effect.ALLOW if status in (200, 201, 204) else Effect.DENY
            obs.append(Observation(test_id=c.id, status=status, effect=effect))
        return obs

    return _exec


def test_resolve_base_url_prefers_override(matrix):
    assert resolve_base_url(matrix, "http://other") == "http://other"
    assert resolve_base_url(matrix, None) == matrix.base_url


def test_resolve_base_url_requires_a_value():
    from overstep.matrix import Matrix

    with pytest.raises(PipelineError):
        resolve_base_url(Matrix(subjects=[], resources=[]), None)


def test_clean_run_reports_no_vulnerabilities(matrix):
    result = run_pipeline(matrix, executor=_fake_executor())
    assert isinstance(result, RunResult)
    assert result.vulnerabilities == []
    assert len(result.cases) == len(result.observations)


def test_pipeline_surfaces_bola(matrix):
    executor = _fake_executor(overrides={"get_user::alice::other": 200})
    result = run_pipeline(matrix, executor=executor)
    assert any(f.vuln_class == VulnClass.BOLA for f in result.vulnerabilities)


def test_pipeline_applies_baseline_drift(matrix):
    clean = run_pipeline(matrix, executor=_fake_executor())
    baseline = {
        "decisions": {
            o.test_id: {"observed": o.effect.value} for o in clean.observations
        }
    }
    # Now the BOLA probe starts succeeding -> both a vuln and a drift finding.
    executor = _fake_executor(overrides={"get_user::alice::other": 200})
    result = run_pipeline(matrix, baseline=baseline, executor=executor)
    assert result.drift
    assert result.vulnerabilities


def test_snapshot_pipeline_records_every_decision(matrix):
    """snapshot shares the run orchestration: every planned case gets a decision."""
    snap, warnings = snapshot_pipeline(matrix, executor=_fake_executor())
    assert set(snap["decisions"]) == {c.id for c in plan(matrix)}
    assert snap["tool"] == "overstep"
    assert warnings == []


def test_snapshot_pipeline_goes_through_the_injected_executor(matrix):
    """The snapshot must observe what the (dispatched) executor returns, so an
    override on the shared executor flows into the recorded decision."""
    executor = _fake_executor(overrides={"get_user::alice::other": 200})
    snap, _ = snapshot_pipeline(matrix, executor=executor)
    assert snap["decisions"]["get_user::alice::other"]["observed"] == Effect.ALLOW.value


def test_snapshot_pipeline_surfaces_teardown_warnings(matrix):
    """A fixture-cleanup failure during snapshot must not be swallowed."""
    def noisy_teardown(*args, **kwargs):
        return ["could not delete fixture order-1"]

    snap, warnings = snapshot_pipeline(
        matrix, executor=_fake_executor(), teardown_runner=noisy_teardown
    )
    assert snap["decisions"]
    assert "could not delete fixture order-1" in warnings


def test_run_teardown_runs_even_when_the_executor_raises(matrix):
    """Teardown must execute in a finally, so a crash mid-run still cleans up."""
    calls = []

    def boom(*args, **kwargs):
        raise RuntimeError("executor exploded")

    def spy_teardown(*args, **kwargs):
        calls.append("teardown")
        return []

    with pytest.raises(RuntimeError, match="executor exploded"):
        run_pipeline(matrix, executor=boom, teardown_runner=spy_teardown)
    assert calls == ["teardown"]


def test_snapshot_teardown_runs_even_when_the_executor_raises(matrix):
    calls = []

    def boom(*args, **kwargs):
        raise RuntimeError("executor exploded")

    def spy_teardown(*args, **kwargs):
        calls.append("teardown")
        return []

    with pytest.raises(RuntimeError, match="executor exploded"):
        snapshot_pipeline(matrix, executor=boom, teardown_runner=spy_teardown)
    assert calls == ["teardown"]


def test_teardown_warnings_surface_on_a_clean_run(matrix):
    def noisy_teardown(*args, **kwargs):
        return ["could not delete fixture order-1"]

    result = run_pipeline(matrix, executor=_fake_executor(), teardown_runner=noisy_teardown)
    assert "could not delete fixture order-1" in result.warnings


def test_write_reports_emits_every_registered_format(matrix, tmp_path):
    result = run_pipeline(matrix, executor=_fake_executor())
    written = write_reports(result, str(tmp_path))

    assert len(written) == len(all_reporters()) >= 4
    # JSON is machine-readable and should round-trip.
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["summary"]["total_tests"] == len(result.cases)
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "overstep.sarif").exists()
    assert (tmp_path / "junit.xml").exists()
