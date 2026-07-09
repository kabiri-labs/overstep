"""Tests for the orchestration pipeline and the reporter registry."""
import json

import pytest

from overstep.models import Effect, Observation, RunResult, VulnClass
from overstep.pipeline import PipelineError, resolve_base_url, run_pipeline, write_reports
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
