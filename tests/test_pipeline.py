"""Tests for the orchestration pipeline and the reporter registry."""
import json

import pytest

from overstep.models import Effect, Observation, RunResult, VulnClass
from overstep.pipeline import (
    InconclusiveRunError,
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


def _dead_target(base_url, subjects, cases, **kwargs):
    """An executor standing in for a target nothing can connect to."""
    return [
        Observation(
            test_id=c.id,
            status=0,
            effect=Effect.DENY,
            error="All connection attempts failed",
        )
        for c in cases
    ]


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


def test_healthy_run_is_marked_conclusive(matrix):
    result = run_pipeline(matrix, executor=_fake_executor())
    assert not result.health.inconclusive
    assert result.health.executed == len(result.cases)


def test_run_against_a_dead_target_is_marked_inconclusive(matrix):
    """The regression this guards: no findings because nothing was ever tested."""
    result = run_pipeline(matrix, executor=_dead_target)

    assert result.vulnerabilities == []      # would have read as a clean bill of health
    assert result.health.inconclusive        # ...but the run proved nothing
    assert result.health.transport_errors == len(result.cases)


def test_snapshot_refuses_to_write_a_baseline_from_a_dead_target(matrix):
    """A baseline of "everything denied" would report the next healthy run as drift."""
    with pytest.raises(InconclusiveRunError) as exc:
        snapshot_pipeline(matrix, executor=_dead_target)
    assert exc.value.health.inconclusive
    assert "never reached the target" in str(exc.value)


def test_snapshot_can_be_forced_past_an_inconclusive_run(matrix):
    snap, _ = snapshot_pipeline(matrix, executor=_dead_target, allow_inconclusive=True)
    assert snap["decisions"]


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


def _finding(**overrides):
    """A minimal finding; overrides pick what the grouping should key on."""
    from overstep.models import Finding, Variant, VulnClass

    fields = {
        "test_id": "t",
        "vuln_class": VulnClass.BOPLA,
        "severity": "high",
        "resource": "get_user",
        "subject": "alice",
        "role": "user",
        "method": "GET",
        "path": "/users/u1",
        "expected": Effect.ALLOW,
        "observed": Effect.ALLOW,
        "status": 200,
        "variant": Variant.SELF,
        "detail": "d",
        "evidence": Observation(test_id="t", status=200, effect=Effect.ALLOW),
    }
    fields.update(overrides)
    return Finding(**fields)


def test_one_defect_seen_by_many_subjects_is_one_group():
    """The regression this guards: triage cost scaled with the number of
    subjects rather than the number of bugs."""
    from overstep.report.base import defects

    findings = [_finding(subject=name, test_id=name) for name in ("alice", "bob", "carol")]

    rollup = defects(findings)

    assert len(rollup) == 1
    assert rollup[0]["findings"] == 3
    assert rollup[0]["subjects"] == ["alice", "bob", "carol"]


def test_the_same_resource_on_another_method_is_a_separate_defect():
    """A resource can be sound on GET and broken on DELETE — two bugs, not one."""
    from overstep.report.base import defects

    rollup = defects([_finding(method="GET"), _finding(method="DELETE")])

    assert len(rollup) == 2


def test_different_vuln_classes_do_not_merge():
    from overstep.models import VulnClass
    from overstep.report.base import defects

    rollup = defects([_finding(vuln_class=VulnClass.BOPLA), _finding(vuln_class=VulnClass.BOLA)])

    assert len(rollup) == 2


def test_a_defect_takes_the_worst_grade_of_its_findings():
    """One confirmed leak makes the defect confirmed, however many probes were
    merely suspected."""
    from overstep.report.base import defects

    rollup = defects([
        _finding(subject="alice", severity="medium", confidence="suspected"),
        _finding(subject="bob", severity="high", confidence="confirmed"),
    ])

    assert rollup[0]["severity"] == "high"
    assert rollup[0]["confidence"] == "confirmed"


def test_defects_are_ordered_worst_first():
    from overstep.report.base import defects

    rollup = defects([
        _finding(resource="low_one", severity="low"),
        _finding(resource="high_one", severity="high"),
        _finding(resource="medium_one", severity="medium"),
    ])

    assert [d["resource"] for d in rollup] == ["high_one", "medium_one", "low_one"]


def test_summary_counts_defects_alongside_findings(matrix):
    from overstep.report.base import summarize

    result = run_pipeline(matrix, executor=_fake_executor(overrides={
        "get_user::alice::other": 200,
        "get_user::bob::other": 200,
    }))
    s = summarize(result)

    # Two subjects walked through the same missing check: two findings, one bug.
    assert s["vulnerabilities"] == 2
    assert s["vulnerability_defects"] == 1


def test_grouping_never_drops_a_finding(matrix):
    """The roll-up is a view, not a filter — every finding stays reachable."""
    from overstep.report.base import defects

    result = run_pipeline(matrix, executor=_fake_executor(overrides={
        "get_user::alice::other": 200,
        "get_user::bob::other": 200,
        "admin_list::alice::na": 200,
    }))

    assert sum(d["findings"] for d in defects(result.findings)) == len(result.findings)
