"""Tests for snapshotting and drift detection."""
from overstep.drift import build_snapshot, diff
from overstep.models import Effect, Observation, VulnClass
from overstep.planner import plan


def _obs(cases, overrides=None):
    overrides = overrides or {}
    out = []
    for c in cases:
        status = overrides.get(c.id, 200 if c.expected == Effect.ALLOW else 403)
        effect = Effect.ALLOW if status in (200, 201, 204) else Effect.DENY
        out.append(Observation(test_id=c.id, status=status, effect=effect))
    return out


def test_snapshot_roundtrips_every_case(matrix):
    cases = plan(matrix)
    snap = build_snapshot(cases, _obs(cases))
    assert set(snap["decisions"]) == {c.id for c in cases}


def test_no_drift_when_identical(matrix):
    cases = plan(matrix)
    obs = _obs(cases)
    snap = build_snapshot(cases, obs)
    assert diff(snap, cases, obs) == []


def test_drift_flags_newly_opened_access(matrix):
    cases = plan(matrix)
    baseline = build_snapshot(cases, _obs(cases))  # secure baseline
    # Now the BOLA probe starts succeeding.
    now = _obs(cases, overrides={"get_user::alice::other": 200})

    findings = diff(baseline, cases, now)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == VulnClass.AUTHORIZATION_DRIFT
    assert f.test_id == "get_user::alice::other"
    assert f.severity == "high"   # deny -> allow is the dangerous direction


def test_drift_flags_tightened_access_as_medium(matrix):
    cases = plan(matrix)
    baseline = build_snapshot(cases, _obs(cases))
    # A positive test starts failing (allow -> deny).
    now = _obs(cases, overrides={"get_user::alice::self": 403})

    findings = diff(baseline, cases, now)
    assert findings[0].severity == "medium"
