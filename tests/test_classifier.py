"""Tests for turning observations into classified findings."""
from overstep.classifier import classify
from overstep.models import Effect, Observation, VulnClass
from overstep.planner import plan


def _obs(test_id, status):
    effect = Effect.ALLOW if status in (200, 201, 204) else Effect.DENY
    return Observation(test_id=test_id, status=status, effect=effect)


def test_bola_when_user_reads_other_object(matrix):
    cases = plan(matrix)
    # Everything denied except the BOLA probe, which the target wrongly allows.
    obs = []
    for c in cases:
        status = 200 if c.id == "get_user::alice::other" else (200 if c.expected == Effect.ALLOW else 403)
        obs.append(_obs(c.id, status))

    findings = classify(matrix, cases, obs)
    bola = [f for f in findings if f.vuln_class == VulnClass.BOLA]
    assert len(bola) == 1
    assert bola[0].test_id == "get_user::alice::other"
    assert bola[0].severity == "high"


def test_privilege_escalation_when_user_hits_admin_function(matrix):
    cases = plan(matrix)
    obs = [_obs(c.id, 200 if (c.expected == Effect.ALLOW or c.id == "admin_list::alice::na") else 403)
           for c in cases]

    findings = classify(matrix, cases, obs)
    privesc = [f for f in findings if f.vuln_class == VulnClass.PRIVILEGE_ESCALATION]
    assert any(f.test_id == "admin_list::alice::na" for f in privesc)


def test_unexpected_deny_is_low_severity(matrix):
    cases = plan(matrix)
    # A positive test the target wrongly denies.
    obs = [_obs(c.id, 403 if c.id == "get_user::alice::self" else (200 if c.expected == Effect.ALLOW else 403))
           for c in cases]

    findings = classify(matrix, cases, obs)
    denies = [f for f in findings if f.vuln_class == VulnClass.UNEXPECTED_DENY]
    assert len(denies) == 1
    assert denies[0].severity == "low"


def test_clean_run_has_no_findings(matrix):
    cases = plan(matrix)
    # The target behaves exactly as the matrix expects.
    obs = [_obs(c.id, 200 if c.expected == Effect.ALLOW else 403) for c in cases]
    assert classify(matrix, cases, obs) == []
