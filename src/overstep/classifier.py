"""Compare expectations with observations and classify the mismatches.

There are two kinds of mismatch:

* A negative test (expected deny) that was **allowed** is a real authorization
  weakness. We label it BOLA, BFLA or privilege escalation depending on the
  resource type and the subject's role relative to what the policy requires.
* A positive test (expected allow) that was **denied** is an over-restriction —
  not a security hole, but a functional regression worth surfacing.
"""
from __future__ import annotations

from typing import Dict, List

from overstep.matrix import Matrix
from overstep.models import (
    Effect,
    Finding,
    Observation,
    ResourceType,
    TestCase,
    Variant,
    VulnClass,
)


def _min_required_rank(matrix: Matrix, case: TestCase) -> int:
    ranks = [matrix.role_rank(r) for r in case.required_roles]
    ranks = [r for r in ranks if r >= 0]
    return min(ranks) if ranks else -1


def _classify_violation(matrix: Matrix, case: TestCase) -> VulnClass:
    """A negative test slipped through — decide which flavour of broken authz."""
    subject_rank = matrix.role_rank(case.role)
    required_rank = _min_required_rank(matrix, case)

    # Vertical escalation: the subject reached something only a strictly more
    # privileged role should be able to reach.
    if subject_rank >= 0 and required_rank >= 0 and subject_rank < required_rank:
        return VulnClass.PRIVILEGE_ESCALATION

    if case.resource_type == ResourceType.OBJECT and case.variant == Variant.OTHER:
        return VulnClass.BOLA
    return VulnClass.BFLA


def _detail(case: TestCase, obs: Observation, vuln: VulnClass) -> str:
    if vuln == VulnClass.BOLA:
        return (
            f"{case.subject} ({case.role}) read another subject's object via "
            f"{case.method} {case.path} and got {obs.status}; the matrix only "
            f"allows owners here."
        )
    if vuln == VulnClass.PRIVILEGE_ESCALATION:
        allowed = ", ".join(case.required_roles) or "a higher-privileged role"
        return (
            f"{case.subject} ({case.role}) reached {case.method} {case.path} "
            f"(status {obs.status}) which the matrix reserves for {allowed}."
        )
    return (
        f"{case.subject} ({case.role}) invoked {case.method} {case.path} "
        f"(status {obs.status}) but has no allow rule for it."
    )


def classify(matrix: Matrix, cases: List[TestCase], observations: List[Observation]) -> List[Finding]:
    """Produce findings from expectations vs. observations."""
    by_id: Dict[str, TestCase] = {c.id: c for c in cases}
    findings: List[Finding] = []

    for obs in observations:
        case = by_id.get(obs.test_id)
        if case is None:
            continue

        if case.expected == Effect.ALLOW:
            if obs.effect == Effect.DENY:
                findings.append(
                    Finding(
                        test_id=case.id,
                        vuln_class=VulnClass.UNEXPECTED_DENY,
                        severity="low",
                        resource=case.resource,
                        subject=case.subject,
                        role=case.role,
                        method=case.method,
                        path=case.path,
                        expected=case.expected,
                        observed=obs.effect,
                        status=obs.status,
                        variant=case.variant,
                        detail=(
                            f"{case.subject} ({case.role}) should be allowed "
                            f"{case.method} {case.path} but was denied "
                            f"(status {obs.status})."
                        ),
                        evidence=obs,
                    )
                )
            continue

        # Negative test.
        if obs.effect == Effect.ALLOW:
            vuln = _classify_violation(matrix, case)
            findings.append(
                Finding(
                    test_id=case.id,
                    vuln_class=vuln,
                    severity="high",
                    resource=case.resource,
                    subject=case.subject,
                    role=case.role,
                    method=case.method,
                    path=case.path,
                    expected=case.expected,
                    observed=obs.effect,
                    status=obs.status,
                    variant=case.variant,
                    detail=_detail(case, obs, vuln),
                    evidence=obs,
                )
            )

    # Highest severity, then stable by test id, so reports read consistently.
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.test_id))
    return findings
