"""Compare expectations with observations and classify the mismatches.

There are two kinds of mismatch:

* A negative test (expected deny) that was **allowed** is a real authorization
  weakness. We label it BOLA, BFLA or privilege escalation depending on the
  resource type and the subject's role relative to what the policy requires.
* A positive test (expected allow) that was **denied** is an over-restriction —
  not a security hole, but a functional regression worth surfacing.
"""
from __future__ import annotations

import json
from typing import Dict, List, Set

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
from overstep.repro import request_record, to_curl


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


def _json_keys(body: str) -> Set[str]:
    """Every object key that appears anywhere in a JSON body (recursively).

    Returns an empty set when the body is not valid JSON, so BOPLA checks match
    real property *keys* rather than substrings of arbitrary text.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return set()

    keys: Set[str] = set()

    def _walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                keys.add(key)
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return keys


def _leaked_fields(resource, obs: Observation) -> Set[str]:
    """Forbidden JSON keys present in an allowed response (BOPLA surface)."""
    if resource is None or not resource.forbidden_fields:
        return set()
    present = _json_keys(obs.body_snippet)
    return {f for f in resource.forbidden_fields if f in present}


def _grade(vuln: VulnClass, case: TestCase, obs: Observation):
    """Assign (severity, confidence) using the content-aware oracle.

    Only object-level probes (BOLA) can be content-verified: we know the victim's
    marker. When it shows up in the body the leak is *confirmed*; when a marker was
    configured but never appeared the grant is *suspected* (possibly an empty
    result) and downgraded; with no marker at all we fall back to status alone and
    label the finding *unverified*.
    """
    if vuln != VulnClass.BOLA:
        return "high", "confirmed"
    if not case.expect_markers:
        return "high", "unverified"
    if obs.matched_markers:
        return "high", "confirmed"
    return "medium", "suspected"


def _detail(case: TestCase, obs: Observation, vuln: VulnClass, confidence: str = "confirmed") -> str:
    if vuln == VulnClass.BOLA:
        if confidence == "confirmed":
            leaked = ", ".join(obs.matched_markers)
            proof = (
                f" and the response exposed the owner's data ({leaked})"
                if leaked
                else ""
            )
            return (
                f"{case.subject} ({case.role}) read another subject's object via "
                f"{case.method} {case.path} and got {obs.status}{proof}; the matrix "
                f"only allows owners here."
            )
        if confidence == "suspected":
            return (
                f"{case.subject} ({case.role}) was granted {case.method} {case.path} "
                f"(status {obs.status}) on another subject's object, but the expected "
                f"owner data did not appear — suspected BOLA, verify manually."
            )
        return (
            f"{case.subject} ({case.role}) read another subject's object via "
            f"{case.method} {case.path} and got {obs.status}; the matrix only "
            f"allows owners here (no content marker configured to confirm the leak)."
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


def classify(
    matrix: Matrix,
    cases: List[TestCase],
    observations: List[Observation],
    *,
    base_url: str = "",
) -> List[Finding]:
    """Produce findings from expectations vs. observations.

    ``base_url`` (defaulting to the matrix's own) is used to render a
    reproduction (``curl`` + a masked request record) onto every finding.
    """
    by_id: Dict[str, TestCase] = {c.id: c for c in cases}
    by_case: Dict[str, TestCase] = by_id
    subjects = {s.name: s for s in matrix.subjects}
    resources = matrix.resource_map()
    repro_base = base_url or matrix.base_url or ""
    findings: List[Finding] = []

    for obs in observations:
        case = by_id.get(obs.test_id)
        if case is None:
            continue
        # A deliberately skipped request (read-only) is not evidence either way.
        if obs.skipped:
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
            elif obs.effect == Effect.ALLOW:
                # BOPLA: an allowed read that over-shares forbidden properties.
                leaked = _leaked_fields(resources.get(case.resource), obs)
                if leaked:
                    fields = ", ".join(sorted(leaked))
                    findings.append(
                        Finding(
                            test_id=case.id,
                            vuln_class=VulnClass.BOPLA,
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
                            detail=(
                                f"{case.subject} ({case.role}) was allowed "
                                f"{case.method} {case.path} but the response exposed "
                                f"forbidden field(s): {fields}."
                            ),
                            evidence=obs,
                        )
                    )
            continue

        # Negative test.
        if obs.effect == Effect.ALLOW:
            vuln = _classify_violation(matrix, case)
            severity, confidence = _grade(vuln, case, obs)
            findings.append(
                Finding(
                    test_id=case.id,
                    vuln_class=vuln,
                    severity=severity,
                    resource=case.resource,
                    subject=case.subject,
                    role=case.role,
                    method=case.method,
                    path=case.path,
                    expected=case.expected,
                    observed=obs.effect,
                    status=obs.status,
                    variant=case.variant,
                    detail=_detail(case, obs, vuln, confidence),
                    evidence=obs,
                    confidence=confidence,
                )
            )

    # Attach a copy-pasteable reproduction to every finding.
    for f in findings:
        case = by_case.get(f.test_id)
        subject = subjects.get(f.subject)
        if case is not None and subject is not None:
            f.curl = to_curl(repro_base, subject, case)
            f.request = request_record(repro_base, subject, case)

    # Highest severity, then stable by test id, so reports read consistently.
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.test_id))
    return findings
