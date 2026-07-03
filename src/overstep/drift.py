"""Authorization drift: compare this run's decisions to a saved baseline.

The point of a security tool in CI is catching *changes*. A snapshot records the
allow/deny decision the target actually made for every test case. On the next
run we diff against it: a cell that flipped from deny to allow is a newly opened
hole; allow to deny is a new restriction (often benign, occasionally an outage).
Either way the matrix and the snapshot together pin the authorization surface in
place so nothing moves silently between releases.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List

from overstep import __version__
from overstep.models import Effect, Finding, Observation, TestCase, VulnClass


def build_snapshot(cases: List[TestCase], observations: List[Observation]) -> dict:
    """Serialize the decision each test case produced."""
    by_id = {c.id: c for c in cases}
    decisions = {}
    for obs in observations:
        case = by_id.get(obs.test_id)
        if case is None:
            continue
        decisions[obs.test_id] = {
            "resource": case.resource,
            "subject": case.subject,
            "method": case.method,
            "path": case.path,
            "expected": case.expected.value,
            "observed": obs.effect.value,
            "status": obs.status,
        }
    return {
        "tool": "overstep",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "decisions": decisions,
    }


def save_snapshot(snapshot: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)


def load_snapshot(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def diff(baseline: dict, cases: List[TestCase], observations: List[Observation]) -> List[Finding]:
    """Report every test whose observed decision changed since the baseline."""
    base_decisions: Dict[str, dict] = baseline.get("decisions", {})
    by_id = {c.id: c for c in cases}
    findings: List[Finding] = []

    for obs in observations:
        case = by_id.get(obs.test_id)
        prior = base_decisions.get(obs.test_id)
        if case is None or prior is None:
            continue

        was = prior.get("observed")
        now = obs.effect.value
        if was == now:
            continue

        opened = was == Effect.DENY.value and now == Effect.ALLOW.value
        severity = "high" if opened else "medium"
        direction = "opened up (deny -> allow)" if opened else "tightened (allow -> deny)"
        findings.append(
            Finding(
                test_id=case.id,
                vuln_class=VulnClass.AUTHORIZATION_DRIFT,
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
                detail=(
                    f"Access for {case.subject} on {case.method} {case.path} "
                    f"{direction} since the baseline."
                ),
                evidence=obs,
            )
        )

    findings.sort(key=lambda f: (0 if f.severity == "high" else 1, f.test_id))
    return findings
