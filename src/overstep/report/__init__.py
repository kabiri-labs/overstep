"""Reporters that turn findings into machine- and human-readable output."""
from __future__ import annotations

from collections import Counter
from typing import Dict, List

from overstep.models import Effect, Finding, TestCase, VulnClass


def summarize(cases: List[TestCase], findings: List[Finding]) -> Dict[str, object]:
    """A compact roll-up used by the CLI and the JSON/HTML reports."""
    positive = sum(1 for c in cases if c.expected == Effect.ALLOW)
    negative = sum(1 for c in cases if c.expected == Effect.DENY)
    by_class = Counter(f.vuln_class.value for f in findings)
    vulns = sum(
        1
        for f in findings
        if f.vuln_class
        in (
            VulnClass.BOLA,
            VulnClass.BFLA,
            VulnClass.PRIVILEGE_ESCALATION,
        )
    )
    return {
        "total_tests": len(cases),
        "positive_tests": positive,
        "negative_tests": negative,
        "findings": len(findings),
        "vulnerabilities": vulns,
        "by_class": dict(by_class),
    }
