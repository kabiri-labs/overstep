"""Reporter plumbing: a small registry so output formats are pluggable.

Every reporter is a function ``write(result, path)`` registered under a name and a
default filename. The pipeline discovers them through :func:`all_reporters`, so
adding a format is a one-line decorator with no changes to the pipeline or CLI.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List

from overstep.models import Effect, Finding, RunResult, VulnClass

WriteFn = Callable[[RunResult, str], None]


@dataclass(frozen=True)
class ReporterSpec:
    name: str
    filename: str
    write: WriteFn


_REGISTRY: Dict[str, ReporterSpec] = {}


def register(name: str, filename: str) -> Callable[[WriteFn], WriteFn]:
    def decorator(fn: WriteFn) -> WriteFn:
        _REGISTRY[name] = ReporterSpec(name=name, filename=filename, write=fn)
        return fn

    return decorator


def all_reporters() -> List[ReporterSpec]:
    return list(_REGISTRY.values())


def get_reporter(name: str) -> ReporterSpec:
    return _REGISTRY[name]


def defects(findings: List[Finding]) -> List[Dict[str, object]]:
    """Roll findings up into the distinct defects behind them.

    One missing check is reported once per identity that reaches it, so a single
    bug can arrive as a dozen findings and triage cost tracks the size of the
    matrix rather than the number of bugs. Grouping keeps every finding intact
    while giving a caller the shorter list to work from — the subjects become
    evidence of blast radius instead of separate work items.
    """
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.group, []).append(finding)

    rollup: List[Dict[str, object]] = []
    for group, items in grouped.items():
        first = items[0]
        rollup.append(
            {
                "group": group,
                "vuln_class": first.vuln_class.value,
                "resource": first.resource,
                "method": first.method,
                # The worst grade any identity saw: one confirmed leak makes the
                # defect confirmed even if other probes were only suspected.
                "severity": min((f.severity for f in items), key=_SEVERITY_ORDER.index),
                "confidence": min((f.confidence for f in items), key=_CONFIDENCE_ORDER.index),
                "findings": len(items),
                "subjects": sorted({f.subject for f in items}),
                "example_test_id": first.test_id,
            }
        )
    rollup.sort(key=lambda d: (_SEVERITY_ORDER.index(d["severity"]), -d["findings"]))
    return rollup


_SEVERITY_ORDER = ["high", "medium", "low"]
_CONFIDENCE_ORDER = ["confirmed", "suspected", "unverified"]


def summarize(result: RunResult) -> Dict[str, object]:
    """A compact roll-up used by the CLI and the JSON/HTML reports."""
    positive = sum(1 for c in result.cases if c.expected == Effect.ALLOW)
    negative = sum(1 for c in result.cases if c.expected == Effect.DENY)
    by_class = Counter(f.vuln_class.value for f in result.findings)
    return {
        "total_tests": len(result.cases),
        "positive_tests": positive,
        "negative_tests": negative,
        "findings": len(result.findings),
        "vulnerabilities": len(result.vulnerabilities),
        # How many distinct defects those findings represent — the number of
        # things somebody has to go and fix.
        "defects": len({f.group for f in result.findings}),
        "vulnerability_defects": len({f.group for f in result.vulnerabilities}),
        "drift": len(result.drift),
        "waived": len(result.waived),
        "by_class": dict(by_class),
        # A consumer must not read "vulnerabilities: 0" as "none exist" when the
        # run never reached the target, so the verdict travels with the counts.
        "inconclusive": result.health.inconclusive,
        "inconclusive_reasons": list(result.health.reasons),
        # "No BOLA findings" is only evidence for the object resources this run
        # could actually probe across owners; the rest were never asked.
        "object_resources": result.coverage.object_resources,
        "object_resources_probed": result.coverage.probed,
        "object_resources_unprobed": list(result.coverage.unprobed),
    }
