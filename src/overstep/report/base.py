"""Reporter plumbing: a small registry so output formats are pluggable.

Every reporter is a function ``write(result, path)`` registered under a name and a
default filename. The pipeline discovers them through :func:`all_reporters`, so
adding a format is a one-line decorator with no changes to the pipeline or CLI.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence

from overstep.models import Effect, Finding, RunResult, TestCase, Variant, VulnClass

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


def run_info(result: RunResult) -> Dict[str, object]:
    """What a reader needs to know which run a document describes.

    A report used to open on its counts. Nothing in it said what had been
    tested, when, by which version or from which matrix, so a file passed
    along in a ticket could not be told from last month's against staging.
    """
    from overstep import __version__

    from overstep.repro import safe_url

    # Every URL here goes through `safe_url`. A `base_url` or a server `url` may
    # carry credentials in its userinfo — `https://user:password@api.example` is
    # legal and httpx accepts it — and these documents are written to be shared:
    # attached to tickets, uploaded as CI artifacts, read by dashboards. The
    # masking that covers every other credential cannot help, because this one
    # was never declared as a value: it arrived inside a URL, so there is nothing
    # for `credential_values` to have recognised. The host survives, which is
    # the part that says which run this is.
    http = any(case.mcp is None for case in result.cases)
    targets = [safe_url(result.base_url)] if (http and result.base_url) else []
    for case in result.cases:
        if case.mcp is None:
            continue
        # A stdio server is named by its program alone. The arguments belong to
        # whoever wrote the matrix and have no business in a shared document.
        target = safe_url(case.mcp.url) if case.mcp.url else (
            f"stdio: {(case.mcp.command or ['?'])[0]}"
        )
        if target not in targets:
            targets.append(target)
    return {
        "overstep_version": __version__,
        "started_at": result.started_at,
        "duration_s": result.duration_s,
        "matrix": result.source,
        "targets": targets,
        "read_only": result.read_only,
        "partial": result.partial,
        "selection": {key: list(names) for key, names in result.selection.items()},
    }


def case_rows(result: RunResult) -> List[Dict[str, object]]:
    """Every case the run planned, with what came back and how it was judged.

    Findings are the cases that went wrong. The ones that went right were only
    in `junit.xml`, so neither the JSON nor the HTML report could answer "was
    this endpoint tested as this subject, and did it pass?" — which is the
    question a clean report gets asked.

    Nothing of the request beyond its method and path is carried, and nothing
    of the response beyond its status: headers hold the credential and bodies
    hold the target's data, and neither is needed to say a case passed.
    """
    observed = {obs.test_id: obs for obs in result.observations}

    planned = {case.id for case in result.cases}

    def judged(findings: List[Finding]) -> set:
        """The cases these findings are about.

        A finding normally carries its case's id. One derived from a case —
        a tool a listing should not have advertised — is filed under
        `<case id>::<detail>` and belongs to that parent. The parent is only
        looked for when the id is not itself a case: a cross-method probe is a
        case of its own whose id also ends in `::<METHOD>`, and trimming that
        would mark the request it was derived from as failed when it passed.
        """
        ids = set()
        for finding in findings:
            if finding.test_id in planned or "::" not in finding.test_id:
                ids.add(finding.test_id)
            else:
                ids.add(finding.test_id.rsplit("::", 1)[0])
        return ids

    found, waived = judged(result.findings), judged(result.waived)
    rows: List[Dict[str, object]] = []
    for case in result.cases:
        obs = observed.get(case.id)
        if obs is None:
            outcome = "undelivered"
        elif obs.skipped:
            outcome = "skipped"
        elif case.id in found:
            outcome = "finding"
        elif case.id in waived:
            outcome = "waived"
        elif obs.status == 0:
            outcome = "undelivered"
        else:
            outcome = "passed"
        rows.append(
            {
                "test_id": case.id,
                "resource": case.resource,
                "subject": case.subject,
                "role": case.role,
                "method": case.method,
                "path": case.path,
                "variant": case.variant.value,
                "victim": case.victim,
                "expected": case.expected.value,
                "observed": obs.effect.value if obs is not None and not obs.skipped else None,
                "status": obs.status if obs is not None and not obs.skipped else None,
                "outcome": outcome,
                "latency_ms": obs.latency_ms if obs is not None else 0.0,
            }
        )
    return rows


def defects(
    findings: List[Finding], cases: Sequence[TestCase] = ()
) -> List[Dict[str, object]]:
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
    templates = {case.id: case.path_template for case in cases}

    rollup: List[Dict[str, object]] = []
    for group, items in grouped.items():
        first = items[0]
        rollup.append(
            {
                "group": group,
                "vuln_class": first.vuln_class.value,
                "resource": first.resource,
                "method": first.method,
                # Where the defect is, as the API spells it: the template when
                # the cases are to hand, since one defect spans several objects,
                # and otherwise the path of the first probe that found it.
                "path": templates.get(first.test_id) or first.path,
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
    # A positive test is one whose success proves the credential works, which is
    # what `is_positive_control` means and what `expected == ALLOW` only looks
    # like: an enumeration probe is nominally allow-expected but reports on what
    # a listing *contained*, so counting it here would inflate the number of
    # controls a reader (and the README) sees. It gets its own count instead, so
    # the three still add up to the total.
    positive = sum(1 for c in result.cases if c.is_positive_control)
    negative = sum(1 for c in result.cases if c.expected == Effect.DENY)
    listing = sum(1 for c in result.cases if c.variant == Variant.ENUMERATE)
    by_class = Counter(f.vuln_class.value for f in result.findings)
    return {
        "total_tests": len(result.cases),
        "positive_tests": positive,
        "negative_tests": negative,
        # Probes that are neither: they read a listing rather than assert an effect.
        "listing_tests": listing,
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
        # A request that never arrived is not evidence. Counting these keeps
        # "no finding" from reading as "nothing to find" — the negative ones
        # especially, since those are recorded as denied, which is what the
        # matrix expected, so they leave no trace in the finding count at all.
        "undelivered_tests": result.health.transport_errors,
        "undelivered_negative_tests": result.health.undelivered_negative,
        # Surfaces (resource + method) that got nothing through, so this run
        # says nothing about them.
        "untested_surfaces": list(result.health.untested_surfaces),
        # Whether mutating operations were skipped, and which surfaces that cost
        # the run. Without these a --read-only run and a full one produce the
        # same document, so "no findings" cannot be read for how much of the
        # surface it covers.
        "read_only": result.read_only,
        # Whether the run was narrowed to named resources or subjects, to what,
        # and out of how many cases. A partial run's "no findings" covers only
        # what it sent, so the three travel with the counts they qualify.
        "partial": result.partial,
        "selection": {key: list(names) for key, names in result.selection.items()},
        "planned_tests": result.planned_tests,
        "skipped_tests": result.health.skipped,
        "skipped_surfaces": list(result.health.skipped_surfaces),
        # "No BOLA findings" is only evidence for the object resources this run
        # could actually probe across owners; the rest were never asked.
        "object_resources": result.coverage.object_resources,
        "object_resources_probed": result.coverage.probed,
        "object_resources_unprobed": list(result.coverage.unprobed),
    }
