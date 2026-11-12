"""JSON report — the canonical, machine-readable output."""
from __future__ import annotations

import json
import os

from overstep.models import Finding, RunResult
from overstep.report.base import case_rows, defects, register, run_info, summarize
from overstep.taxonomy import TAXONOMY


def _dump(f: Finding) -> dict:
    data = f.model_dump()
    tax = TAXONOMY[f.vuln_class]
    data["cwe"] = tax.cwe
    data["owasp_api"] = tax.owasp_api
    return data


@register("json", "findings.json")
def write(result: RunResult, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "base_url": result.base_url,
        # Which run this is: target, time, version, matrix and how it was scoped.
        "run": run_info(result),
        "summary": summarize(result),
        # One entry per distinct defect, worst first — the work list. Every
        # finding is still below, so nothing is lost by collapsing here.
        "defects": defects(result.findings, result.cases),
        "findings": [_dump(f) for f in result.findings],
        "waived": [_dump(f) for f in result.waived],
        "warnings": result.warnings,
        # Every case, passed ones included — what was tested, not only what
        # failed. Last, so the findings stay at the top of a file read by eye.
        "cases": case_rows(result),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
