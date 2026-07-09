"""JSON report — the canonical, machine-readable output."""
from __future__ import annotations

import json
import os

from overstep.models import Finding, RunResult
from overstep.report.base import register, summarize
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
        "summary": summarize(result),
        "findings": [_dump(f) for f in result.findings],
        "waived": [_dump(f) for f in result.waived],
        "warnings": result.warnings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
