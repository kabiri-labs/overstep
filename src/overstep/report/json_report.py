"""JSON report — the canonical, machine-readable output."""
from __future__ import annotations

import json
import os

from overstep.models import RunResult
from overstep.report.base import register, summarize


@register("json", "findings.json")
def write(result: RunResult, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "base_url": result.base_url,
        "summary": summarize(result),
        "findings": [f.model_dump() for f in result.findings],
        "waived": [f.model_dump() for f in result.waived],
        "warnings": result.warnings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
