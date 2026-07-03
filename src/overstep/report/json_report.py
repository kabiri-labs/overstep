"""JSON report — the canonical, machine-readable output."""
from __future__ import annotations

import json
import os
from typing import List

from overstep.models import Finding, TestCase
from overstep.report import summarize


def write(cases: List[TestCase], findings: List[Finding], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "summary": summarize(cases, findings),
        "findings": [f.model_dump() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
