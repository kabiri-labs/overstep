"""JUnit XML report so CI test dashboards can render overstep results.

Every test case becomes a ``<testcase>``; a finding turns it into a failure.
Positive tests that passed and negative tests that were correctly denied show up
as green, giving a familiar pass/fail view of the authorization surface.
"""
from __future__ import annotations

import os
from typing import Dict
from xml.sax.saxutils import escape, quoteattr

from overstep.models import Finding, RunResult
from overstep.report.base import register


@register("junit", "junit.xml")
def write(result: RunResult, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    by_test: Dict[str, Finding] = {f.test_id: f for f in result.findings}

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        f'<testsuite name="overstep" tests="{len(result.cases)}" failures="{len(result.findings)}">'
    )
    for case in result.cases:
        name = quoteattr(f"{case.method} {case.path} [{case.subject}/{case.variant.value}]")
        classname = quoteattr(case.resource)
        finding = by_test.get(case.id)
        if finding is None:
            lines.append(f"  <testcase classname={classname} name={name}/>")
        else:
            msg = quoteattr(f"{finding.vuln_class.value}: {finding.detail}")
            lines.append(f"  <testcase classname={classname} name={name}>")
            lines.append(
                f"    <failure type={quoteattr(finding.vuln_class.value)} message={msg}>"
                f"{escape(finding.detail)}</failure>"
            )
            lines.append("  </testcase>")
    lines.append("</testsuite>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
