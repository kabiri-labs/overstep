"""SARIF 2.1.0 report so findings show up in GitHub code scanning."""
from __future__ import annotations

import json
import os
from typing import List

from overstep import __version__
from overstep.models import RunResult, VulnClass
from overstep.report.base import register
from overstep.taxonomy import TAXONOMY, sarif_tags

_LEVEL = {"high": "error", "medium": "warning", "low": "note"}

_RULE_HELP = {
    VulnClass.BOLA: "Broken Object Level Authorization: a subject accessed an object it does not own.",
    VulnClass.BFLA: "Broken Function Level Authorization: a subject invoked a function it is not permitted to.",
    VulnClass.BOPLA: "Broken Object Property Level Authorization: an allowed response exposed a property the caller should not see.",
    VulnClass.PRIVILEGE_ESCALATION: "A subject reached a resource reserved for a more privileged role.",
    VulnClass.AUTHORIZATION_DRIFT: "The authorization decision changed relative to the recorded baseline.",
    VulnClass.UNEXPECTED_DENY: "A subject was denied access the matrix says should be allowed.",
}


def _rules() -> List[dict]:
    rules = []
    for vc, help_text in _RULE_HELP.items():
        tax = TAXONOMY[vc]
        rules.append(
            {
                "id": vc.value,
                "name": vc.name,
                "shortDescription": {"text": vc.value},
                "fullDescription": {"text": help_text},
                "helpUri": tax.help_uri,
                "help": {"text": f"{help_text}\n\n{tax.cwe} ({tax.cwe_name}) · {tax.owasp_api}"},
                "defaultConfiguration": {
                    "level": "error" if vc != VulnClass.UNEXPECTED_DENY else "note"
                },
                "properties": {
                    "cwe": tax.cwe,
                    "owasp-api": tax.owasp_api,
                    "security-severity": tax.security_severity,
                    "tags": sarif_tags(vc),
                },
            }
        )
    return rules


@register("sarif", "overstep.sarif")
def write(result: RunResult, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.vuln_class.value,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f.detail},
                "properties": {
                    "subject": f.subject,
                    "role": f.role,
                    "status": f.status,
                    "expected": f.expected.value,
                    "observed": f.observed.value,
                    "confidence": f.confidence,
                    "cwe": TAXONOMY[f.vuln_class].cwe,
                    "owasp-api": TAXONOMY[f.vuln_class].owasp_api,
                    "security-severity": TAXONOMY[f.vuln_class].security_severity,
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {"name": f"{f.method} {f.path}", "kind": "resource"}
                        ]
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "overstep",
                        "version": __version__,
                        "informationUri": "https://github.com/kabiri-labs/overstep",
                        "rules": _rules(),
                    }
                },
                "results": results,
            }
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
