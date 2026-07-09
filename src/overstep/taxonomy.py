"""Map each finding class to its industry taxonomy (CWE + OWASP API Top 10).

Security dashboards, vulnerability managers and compliance reports key off CWE
identifiers and the OWASP API Security Top 10. Carrying these on every rule and
result makes overstep's output first-class in those systems instead of an opaque
tool-specific label.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from overstep.models import VulnClass


@dataclass(frozen=True)
class Taxon:
    cwe: str                 # e.g. "CWE-639"
    cwe_name: str
    owasp_api: str           # e.g. "API1:2023 Broken Object Level Authorization"
    # GitHub code scanning sorts by this 0.0-10.0 score, not the SARIF level.
    security_severity: str
    help_uri: str


# CWE-639 Authorization Bypass Through User-Controlled Key (BOLA),
# CWE-285 Improper Authorization (BFLA), CWE-213 Exposure of Sensitive
# Information Due to Incompatible Policies (BOPLA), CWE-269 Improper Privilege
# Management (privilege escalation).
TAXONOMY: Dict[VulnClass, Taxon] = {
    VulnClass.BOLA: Taxon(
        cwe="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp_api="API1:2023 Broken Object Level Authorization",
        security_severity="8.1",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ),
    VulnClass.BFLA: Taxon(
        cwe="CWE-285",
        cwe_name="Improper Authorization",
        owasp_api="API5:2023 Broken Function Level Authorization",
        security_severity="8.1",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    VulnClass.BOPLA: Taxon(
        cwe="CWE-213",
        cwe_name="Exposure of Sensitive Information Due to Incompatible Policies",
        owasp_api="API3:2023 Broken Object Property Level Authorization",
        security_severity="7.5",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    ),
    VulnClass.PRIVILEGE_ESCALATION: Taxon(
        cwe="CWE-269",
        cwe_name="Improper Privilege Management",
        owasp_api="API5:2023 Broken Function Level Authorization",
        security_severity="8.8",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    VulnClass.AUTHORIZATION_DRIFT: Taxon(
        cwe="CWE-285",
        cwe_name="Improper Authorization",
        owasp_api="API1:2023 Broken Object Level Authorization",
        security_severity="5.0",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ),
    VulnClass.UNEXPECTED_DENY: Taxon(
        cwe="CWE-285",
        cwe_name="Improper Authorization",
        owasp_api="API5:2023 Broken Function Level Authorization",
        security_severity="0.0",
        help_uri="https://owasp.org/API-Security/editions/2023/en/",
    ),
}


def taxon(vuln: VulnClass) -> Taxon:
    return TAXONOMY[vuln]


def cwe_id(vuln: VulnClass) -> str:
    return TAXONOMY[vuln].cwe


def owasp_api(vuln: VulnClass) -> str:
    return TAXONOMY[vuln].owasp_api


def sarif_tags(vuln: VulnClass) -> List[str]:
    """SARIF rule tags GitHub understands: a security tag, the CWE and the OWASP id."""
    t = TAXONOMY[vuln]
    cwe_num = t.cwe.lower().replace("cwe-", "cwe/cwe-")
    return ["security", f"external/{cwe_num}", t.owasp_api.split(" ", 1)[0]]
