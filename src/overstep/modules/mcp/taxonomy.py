"""The finding classes only an MCP server can produce.

Credential audience and session binding are requirements the MCP authorization
specification places on the server itself, and tool enumeration is a question
about a catalogue nothing else has. They are not variations on a shared class —
they exist because this surface has a protocol with rules of its own.

They sat in `overstep.taxonomy` beside BOLA and BFLA, which meant the table
every surface reads through described one surface's protocol, down to SARIF help
text beginning "An MCP server...". The core keeps the classes both surfaces
report; these register themselves.
"""
from __future__ import annotations

from overstep.models import VulnClass
from overstep.taxonomy import Taxon, register

TAXONOMY = {
    # A resource server that does not check who its token was issued for is the
    # confused deputy of CWE-863; OWASP files audience validation under
    # API2:2023, which calls out exactly this ("does not validate the JWT
    # audience"). Scored above BOLA because the credential is replayable at every
    # service trusting the same issuer, so the blast radius is not one object.
    VulnClass.TOKEN_AUDIENCE: Taxon(
        cwe="CWE-863",
        cwe_name="Incorrect Authorization",
        owasp_api="API2:2023 Broken Authentication",
        security_severity="8.6",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    # A session identifier accepted as proof of identity is an authentication
    # decision made on something that was never a credential — CWE-287, and the
    # session half of OWASP's API2:2023.
    VulnClass.SESSION_HIJACK: Taxon(
        cwe="CWE-287",
        cwe_name="Improper Authentication",
        owasp_api="API2:2023 Broken Authentication",
        security_severity="8.1",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    # Advertising the privileged half of the surface is disclosure, not access:
    # CWE-200, scored well below the classes that let somebody actually reach it.
    VulnClass.TOOL_ENUMERATION: Taxon(
        cwe="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        owasp_api="API5:2023 Broken Function Level Authorization",
        security_severity="5.3",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
}


HELP = {
    VulnClass.TOKEN_AUDIENCE:
        "An MCP server accepted a token that was issued for a different audience.",
    VulnClass.SESSION_HIJACK:
        "An MCP server let a session id stand in for a credential.",
    VulnClass.TOOL_ENUMERATION:
        "An MCP server advertised tools to a subject that may not invoke them.",
}


def register_all() -> None:
    """Contribute this surface's classes to the shared taxonomy and SARIF help."""
    from overstep.report.sarif import register_help

    for vuln, taxon in TAXONOMY.items():
        register(vuln, taxon)
    for vuln, text in HELP.items():
        register_help(vuln, text)
