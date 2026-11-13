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
    # A document naming an identifier that is not the server's own is an origin
    # validation failure — CWE-346 — and OWASP files it under API2:2023 for the
    # same reason the audience class sits there: the value decides where a
    # credential goes next. Scored just below TOKEN_AUDIENCE at 8.6 rather than
    # level with it, because this one is caught: the run refuses the document
    # and stops before any credential is minted, so the finding records an
    # attempt that failed rather than a credential already loose. What keeps it
    # high all the same is that the attempt is unauthenticated and costs the
    # target nothing to retry against a client that does not check.
    VulnClass.METADATA_SPOOF: Taxon(
        cwe="CWE-346",
        cwe_name="Origin Validation Error",
        owasp_api="API2:2023 Broken Authentication",
        security_severity="7.5",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    # A delegated credential that reached further than the delegation declared.
    # CWE-269 because the defect is a privilege that was supposed to shrink and
    # did not. Scored level with BOLA's band rather than above it: what was
    # reached is one resource, and the reach is bounded by whatever the
    # delegator could do in the first place — unlike a leaked credential, this
    # one buys no new issuer-wide replay. The authority for the finding is the
    # operator's declaration and the comment says so twice on purpose: RFC 8693
    # places no attenuation requirement on a token exchange, the word does not
    # appear in it, and its `scope` parameter is a "suggested" mitigation in the
    # security considerations. That makes this a policy-conformance class, like
    # BOLA, and it gates for the same reason BOLA does.
    VulnClass.SCOPE_ESCALATION: Taxon(
        cwe="CWE-269",
        cwe_name="Improper Privilege Management",
        owasp_api="API5:2023 Broken Function Level Authorization",
        security_severity="8.4",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    # Nobody can say which agent acted. CWE-778 rather than an access CWE
    # because nothing was reached: this is the record, not the door. The lowest
    # score here alongside the open registry, and it never gates — RFC 8693
    # defines the `act` claim and leaves issuing it to the authorization
    # server's discretion, so its absence breaks no rule. It is reported only
    # when the matrix asks for it, and the help text says plainly that it is an
    # attribution defect rather than an exploit, because a reader who meets it
    # in a report deserves to know which of the two they are looking at.
    VulnClass.DELEGATION_OPACITY: Taxon(
        cwe="CWE-778",
        cwe_name="Insufficient Logging",
        owasp_api="API8:2023 Security Misconfiguration",
        security_severity="3.1",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    ),
    # The highest score in this table, and the only one above TOKEN_AUDIENCE at
    # 8.6. The two are close relatives and the comparison is the whole argument:
    # an audience failure means the server accepted a credential it should have
    # refused, and the credential was already in the hands of whoever replayed
    # it. Passthrough *creates* that position — the caller's credential is
    # delivered to a third party the caller never authorized, from where it is
    # replayable at every service trusting the same issuer, and the caller has
    # no way to know it happened. CWE-522 rather than CWE-863 for that reason:
    # the defect is the credential's exposure, not the decision about it.
    VulnClass.TOKEN_PASSTHROUGH: Taxon(
        cwe="CWE-522",
        cwe_name="Insufficiently Protected Credentials",
        owasp_api="API2:2023 Broken Authentication",
        security_severity="8.7",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    # The lowest score in this table, and the only class here that is not a
    # rule anybody broke. RFC 7591 section 3 says the registration endpoint
    # SHOULD allow requests with no authorization, and no MCP revision asks for
    # a credential on it — 2026-07-28 deprecates the mechanism without ever
    # requiring one. So the finding is not "this server is wrong", it is "anyone
    # can obtain a client id here", which changes what a client id is worth as
    # evidence of anything and is why it is reported at all. CWE-1188 rather
    # than a missing-authorization CWE for the same reason: the default is
    # permissive by design, and whether that suits the deployment is the
    # operator's call. Scored beneath TOOL_ENUMERATION at 5.3, which at least
    # discloses something the policy said to withhold.
    VulnClass.OPEN_REGISTRATION: Taxon(
        cwe="CWE-1188",
        cwe_name="Insecure Default Initialization of Resource",
        owasp_api="API8:2023 Security Misconfiguration",
        security_severity="3.1",
        help_uri="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    ),
}


HELP = {
    VulnClass.TOKEN_AUDIENCE:
        "An MCP server accepted a token that was issued for a different audience.",
    VulnClass.SESSION_HIJACK:
        "An MCP server let a session id stand in for a credential.",
    VulnClass.TOOL_ENUMERATION:
        "An MCP server advertised tools to a subject that may not invoke them.",
    VulnClass.METADATA_SPOOF:
        "An MCP server served OAuth metadata naming an identifier that was not "
        "its own, so the discovery chain was refused before any credential was "
        "requested.",
    VulnClass.SCOPE_ESCALATION:
        "A credential obtained by delegation reached something the delegation "
        "declared it must not. RFC 8693 requires no attenuation of an exchanged "
        "token, so the boundary is the one the matrix drew.",
    VulnClass.DELEGATION_OPACITY:
        "A delegated credential carries no actor claim, so a record of the call "
        "cannot say which agent made it. An attribution defect, not an exploit; "
        "it does not fail a default gate.",
    VulnClass.TOKEN_PASSTHROUGH:
        "An MCP server forwarded the caller's own credential to an upstream API. "
        "The authorization specification requires it to use a separate token of "
        "its own instead.",
    VulnClass.OPEN_REGISTRATION:
        "An MCP server's authorization server registered a client for a caller "
        "that presented no credential. RFC 7591 permits this; it is reported as "
        "a property of the deployment, not as a violation, and does not fail a "
        "default gate.",
}


def register_all() -> None:
    """Contribute this surface's classes to the shared taxonomy and SARIF help."""
    from overstep.report.sarif import register_help

    for vuln, taxon in TAXONOMY.items():
        register(vuln, taxon)
    for vuln, text in HELP.items():
        register_help(vuln, text)
