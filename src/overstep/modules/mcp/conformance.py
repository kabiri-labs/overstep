"""Requirements the MCP specification places on the server itself.

Two probes live here, and they have almost nothing in common except where they
are declared.

``metadata_identity`` costs nothing and sends nothing. Discovery already
validates, for its own safety, that the documents a target serves actually name
that target: the ``resource`` in its Protected Resource Metadata (RFC 9728
section 3.3), the ``issuer`` in its Authorization Server Metadata (RFC 8414
section 3.3), no redirect carrying a metadata fetch across an origin boundary,
and TLS on both hops. Each of those refusals is also a statement about the
server, and it used to die with the exception that stopped the run — a console
line, no documents, nothing to triage. :mod:`overstep.modules.mcp.auth` now
attaches the evidence to the refusal and :mod:`overstep.pipeline` turns it into
the one case such a run did perform. The abort is unchanged: a host that failed
an identity check is still never handed a credential.

``open_registration`` is the opposite in every respect. It POSTs an RFC 7591
client registration, carrying no credential at all, to the authorization server
the target named, and reports one that mints a client for an anonymous caller —
a client id bound to a redirect URI the caller chose, which is the starting
position for authorization-code interception. It writes to somebody else's
system, so it is off by default, it refuses to run without a redirect URI the
operator owns, ``--read-only`` skips it, and the phased dispatcher puts it last
with the other mutating cases.

The two share a transport because neither is JSON-RPC: both speak plain HTTP to
the OAuth endpoints *around* an MCP server rather than to the server itself.
Giving them their own keeps that HTTP inside this module instead of asking the
REST executor to send it — every request that executor builds carries the
subject's credential, and the whole point of this probe is that it carries none.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional

import httpx

from overstep import netopts
from overstep.models import (
    Effect,
    Observation,
    ResourceType,
    Subject,
    TestCase,
    Variant,
)

TRANSPORT = "mcp-oauth"

# What the probe calls itself when it registers. Somebody reading their
# authorization server's client list afterwards should be able to tell what
# created the entry, and go and delete it.
CLIENT_NAME = "overstep-conformance-probe"

# The registration probe presents no credential, so it is made by nobody in
# particular. Naming the caller rather than borrowing a declared subject keeps
# the finding honest: a report saying alice was allowed to register a client
# would describe a request alice never made, and would imply her credential had
# something to do with the answer.
ANONYMOUS_SUBJECT = "(unauthenticated)"
ANONYMOUS_ROLE = "(none)"

# Fields a registration response carries that are credentials in their own
# right. RFC 7591 section 3.2.1 names the first; the second is what lets its
# holder read, edit or delete the registration afterwards.
SECRET_REGISTRATION_FIELDS = frozenset({
    "client_secret",
    "registration_access_token",
})

REDACTED = "<redacted by overstep>"


def plan_cases(matrix: Any, context: Dict[str, str]) -> List[TestCase]:
    """One unauthenticated client registration per Streamable HTTP server.

    Contributed through the transport registry rather than written in the
    planner, because the request is spelled in an OAuth specification this
    module owns and the core has no business knowing it.

    ``path`` starts as the server's own URL and is replaced, at execution time,
    by the registration endpoint discovery finds behind it. Where that endpoint
    lives is the authorization server's answer, not something the matrix states,
    so it cannot be known while planning — and recording the resolved address on
    the case is what lets the finding's reproduction name it.
    """
    from overstep.planner import make_test_id

    conformance = matrix.modules.mcp.probes.conformance
    redirect_uri = matrix.modules.mcp.canary.redirect_uri
    # The matrix model refuses this combination, so reaching here means a caller
    # built the model by hand. Generating nothing is still the right answer: a
    # probe with no address it can recognise its own client at cannot decide.
    if not conformance.open_registration or not redirect_uri:
        return []

    cases: List[TestCase] = []
    for server in matrix.servers:
        if server.kind != "http" or not server.url:
            # stdio has no OAuth metadata and nothing to register against.
            continue
        resource = f"mcp:{server.name}"
        pins = _declared_pins(matrix, server)
        cases.append(
            TestCase(
                id=make_test_id(resource, ANONYMOUS_SUBJECT, Variant.REGISTER),
                resource=resource,
                subject=ANONYMOUS_SUBJECT,
                role=ANONYMOUS_ROLE,
                transport=TRANSPORT,
                method="POST",
                path_template=server.url,
                path=server.url,
                variant=Variant.REGISTER,
                expected=Effect.DENY,
                resource_type=ResourceType.FUNCTION,
                body=registration_body(redirect_uri),
                discovery_pins=pins,
            )
        )
    return cases


def _declared_pins(matrix: Any, server: Any) -> Optional[Dict[str, str]]:
    """What the matrix already said about this server's authorization server.

    An operator whose server is legitimately known by another identifier says so
    once, with `resource:` on the auth provider, and authentication honours it.
    A probe resolving the same metadata by stricter rules would refuse what the
    run has already accepted and report the endpoint as unprobeable — a
    supported deployment that can never be tested, and a skip message blaming
    the target for something the matrix had answered.
    """
    for provider in matrix.auth.providers:
        if provider.discover_from not in (server.name, server.url):
            continue
        pins = {}
        if provider.issuer:
            pins["issuer"] = provider.issuer
        if provider.resource:
            pins["resource"] = provider.resource
        return pins or None
    return None


def _registration_endpoint(case: TestCase, *, verify_tls: bool) -> tuple:
    """Where this server's authorization server accepts registrations.

    Re-runs discovery rather than reading what authentication already resolved.
    The cost is two metadata fetches per server on an opt-in probe, and the
    alternative is carrying discovery state from the auth stage through the
    planner into a transport — which would couple three stages together to save
    two requests the target serves from a well-known URL anyway.

    It is run under the same terms authentication ran under: the pins the matrix
    declared, and the plaintext allowance a `--insecure` run already chose. The
    identity checks still apply, so a server that names somebody else's issuer
    is refused here exactly as it is there — this is not a relaxation, it is the
    same rules reading the same configuration.
    """
    from overstep.modules.mcp.auth import DiscoveryError, discover_token_endpoint

    pins = case.discovery_pins or {}
    try:
        found = discover_token_endpoint(
            case.path_template,
            verify=verify_tls,
            expected_issuer=pins.get("issuer"),
            expected_resource=pins.get("resource"),
            allow_plaintext=not verify_tls,
        )
    except DiscoveryError as exc:
        return None, f"discovery failed: {exc}"
    if not found.registration_endpoint:
        return None, (
            "the authorization server advertises no registration_endpoint, so "
            "there is nothing to register against"
        )
    return found.registration_endpoint, ""


def registration_body(redirect_uri: str) -> Dict[str, Any]:
    """The RFC 7591 request the probe sends.

    Deliberately minimal. Every field is one the specification requires or the
    operator supplied, and nothing is added to coax a server into accepting a
    registration it would otherwise refuse: a finding obtained that way would
    describe overstep's persistence rather than the server's policy.
    """
    return {
        "client_name": CLIENT_NAME,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def redact(value: Any) -> Any:
    """A registration response with the credentials it just minted taken out.

    This probe is the one place overstep handles a credential that did not exist
    when the run started, which is exactly the one `overstep.repro` cannot mask:
    that machinery is given the values the matrix declared, and a secret the
    authorization server issued thirty milliseconds ago is not among them. So
    the response is never stored as it arrived. A client id is an identifier,
    and it is the proof, so it stays; a client secret, and the token that would
    let its holder edit the registration, do not. Applied by key at every depth,
    because a server is free to nest its answer and a report is not the place to
    find out that one did.
    """
    if isinstance(value, dict):
        return {
            key: REDACTED if key in SECRET_REGISTRATION_FIELDS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def minted_client_id(payload: Any) -> Optional[str]:
    """The ``client_id`` an accepted registration returns, if there is one.

    RFC 7591 section 3.2.1 makes ``client_id`` the one field a successful
    response must carry, which is why it rather than the status code decides the
    verdict. A 2xx without it is not a registration — some gateways answer
    anything with 200 — and reporting one as an open endpoint would be exactly
    the guess-from-status this tool refuses to make elsewhere.
    """
    if not isinstance(payload, dict):
        return None
    value = payload.get("client_id")
    return value if isinstance(value, str) and value else None


def _probe(case: TestCase, *, verify_tls: bool) -> Observation:
    """Send one unauthenticated registration and judge what came back."""
    body = case.body if isinstance(case.body, dict) else {}
    try:
        with httpx.Client(
            verify=verify_tls, follow_redirects=True, **netopts.client_kwargs()
        ) as client:
            # No Authorization header, by construction: the question is what an
            # anonymous caller gets, so there is nothing here to mask later.
            resp = client.post(
                case.path, json=body, headers={"Accept": "application/json"}
            )
    except httpx.HTTPError as exc:
        return Observation(
            test_id=case.id,
            status=0,
            effect=Effect.DENY,
            error=f"{type(exc).__name__}: {exc}",
        )

    try:
        payload = resp.json()
    except ValueError:
        payload = None

    client_id = minted_client_id(payload) if resp.status_code < 400 else None
    # Never `resp.text`. A body that did not parse as JSON cannot be shown to
    # carry no secret, so nothing of it is kept beyond its length — a truncated
    # unknown is still an unknown, and this response is the one most likely to
    # hold a credential overstep itself caused to exist.
    if isinstance(payload, (dict, list)):
        snippet = json.dumps(redact(payload), separators=(",", ":"))[:512]
    else:
        snippet = f"<non-JSON registration response, {len(resp.content)} bytes>"
    if client_id is None:
        return Observation(
            test_id=case.id,
            status=resp.status_code,
            effect=Effect.DENY,
            headers=dict(resp.headers),
            body_snippet=snippet,
        )

    # The id is a credential the probe has just caused to exist, and it is also
    # the proof, so it is recorded as the marker that confirmed the finding
    # rather than left to be read back out of a truncated body.
    return Observation(
        test_id=case.id,
        status=resp.status_code,
        effect=Effect.ALLOW,
        headers=dict(resp.headers),
        body_snippet=snippet,
        matched_markers=[client_id],
    )


def execute(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    *,
    verify_tls: bool = True,
    read_only: bool = False,
    **kwargs: Any,
) -> List[Observation]:
    """Deliver the conformance cases that are actually sent.

    Only the registration probe is. A ``METADATA`` case describes a fetch the
    run already made, and refused, on its way to authenticating, so it never
    reaches a dispatcher. If one somehow does it is recorded as undelivered
    rather than quietly passed: an observation claiming a request happened when
    none did is the fail-open this tool exists to remove.
    """
    observations: List[Observation] = []
    for case in cases:
        if case.variant != Variant.REGISTER:
            observations.append(
                Observation(
                    test_id=case.id,
                    status=0,
                    effect=Effect.DENY,
                    error=f"'{case.variant.value}' is not a case this transport sends",
                )
            )
            continue
        if read_only:
            # `is_mutating` is already true here (the case is a POST), so this is
            # the same decision the other two transports make. It is spelled out
            # because a client registration is the one write overstep aims at a
            # third party, and a reader of this file should not have to derive
            # that it is covered.
            observations.append(
                Observation(
                    test_id=case.id,
                    status=0,
                    effect=Effect.DENY,
                    skipped=True,
                    error="skipped client registration under --read-only",
                )
            )
            continue

        endpoint, problem = _registration_endpoint(case, verify_tls=verify_tls)
        if endpoint is None:
            # Not a finding and not a failure: there was no endpoint to ask. It
            # is recorded as skipped so the run counts it among what it did not
            # test, because "no finding" and "never asked" must not read alike.
            observations.append(
                Observation(
                    test_id=case.id,
                    status=0,
                    effect=Effect.DENY,
                    skipped=True,
                    error=f"client registration not probed — {problem}",
                )
            )
            continue

        case.path = endpoint
        observations.append(_probe(case, verify_tls=verify_tls))
    return observations


def build_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """The structured request record. Neither probe carries a credential."""
    if case.variant == Variant.METADATA:
        return {"method": "GET", "url": case.path, "headers": {}, "body": None}
    return {
        "method": "POST",
        "url": case.path,
        "headers": {"Content-Type": "application/json"},
        "body": case.body,
    }


def build_repro(base_url: str, subject: Subject, case: TestCase) -> str:
    """A command that re-runs the probe, with nothing in it to redact.

    Both probes are unauthenticated by construction, so unlike every other repro
    overstep writes, this one has no credential to leave as a shell variable —
    which also makes it the one an operator can forward to the server's owner
    exactly as the report prints it.
    """
    if case.variant == Variant.METADATA:
        return f"curl -sS {shlex.quote(case.path)}"
    payload = json.dumps(case.body or {}, separators=(",", ":"))
    return (
        "curl -sS -X POST "
        f"-H {shlex.quote('Content-Type: application/json')} "
        f"--data {shlex.quote(payload)} {shlex.quote(case.path)}"
    )
