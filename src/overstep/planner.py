"""Turn an authorization matrix into concrete test cases.

For every (resource, subject) pair we work out what the matrix *expects* to
happen and emit a fully-rendered request for it:

* Object resources are expanded into a SELF variant (the subject reaching for its
  own object) and an OTHER variant (reaching for someone else's). SELF is the
  positive test; OTHER is usually the negative one that catches BOLA.
* Function resources produce a single request per subject; roles without an allow
  rule become negative tests that catch BFLA / privilege escalation.

The expected decision is computed statically from the policy: we know every
subject's attributes up front, so even custom ``condition`` expressions can be
evaluated at plan time.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from overstep.expressions import safe_eval
from overstep.jsonpath import set_at
from overstep.matrix import Matrix
from overstep.models import (
    Effect,
    OwnershipInjection,
    OwnershipLocation,
    Resource,
    ResourceType,
    Subject,
    TestCase,
    Variant,
)
from overstep.templating import render

_PARAM_RE = re.compile(r"{([^}]+)}")


def _path_params(path: str) -> List[str]:
    return _PARAM_RE.findall(path)


def make_test_id(
    resource: str, subject: str, variant: Variant, victim: Optional[str] = None
) -> str:
    """A stable identifier used for reporting and drift snapshots.

    ``victim`` is appended only when one subject probes more than one object, so
    every id a matrix produced before ``probe_victims: all`` keeps its exact
    spelling and existing drift baselines stay comparable.
    """
    base = f"{resource}::{subject}::{variant.value}"
    return f"{base}@{victim}" if victim else base


def _object_id(resource: Resource, subject: Subject, context: Dict[str, str]) -> Optional[str]:
    """The id of the object this subject owns for this resource.

    An explicit ``objects`` entry (with ``{{captures}}`` resolved) wins; otherwise
    fall back to the subject attribute named by ``owner_attr``.
    """
    if subject.name in resource.objects:
        return render(resource.objects[subject.name], context)
    value = subject.attributes.get(resource.owner_attr)
    return None if value is None else str(value)


def _injection_value(
    resource: Resource,
    subject: Subject,
    injection: OwnershipInjection,
    context: Dict[str, str],
) -> Optional[str]:
    """The value to write for one injection, for a given subject.

    An injection may override which attribute identifies the object (e.g. a tenant
    header); otherwise it uses the resource's default object id (``objects`` map or
    ``owner_attr``). Returns ``None`` when the subject has no such value — the
    caller skips the injection rather than inventing a placeholder.
    """
    if injection.owner_attr:
        value = subject.attributes.get(injection.owner_attr)
        return None if value is None else str(value)
    return _object_id(resource, subject, context)


def _injections_by_location(
    resource: Resource, src: Optional[Subject], context: Dict[str, str]
) -> Dict[OwnershipLocation, List[Tuple[str, str]]]:
    """Group this resource's injections by location for the source subject.

    ``src`` is the subject whose object is being reached (the caller for SELF, the
    victim for OTHER). Injections whose value can't be resolved are dropped, so a
    placeholder is never written for ownership.
    """
    out: Dict[OwnershipLocation, List[Tuple[str, str]]] = {}
    if src is None:
        return out
    for inj in resource.effective_injections():
        value = _injection_value(resource, src, inj, context)
        if value is None:
            continue
        out.setdefault(inj.location, []).append((inj.selector, value))
    return out


def _ownership_values(
    resource: Resource, subject: Subject, context: Dict[str, str]
) -> Optional[Tuple[str, ...]]:
    """Everything this subject writes into the request to identify its object.

    ``None`` when the subject cannot supply one of the values — ownership is
    never half-populated. Two subjects with equal tuples address the *same*
    object, so a probe from one at the other's object is not a cross-owner probe
    at all.
    """
    injections = resource.effective_injections()
    if not injections:
        return None
    values = []
    for inj in injections:
        value = _injection_value(resource, subject, inj, context)
        if value is None:
            return None
        values.append(value)
    return tuple(values)


def _locates_object(resource: Resource, subject: Subject, context: Dict[str, str]) -> bool:
    """Whether this subject can supply a value for every ownership injection.

    Basing this on the actual injections (not just ``objects`` / the default
    ``owner_attr``) means an owner_attr-only injection — e.g. a tenant carried in
    a header — still drives SELF/OTHER generation for subjects that have that
    attribute.
    """
    return _ownership_values(resource, subject, context) is not None


def _victims(
    resource: Resource, subject: Subject, subjects: List[Subject], context: Dict[str, str]
) -> List[Subject]:
    """Every subject this one could cross-owner probe, in declaration order.

    Two exclusions, both to avoid generating a request that proves nothing.
    Subjects can legitimately share an object — two members of one tenant, a
    service account and the user it acts for — so a peer holding the *same*
    object would produce a probe byte-identical to the subject's own SELF
    request. And two victims sharing one object are one probe, not two, so only
    the first of them is kept.
    """
    mine = _ownership_values(resource, subject, context)
    out: List[Subject] = []
    seen = set()
    for other in subjects:
        if other.name == subject.name:
            continue
        theirs = _ownership_values(resource, other, context)
        if theirs is None or theirs == mine or theirs in seen:
            continue
        seen.add(theirs)
        out.append(other)
    return out


def _merge_cookies(existing: str, pairs: List[Tuple[str, str]]) -> str:
    """Merge cookie name=value pairs into an existing Cookie header value."""
    jar: Dict[str, str] = {}
    for part in existing.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        jar[key.strip()] = value.strip()
    for key, value in pairs:
        jar[key] = value
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def _set_graphql_var(body, selector: str, value: str):
    """Write a GraphQL variable, creating the ``variables`` object if needed."""
    if not isinstance(body, dict):
        if body is not None:
            return body  # a non-object GraphQL body is left untouched
        body = {}
    variables = body.get("variables")
    if not isinstance(variables, dict):
        variables = {}
        body["variables"] = variables
    if selector.startswith("$"):
        set_at(variables, selector, value)
    else:
        variables[selector] = value
    return body


def _render_path(
    resource: Resource,
    subject: Subject,
    path_injections: List[Tuple[str, str]],
    context: Dict[str, str],
) -> str:
    """Fill in every {param} in the resource path.

    A path-location ownership injection drives its parameter; any other params
    fall back to the subject's own attributes, then to "1". Ownership params are
    never "1" — an unresolved injection is dropped upstream, and the SELF/OTHER
    generation already gates on the subject actually owning an object.
    """
    injected = dict(path_injections)
    path = resource.request.path
    for param in _path_params(path):
        if param in injected:
            value = injected[param]
        else:
            value = subject.attributes.get(param)
            if value is None:
                value = "1"
        path = path.replace("{%s}" % param, str(value))
    return path


def _build_http_request(
    resource: Resource,
    subject: Subject,
    variant: Variant,
    target: Optional[Subject],
    context: Dict[str, str],
) -> Dict:
    """Render an HTTP request and write every object-identifier injection into it.

    Returns a dict of the resolved path/query/body/form/headers, so both the main
    case and any cross-method probes share exactly the same injected request.
    """
    src = None if variant == Variant.NA else (subject if variant == Variant.SELF else target)
    injections = _injections_by_location(resource, src, context)

    path = _render_path(resource, subject, injections.get(OwnershipLocation.PATH, []), context)
    query = render(dict(resource.request.query), context)
    form = render(dict(resource.request.form), context)
    headers = render(dict(resource.request.headers), context)
    body = render(resource.request.body, context)

    for selector, value in injections.get(OwnershipLocation.QUERY, []):
        query[selector] = value
    for selector, value in injections.get(OwnershipLocation.HEADER, []):
        headers[selector] = value
    for selector, value in injections.get(OwnershipLocation.FORM, []):
        form[selector] = value
    cookies = injections.get(OwnershipLocation.COOKIE, [])
    if cookies:
        headers["Cookie"] = _merge_cookies(headers.get("Cookie", ""), cookies)
    for selector, value in injections.get(OwnershipLocation.JSON, []):
        body = set_at({} if body is None else body, selector, value)
    for selector, value in injections.get(OwnershipLocation.GRAPHQL_VARIABLES, []):
        body = _set_graphql_var(body, selector, value)

    return {"path": path, "query": query, "form": form, "headers": headers, "body": body}


def _expected_effect(
    matrix: Matrix,
    resource: Resource,
    subject: Subject,
    variant: Variant,
    target: Optional[Subject],
) -> Effect:
    """Resolve the matrix policy for one subject/variant into allow or deny."""
    policy = matrix.policy.get(resource.name)
    if not policy or not policy.allow:
        return Effect.DENY

    for rule in policy.allow:
        if rule.role != subject.role:
            continue
        # Ownership scope only constrains object resources.
        if (
            resource.type == ResourceType.OBJECT
            and rule.scope == "own"
            and variant == Variant.OTHER
        ):
            continue
        if rule.condition:
            target_attrs = (target.attributes if target else subject.attributes)
            context = {"subject": subject.attributes, "target": target_attrs}
            try:
                if not safe_eval(rule.condition, context):
                    continue
            except Exception:
                # A condition we can't evaluate is treated as not granting access.
                continue
        return Effect.ALLOW
    return Effect.DENY


def _variants(
    resource: Resource,
    subject: Subject,
    subjects: List[Subject],
    context: Dict[str, str],
    probe_victims: str = "one",
) -> List[Tuple[Variant, Optional[Subject]]]:
    """Which (variant, target) pairs to generate for this subject/resource."""
    if resource.type != ResourceType.OBJECT or not resource.is_object_locatable:
        return [(Variant.NA, None)]

    out: List[Tuple[Variant, Optional[Subject]]] = []
    if _locates_object(resource, subject, context):
        out.append((Variant.SELF, subject))
    victims = _victims(resource, subject, subjects, context)
    if probe_victims != "all":
        victims = victims[:1]
    out.extend((Variant.OTHER, victim) for victim in victims)
    return out or [(Variant.OTHER, None)]


def _build_mcp_invocation(matrix, resource, subject, variant, target, context):
    """Resolve a fully-rendered MCP tool-call for one subject/variant.

    The server is resolved to its URL/headers and embedded on the case so the
    executor stays self-contained. For object resources the ``owner_arg`` argument
    is filled with the caller's (SELF) or victim's (OTHER) object id — the BOLA
    surface — and the matcher is the resource override or the matrix default.
    """
    from overstep.models import McpInvocation

    call = resource.call
    server = matrix.server_map().get(call.server)
    arguments = render(dict(call.arguments), context)
    src = None if variant == Variant.NA else (subject if variant == Variant.SELF else target)
    for selector, value in _injections_by_location(resource, src, context).get(
        OwnershipLocation.MCP_ARGUMENT, []
    ):
        if selector.startswith("$"):
            set_at(arguments, selector, value)
        else:
            arguments[selector] = value
    matcher = resource.mcp_access or matrix.mcp_access

    kind = server.kind if server else "http"
    fields = dict(
        kind=kind,
        protocol_version=server.protocol_version if server else "2025-06-18",
        tool=call.tool,
        arguments=arguments,
        matcher=matcher,
        mutating=call.mutating,
    )
    if kind == "stdio":
        # Identity for stdio is injected into the child's environment: the static
        # server env plus this subject's token under token_env.
        env = render(dict(server.env), context)
        if server.token_env and subject.token is not None:
            env[server.token_env] = subject.token
        fields.update(command=list(server.command or []), env=env)
    else:
        fields.update(
            url=server.url if server else "",
            headers=render(dict(server.headers), context) if server else {},
        )
    return McpInvocation(**fields)


def _same_audience(server, audience: str) -> bool:
    """Whether ``audience`` identifies this MCP server.

    Both spellings a matrix can use are accepted — the server's name under
    ``servers:``, and its URL — because the audience may equally have been
    written by hand or discovered from the server's own Protected Resource
    Metadata, which reports a URI. The prefix comparison covers the common
    mismatch between a resource identifier written as an origin
    (``https://host``) and the JSON-RPC endpoint under it (``https://host/mcp``);
    reading those as different audiences would manufacture a finding against a
    server the token is genuinely valid for, which is the one error this probe
    cannot afford.
    """
    if audience == server.name:
        return True
    if not server.url:
        return False
    a, u = audience.rstrip("/"), server.url.rstrip("/")
    return a == u or u.startswith(a + "/") or a.startswith(u + "/")


def _declared_audience(matrix: Matrix, subject: Subject) -> Optional[str]:
    """The audience a subject's token was issued for, or None if unknown.

    An explicit ``token_audience`` wins. Otherwise it is inferred from the
    subject's auth provider: a provider that discovers its token endpoint from an
    MCP server obtains a token bound to that server (it sends the RFC 8707
    resource indicator), so the server it discovered from *is* the audience. No
    provider, or one with a hardcoded token URL, says nothing about audience —
    and a guess here would invent probes, so None means no probe.
    """
    if subject.token_audience:
        return subject.token_audience
    if subject.auth:
        for provider in matrix.auth.providers:
            if provider.name == subject.auth.provider:
                return provider.resource or provider.discover_from
    return None


def _audience_cases(matrix: Matrix, context: Dict[str, str]) -> List[TestCase]:
    """Replay each subject's credential at every MCP server it was not issued for.

    The MCP authorization spec is unambiguous here: a server must not accept a
    token that was not issued for it. One that does is a confused deputy — the
    credential a user handed to server A works at server B, and every service
    trusting that issuer is reachable with it. Unlike BOLA or BFLA this is not a
    question about the policy, so the matrix's allow rules are deliberately not
    consulted: an admin's token bound to A must still be refused by B.

    The probe is ``tools/list``, not a tool-call. It requires authorization,
    takes no arguments and changes nothing, so it isolates the one question being
    asked — was this credential accepted at all — without invoking anybody's
    tool, and it needs no object to be resolvable. One probe per (subject,
    server): audience validation is a property of the server, not of each tool.

    Restricted to Streamable HTTP servers. On stdio the token is placed in the
    child process's environment under a variable that server chose, so there is
    no audience to violate and nothing to replay.
    """
    if not matrix.probe_token_audience:
        return []

    cases: List[TestCase] = []
    for subject in matrix.subjects:
        if not subject.token:
            continue  # nothing to replay
        audience = _declared_audience(matrix, subject)
        if not audience:
            continue
        for server in (s for s in matrix.servers if s.kind == "http"):
            if _same_audience(server, audience):
                continue
            inv = _tools_list_invocation(matrix, server, context)
            cases.append(
                _protocol_case(
                    server, subject, Variant.AUDIENCE, inv,
                    expected=Effect.DENY, audience=audience,
                )
            )
    return cases


def _protocol_case(server, subject: Subject, variant: Variant, inv, **fields) -> TestCase:
    """One MCP protocol probe, addressed at a server rather than a resource.

    These ask about the credential or the connection, not about a declared
    operation, so they have no resource of their own. ``mcp:<server>`` stands in
    for one: it keeps ids unique and readable, and gives the defect roll-up a key
    that groups by the server the question is about.
    """
    resource = f"mcp:{server.name}"
    return TestCase(
        id=make_test_id(resource, subject.name, variant),
        resource=resource,
        subject=subject.name,
        role=subject.role,
        transport="mcp",
        method=inv.method,
        path_template=server.name,
        path=server.name,
        variant=variant,
        resource_type=ResourceType.FUNCTION,
        mcp=inv,
        **fields,
    )


def _tools_list_invocation(matrix: Matrix, server, context: Dict[str, str], **fields):
    """A ``tools/list`` invocation against one server, for the protocol probes."""
    from overstep.models import McpInvocation

    return McpInvocation(
        kind="http",
        url=server.url or "",
        headers=render(dict(server.headers), context),
        protocol_version=server.protocol_version,
        method="tools/list",
        matcher=matrix.mcp_access,
        **fields,
    )


def _session_cases(matrix: Matrix, context: Dict[str, str]) -> List[TestCase]:
    """Ask each server whether a session id substitutes for a credential.

    MCP's Streamable HTTP transport hands out an ``Mcp-Session-Id`` at
    ``initialize``, and the spec is explicit that it must not be used to
    authenticate: session identifiers travel in headers, and headers end up in
    proxies, logs and referrers, so anyone who obtains one would inherit the
    identity that opened it.

    One probe per (credentialed subject, HTTP server). The verdict is reached
    inside the transport, which sends the anonymous request both with the
    session and without it — the second being the control that separates a
    hijackable session from an endpoint that was open to everyone anyway.
    """
    if not matrix.probe_session_binding:
        return []

    cases: List[TestCase] = []
    for server in (s for s in matrix.servers if s.kind == "http"):
        for subject in matrix.subjects:
            if not subject.token and not subject.headers:
                continue  # no identity to open a session worth stealing
            identity = dict(subject.headers)
            if subject.token and not any(k.lower() == "authorization" for k in identity):
                identity["Authorization"] = f"Bearer {subject.token}"
            inv = _tools_list_invocation(
                matrix, server, context, anonymous=True, handshake_headers=identity,
            )
            cases.append(
                _protocol_case(server, subject, Variant.SESSION, inv, expected=Effect.DENY)
            )
    return cases


def _enumeration_cases(matrix: Matrix, context: Dict[str, str]) -> List[TestCase]:
    """Ask each server what it is willing to *list* to each subject.

    A server that advertises a tool to someone who may not invoke it discloses
    its function surface: the caller learns the shape of the privileged half of
    the API, which is where an attack starts rather than where it ends.

    Opt-in, unlike the other protocol probes, and the asymmetry is deliberate.
    Listing every tool to every caller and enforcing at call time is a common and
    entirely defensible design, so reporting it by default would be an opinion
    dressed as a finding. Session hijacking and a token accepted from the wrong
    audience are never defensible, so those need no opt-in.
    """
    if not matrix.probe_tool_enumeration:
        return []

    cases: List[TestCase] = []
    for server in (s for s in matrix.servers if s.kind == "http"):
        for subject in matrix.subjects:
            inv = _tools_list_invocation(matrix, server, context)
            # The findings come from what the listing *contained*, so the effect
            # carries no expectation to violate: a subject that cannot list at
            # all simply has nothing to check, not an over-restriction to report.
            cases.append(
                _protocol_case(server, subject, Variant.ENUMERATE, inv, expected=Effect.ALLOW)
            )
    return cases


def plan(matrix: Matrix, context: Optional[Dict[str, str]] = None) -> List[TestCase]:
    """Generate the full list of test cases for a matrix.

    ``context`` holds values captured by setup steps; it fills ``{{...}}``
    placeholders in resource object ids and request bodies/queries/headers.
    """
    context = context or {}
    cases: List[TestCase] = []
    subjects = matrix.subjects

    for resource in matrix.resources:
        required = matrix.required_roles(resource.name)
        matcher = resource.access or matrix.access
        for subject in subjects:
            pairs = _variants(
                resource, subject, subjects, context, matrix.victims_for(resource)
            )
            # Only disambiguate when this subject really does probe more than one
            # object; a single probe keeps the id it has always had.
            multi_victim = sum(1 for v, _ in pairs if v == Variant.OTHER) > 1
            for variant, target in pairs:
                expected = _expected_effect(matrix, resource, subject, variant, target)
                # For an OTHER probe, a leak would expose the victim's data, so
                # carry the victim's marker along for the content-aware oracle.
                expect_markers = (
                    [target.marker]
                    if variant == Variant.OTHER and target and target.marker
                    else []
                )
                id_victim = target.name if (multi_victim and target is not None) else None
                # Whose object this probe reaches for. Only an OTHER probe with
                # a real target is a cross-owner probe: when a subject can
                # neither locate its own object nor find a peer holding a
                # different one, _variants still emits an OTHER case so the
                # resource is exercised, but it reaches for a default id that
                # belongs to nobody and proves nothing about ownership.
                victim = target.name if (variant == Variant.OTHER and target) else None
                common = dict(
                    id=make_test_id(resource.name, subject.name, variant, id_victim),
                    victim=victim,
                    resource=resource.name,
                    subject=subject.name,
                    role=subject.role,
                    transport=resource.transport,
                    variant=variant,
                    expected=expected,
                    resource_type=resource.type,
                    required_roles=required,
                    expect_markers=expect_markers,
                )

                if resource.transport == "mcp":
                    inv = _build_mcp_invocation(matrix, resource, subject, variant, target, context)
                    cases.append(
                        TestCase(
                            **common,
                            method="tools/call",
                            path=inv.tool,
                            path_template=inv.tool,
                            mcp=inv,
                        )
                    )
                    # Cross-method probing is HTTP-specific; MCP has no verb.
                    continue

                req = _build_http_request(resource, subject, variant, target, context)
                cases.append(
                    TestCase(
                        **common,
                        method=resource.request.method,
                        path_template=resource.request.path,
                        path=req["path"],
                        query=req["query"],
                        body=req["body"],
                        form=req["form"],
                        headers=req["headers"],
                        matcher=matcher,
                    )
                )

                # Cross-method probing: fire other verbs at the SAME (other)
                # object. Each is a negative test — succeeding means the endpoint
                # authorizes a method the subject was never granted. The request
                # carries the same injected object identifier as the base case.
                if variant == Variant.OTHER and target is not None:
                    for probe in resource.probe_methods:
                        method = probe.upper()
                        if method == resource.request.method.upper():
                            continue
                        cases.append(
                            TestCase(
                                id=(
                                    f"{make_test_id(resource.name, subject.name, variant, id_victim)}"
                                    f"::{method}"
                                ),
                                resource=resource.name,
                                subject=subject.name,
                                role=subject.role,
                                victim=victim,
                                transport=resource.transport,
                                method=method,
                                path_template=resource.request.path,
                                path=req["path"],
                                variant=variant,
                                expected=Effect.DENY,
                                resource_type=resource.type,
                                required_roles=required,
                                query=req["query"],
                                body=req["body"],
                                form=req["form"],
                                headers=req["headers"],
                                matcher=matcher,
                                expect_markers=expect_markers,
                            )
                        )

    cases.extend(_audience_cases(matrix, context))
    cases.extend(_session_cases(matrix, context))
    cases.extend(_enumeration_cases(matrix, context))
    return cases
