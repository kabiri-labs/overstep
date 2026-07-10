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


def make_test_id(resource: str, subject: str, variant: Variant) -> str:
    """A stable identifier used for reporting and drift snapshots."""
    return f"{resource}::{subject}::{variant.value}"


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


def _has_object(resource: Resource, subject: Subject) -> bool:
    return subject.name in resource.objects or subject.attributes.get(resource.owner_attr) is not None


def _pick_other(resource: Resource, subject: Subject, subjects: List[Subject]) -> Optional[Subject]:
    """Find another subject that actually owns an object for this resource."""
    for other in subjects:
        if other.name == subject.name:
            continue
        if _has_object(resource, other):
            return other
    return None


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


def _variants(resource: Resource, subject: Subject, subjects: List[Subject]) -> List[Tuple[Variant, Optional[Subject]]]:
    """Which (variant, target) pairs to generate for this subject/resource."""
    if resource.type != ResourceType.OBJECT or not resource.is_object_locatable:
        return [(Variant.NA, None)]

    out: List[Tuple[Variant, Optional[Subject]]] = []
    if _has_object(resource, subject):
        out.append((Variant.SELF, subject))
    other = _pick_other(resource, subject, subjects)
    if other is not None:
        out.append((Variant.OTHER, other))
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
            for variant, target in _variants(resource, subject, subjects):
                expected = _expected_effect(matrix, resource, subject, variant, target)
                # For an OTHER probe, a leak would expose the victim's data, so
                # carry the victim's marker along for the content-aware oracle.
                expect_markers = (
                    [target.marker]
                    if variant == Variant.OTHER and target and target.marker
                    else []
                )
                common = dict(
                    id=make_test_id(resource.name, subject.name, variant),
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
                                id=f"{make_test_id(resource.name, subject.name, variant)}::{method}",
                                resource=resource.name,
                                subject=subject.name,
                                role=subject.role,
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
    return cases
