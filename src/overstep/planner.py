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
from overstep.matrix import Matrix
from overstep.models import (
    Effect,
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


def _render_path(
    resource: Resource,
    subject: Subject,
    variant: Variant,
    target: Optional[Subject],
    context: Dict[str, str],
) -> str:
    """Fill in every {param} in the resource path.

    The owner_param is driven by the variant (own object id vs. another subject's);
    any other params fall back to the subject's own attributes, then to "1".
    """
    path = resource.request.path
    for param in _path_params(path):
        if resource.owner_param and param == resource.owner_param and variant != Variant.NA:
            src = subject if variant == Variant.SELF else target
            value = _object_id(resource, src, context) if src else None
        else:
            value = subject.attributes.get(param)
        if value is None:
            value = "1"
        path = path.replace("{%s}" % param, str(value))
    return path


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
    if resource.type != ResourceType.OBJECT or not resource.owner_param:
        return [(Variant.NA, None)]

    out: List[Tuple[Variant, Optional[Subject]]] = []
    if _has_object(resource, subject):
        out.append((Variant.SELF, subject))
    other = _pick_other(resource, subject, subjects)
    if other is not None:
        out.append((Variant.OTHER, other))
    return out or [(Variant.OTHER, None)]


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
                path = _render_path(resource, subject, variant, target, context)
                # For an OTHER probe, a leak would expose the victim's data, so
                # carry the victim's marker along for the content-aware oracle.
                expect_markers = (
                    [target.marker]
                    if variant == Variant.OTHER and target and target.marker
                    else []
                )
                cases.append(
                    TestCase(
                        id=make_test_id(resource.name, subject.name, variant),
                        resource=resource.name,
                        subject=subject.name,
                        role=subject.role,
                        transport=resource.transport,
                        method=resource.request.method,
                        path_template=resource.request.path,
                        path=path,
                        variant=variant,
                        expected=expected,
                        resource_type=resource.type,
                        required_roles=required,
                        query=render(dict(resource.request.query), context),
                        body=render(resource.request.body, context),
                        headers=render(dict(resource.request.headers), context),
                        matcher=matcher,
                        expect_markers=expect_markers,
                    )
                )

                # Cross-method probing: fire other verbs at the SAME (other)
                # object. Each is a negative test — succeeding means the endpoint
                # authorizes a method the subject was never granted.
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
                                path=path,
                                variant=variant,
                                expected=Effect.DENY,
                                resource_type=resource.type,
                                required_roles=required,
                                query=render(dict(resource.request.query), context),
                                body=render(resource.request.body, context),
                                headers=render(dict(resource.request.headers), context),
                                matcher=matcher,
                                expect_markers=expect_markers,
                            )
                        )
    return cases
