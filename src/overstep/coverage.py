"""Measure what a matrix covers — of the API, and of its own object surface.

Two different absences, both of which make ``Vulnerabilities 0`` mean less than
it looks like, and neither of which a finding count can express.

*Spec coverage* is the outer one: an operation that never entered the matrix is
never tested, and nothing in a run mentions it. The matrix is the specification,
so a gap in it is invisible by construction — the only way to see one is to
compare the matrix against an independent description of the API.

*Probe coverage* is the inner one: a resource can be in the matrix, be requested
on every run, and still never be asked the question it was declared for.

An object resource is a claim that object-level access control matters here.
Testing that claim takes a cross-owner probe — one subject reaching for another
subject's object — and the planner only generates one when two subjects resolve
to genuinely different objects (see :func:`overstep.planner._victims`). When they
don't, the probe is dropped rather than faked, which is the right call: replaying
a subject's own request under the OTHER label would manufacture a pass.

What is missing is the accounting. A dropped probe leaves no trace in the finding
count, so a resource that was never tested for BOLA and a resource that was
tested and found clean produce the same ``Vulnerabilities 0``. That is the one
claim this tool cannot afford to blur — reporting the absence of a finding means
something only if the run could have seen it.

``validate`` already warns about the matrix-level cause, but a warning at lint
time is not the same as a number on the report a run hands to somebody else.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Sequence

from overstep.matrix import Matrix
from overstep.models import ProbeCoverage, Resource, ResourceType, TestCase, Variant

_PARAM_RE = re.compile(r"{[^}]*}")


def _normalize(method: str, path: str) -> str:
    """A comparable key for one operation.

    Path parameter *names* are the matrix author's choice, not the API's: a spec
    writing ``/users/{id}`` and a matrix writing ``/users/{user_id}`` describe
    the same operation, and reporting that as a gap would send someone to fix
    something that is not broken. The name is dropped and the position kept.
    A trailing slash is likewise not a distinct operation.
    """
    collapsed = _PARAM_RE.sub("{}", path.strip())
    if len(collapsed) > 1:
        collapsed = collapsed.rstrip("/")
    return f"{method.strip().upper()} {collapsed}"


def _label(resource: Resource) -> str:
    """How an operation is named back to the user: as they would write it."""
    if resource.request is not None:
        return f"{resource.request.method.upper()} {resource.request.path}"
    if resource.call is not None:
        return f"tool {resource.call.tool}"
    return resource.name


@dataclass(frozen=True)
class SpecCoverage:
    """How much of an API description the matrix actually declares.

    ``missing`` is the point of the measurement: operations the API has and the
    matrix does not, which no run can report on because no run will send them.
    ``extra`` is the other direction — resources the matrix tests that the
    description does not mention. That is not necessarily wrong (an undocumented
    endpoint is worth testing, and specs go stale), but it is worth seeing,
    because it also catches a path typed wrongly into the matrix.
    """

    operations: int = 0
    missing: List[str] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)

    @property
    def covered(self) -> int:
        return self.operations - len(self.missing)

    @property
    def complete(self) -> bool:
        return not self.missing

    @property
    def ratio(self) -> float:
        """Declared share of the API's operations; 1.0 when it has none."""
        if not self.operations:
            return 1.0
        return self.covered / self.operations


def against_spec(matrix: Matrix, declared: Sequence[Resource]) -> SpecCoverage:
    """Compare a matrix against an independent description of the same API.

    ``declared`` is whatever a loader read — OpenAPI operations, HAR entries,
    MCP tools. Matching is by normalized method and path (or tool name), so the
    two sides may disagree about parameter naming without producing phantom
    gaps.
    """
    spec_keys = {}
    for resource in declared:
        spec_keys.setdefault(_key(resource), _label(resource))
    matrix_keys = {_key(r) for r in matrix.resources}

    missing = [label for key, label in spec_keys.items() if key not in matrix_keys]
    extra = [
        _label(r) for r in matrix.resources if _key(r) not in spec_keys
    ]
    return SpecCoverage(operations=len(spec_keys), missing=missing, extra=extra)


def _key(resource: Resource) -> str:
    """The identity an operation is matched on across the two sides."""
    if resource.transport == "mcp" and resource.call is not None:
        return f"MCP {resource.call.tool}"
    if resource.request is None:
        # Nothing deliverable to compare; fall back to the name so the resource
        # is still accounted for rather than silently matching everything.
        return f"?? {resource.name}"
    return _normalize(resource.request.method, resource.request.path)


def assess(matrix: Matrix, cases: Sequence[TestCase]) -> ProbeCoverage:
    """Count the object resources that got a real cross-owner probe.

    Both inputs are needed and neither substitutes for the other: the matrix
    knows every object resource that was *declared*, including ones no subject
    could reach and which therefore produced no cases at all, while the cases
    know which of them a cross-owner probe was actually planned for. Counting
    from the cases alone would quietly drop the worst offenders — a resource
    with no probes at all would simply not appear.
    """
    declared = [r.name for r in matrix.resources if r.type == ResourceType.OBJECT]
    # The victim is what makes it a *cross-owner* probe. An OTHER case without
    # one reaches for a default object that belongs to nobody, so counting it
    # would report coverage the run does not have — the exact confusion this
    # measurement exists to remove.
    probed = {
        c.resource
        for c in cases
        if c.variant == Variant.OTHER and c.victim is not None
    }
    unprobed = [name for name in declared if name not in probed]
    return ProbeCoverage(
        object_resources=len(declared),
        probed=len(declared) - len(unprobed),
        unprobed=unprobed,
    )
