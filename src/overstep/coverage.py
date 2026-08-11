"""Measure how much of the declared BOLA surface a run could actually probe.

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

from typing import Sequence

from overstep.matrix import Matrix
from overstep.models import ProbeCoverage, ResourceType, TestCase, Variant


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
