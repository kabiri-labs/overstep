"""Detect a run that never actually tested anything.

An authorization run only means something if the requests reached the target and
the credentials were accepted. When they didn't, every negative test "passes" for
the wrong reason — nothing was allowed because nothing got through — and the
summary reads ``Vulnerabilities 0`` with a zero exit code. A security gate that
reports success when the target was unreachable fails *open*, which is the one
failure mode a gate must not have.

The evidence needed to catch this is already on the observations: both transports
record a delivery failure as ``status == 0``, and a deliberately skipped test
carries ``skipped``. This module turns that into an explicit verdict so the caller
can refuse to report success for a run that proved nothing.

A run is inconclusive when, **for any one target**, either

* **unreachable** — most requests never got through (target down, wrong base URL,
  a dead stdio server, DNS or TLS failure);
* **unverified** — nothing proves the credentials work: either every planned
  expected-*allow* test was skipped, or none of the ones that ran was allowed.

The judgement is per target rather than over the whole run because a matrix may
span several: a busy, healthy HTTP API would otherwise mask an MCP server that
answered nothing, and the MCP half of the run would report clean while never
having executed. Targets are the units that can fail independently — each
transport, and within MCP each server. A target with no expected-allow tests at
all is not condemned — an intentionally all-negative matrix has no positive
control to lose.
"""
from __future__ import annotations

from typing import Dict, List, Sequence, Set, Tuple

from overstep.models import Effect, Observation, RunHealth, TestCase
from overstep.transports.base import DEFAULT_TRANSPORT

# The share of a target's requests that must fail at the transport layer before
# it is called unreachable. High enough that one flaky timeout is not fatal, low
# enough that a target which is mostly down still trips it.
UNREACHABLE_RATIO = 0.5


def _never_delivered(obs: Observation) -> bool:
    """True when the request never reached the target.

    Every transport reserves ``status == 0`` for a delivery failure, and it is
    the only thing that sets it: an HTTP or MCP transport error, a launch
    failure, or a stdio call that timed out or hit EOF (which yields no message
    and, unlike the others, no error string either — so the status alone is the
    signal). Skipped observations share the status but are excluded by the
    caller, since not sending a request was the point.
    """
    return obs.status == 0


def _target(case: TestCase) -> str:
    """A label for the endpoint a case is delivered to.

    Reachability is a property of a target, not of a run, so cases are judged in
    the groups that can independently fail. The transport is the coarse grouping
    — the registry accepts any name, and a transport nobody registered in this
    process fails as a unit — and MCP is refined further, since one matrix can
    address several servers (by URL, or by argv for a local stdio process).
    """
    transport = case.transport or DEFAULT_TRANSPORT
    if transport == "mcp" and case.mcp is not None:
        if case.mcp.kind == "stdio":
            return f"MCP server '{' '.join(case.mcp.command)}'"
        return f"MCP server {case.mcp.url}"
    if transport == DEFAULT_TRANSPORT:
        return "the HTTP target"
    return f"the '{transport}' transport"


def _pairs(
    cases: Sequence[TestCase], observations: Sequence[Observation]
) -> List[Tuple[TestCase, Observation]]:
    """Every case that produced an observation, paired with it."""
    seen = {obs.test_id: obs for obs in observations}
    return [(case, seen[case.id]) for case in cases if case.id in seen]


def _group(
    cases: Sequence[TestCase], observations: Sequence[Observation]
) -> Dict[str, List[Tuple[TestCase, Observation]]]:
    """Pair every case with its observation, grouped by target."""
    grouped: Dict[str, List[Tuple[TestCase, Observation]]] = {}
    for case, obs in _pairs(cases, observations):
        grouped.setdefault(_target(case), []).append((case, obs))
    return grouped


def _untested_resources(
    cases: Sequence[TestCase],
    observations: Sequence[Observation],
    excluded_targets: Set[str],
) -> List[Tuple[str, int, int]]:
    """Resources whose every sent request failed at the transport, worst first.

    A target answering most of its requests can still hold one endpoint that
    answers none — a wedged route, a dependency that is down, a proxy rule that
    drops one path. The target-level ratio is deliberately blunt enough to
    survive a flaky timeout, so such an endpoint sits far below it and vanishes:
    its negative tests are recorded as denied, which is what the matrix expected,
    so they produce no finding and read exactly like probes that ran and found
    nothing.

    The threshold here is *every* request, not any. One probe of three timing out
    is a flake, and condemning a run for it would teach the reader to pass
    ``--allow-inconclusive`` permanently, which costs more than it saves. A
    resource that got nothing through was not tested, and that is a different
    statement from a resource that was.

    Targets already reported unreachable are excluded: every resource on them
    failed by definition, and saying so again is the same fact told twice.
    """
    grouped: Dict[str, List[Tuple[TestCase, Observation]]] = {}
    for case, obs in _pairs(cases, observations):
        if _target(case) in excluded_targets or obs.skipped:
            continue
        grouped.setdefault(case.resource, []).append((case, obs))

    out: List[Tuple[str, int, int]] = []
    for resource, pairs in grouped.items():
        if not all(_never_delivered(o) for _, o in pairs):
            continue
        negatives = sum(1 for c, _ in pairs if c.expected == Effect.DENY)
        out.append((resource, len(pairs), negatives))
    # Most negative tests lost first: those are the ones whose silence is a
    # missing answer about authorization rather than a missing positive control.
    return sorted(out, key=lambda item: (-item[2], item[0]))


def assess(
    cases: Sequence[TestCase],
    observations: Sequence[Observation],
    *,
    unreachable_ratio: float = UNREACHABLE_RATIO,
) -> RunHealth:
    """Judge whether a run's observations are worth drawing conclusions from."""
    grouped = _group(cases, observations)
    sent_all = [o for o in observations if not o.skipped]
    # Only a case whose allowed result would prove the credential works counts;
    # see TestCase.is_positive_control for the one that looks like it and isn't.
    controls = {case.id for case in cases if case.is_positive_control}
    positives_all = [o for o in sent_all if o.test_id in controls]

    negatives = {case.id for case in cases if case.expected == Effect.DENY}
    health = RunHealth(
        executed=len(sent_all),
        transport_errors=sum(1 for o in sent_all if _never_delivered(o)),
        undelivered_negative=sum(
            1 for o in sent_all if _never_delivered(o) and o.test_id in negatives
        ),
        positive_tests=len(positives_all),
        positive_allowed=sum(1 for o in positives_all if o.effect == Effect.ALLOW),
    )

    if not sent_all:
        health.reasons.append(
            "no request was sent — every planned test was skipped, so nothing was tested"
        )
        return health

    # Name the target only when there is more than one, so the common
    # single-target message stays readable.
    label_targets = len(grouped) > 1
    unreachable: Set[str] = set()

    for target, pairs in grouped.items():
        prefix = f"{target}: " if label_targets else ""
        sent = [(c, o) for c, o in pairs if not o.skipped]
        planned_positive = [c for c, _ in pairs if c.is_positive_control]

        if not sent:
            health.reasons.append(
                f"{prefix}every planned test was skipped, so this target was never exercised"
            )
            continue

        errors = [o for _, o in sent if _never_delivered(o)]
        if len(errors) / len(sent) >= unreachable_ratio:
            detail = errors[0].error or "no response"
            health.reasons.append(
                f"{prefix}{len(errors)} of {len(sent)} requests never reached the target "
                f"(first failure: {detail}) — it is unreachable, so these results say "
                f"nothing about authorization"
            )
            # Its positive controls failed too, but that is the same fact told
            # twice: an unreachable target denies everything by definition.
            unreachable.add(target)
            continue

        positives = [(c, o) for c, o in sent if c.is_positive_control]
        if planned_positive and not positives:
            health.reasons.append(
                f"{prefix}every expected-allow test was skipped, so nothing proves the "
                f"credentials work — the negative results are unverified"
            )
        elif positives and not any(o.effect == Effect.ALLOW for _, o in positives):
            health.reasons.append(
                f"{prefix}none of the {len(positives)} expected-allow tests were allowed — "
                f"the credentials or the matrix are wrong, so the negative results cannot "
                f"be trusted"
            )

    # A healthy target can still hold one endpoint that answered nothing, and
    # that endpoint's negative tests are the ones whose silence reads as safety.
    for resource, sent_count, negative_count in _untested_resources(
        cases, observations, unreachable
    ):
        health.untested_resources.append(resource)
        lost = (
            f", {negative_count} of them negative" if negative_count else ""
        )
        health.reasons.append(
            f"resource '{resource}': none of its {sent_count} request(s) reached "
            f"the target{lost} — it was not tested, so a clean result here is the "
            f"absence of an answer rather than a safe one"
        )

    return health
