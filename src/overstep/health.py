"""Detect a run that never actually tested anything.

An authorization run only means something if the requests reached the target and
the credentials were accepted. When they didn't, every negative test "passes" for
the wrong reason — nothing was allowed because nothing got through — and the
summary reads ``Vulnerabilities 0`` with a zero exit code. A security gate that
reports success when the target was unreachable fails *open*, which is the one
failure mode a gate must not have.

The evidence needed to catch this is already on the observations: both transports
record a delivery failure as ``status == 0`` with an ``error``, and a deliberately
skipped test carries ``skipped``. This module turns that into an explicit verdict
so the caller can refuse to report success for a run that proved nothing.

Two conditions make a run inconclusive:

* **unreachable** — most requests never got through (target down, wrong base URL,
  DNS or TLS failure);
* **rejected** — requests arrived but not one of the expected-*allow* tests was
  allowed, which is what expired credentials or a misconfigured matrix look like.
"""
from __future__ import annotations

from typing import Sequence

from overstep.models import Effect, Observation, RunHealth, TestCase

# The share of sent requests that must fail at the transport layer before the run
# is called unreachable. High enough that one flaky timeout is not fatal, low
# enough that a target which is mostly down still trips it.
UNREACHABLE_RATIO = 0.5


def _never_delivered(obs: Observation) -> bool:
    """True when the request never reached the target.

    ``status == 0`` plus an error is the signal both transports use for a
    delivery failure. An MCP JSON-RPC error also sets ``error`` but carries the
    real HTTP status, so it stays what it is — a genuine denial, not a failure to
    connect.
    """
    return not obs.skipped and obs.status == 0 and bool(obs.error)


def assess(
    cases: Sequence[TestCase],
    observations: Sequence[Observation],
    *,
    unreachable_ratio: float = UNREACHABLE_RATIO,
) -> RunHealth:
    """Judge whether a run's observations are worth drawing conclusions from."""
    expected_by_id = {case.id: case.expected for case in cases}
    sent = [o for o in observations if not o.skipped]
    errors = [o for o in sent if _never_delivered(o)]
    positives = [o for o in sent if expected_by_id.get(o.test_id) == Effect.ALLOW]
    allowed = [o for o in positives if o.effect == Effect.ALLOW]

    health = RunHealth(
        executed=len(sent),
        transport_errors=len(errors),
        positive_tests=len(positives),
        positive_allowed=len(allowed),
    )

    if not sent:
        health.reasons.append(
            "no request was sent — every planned test was skipped, so nothing was tested"
        )
        return health

    if len(errors) / len(sent) >= unreachable_ratio:
        health.reasons.append(
            f"{len(errors)} of {len(sent)} requests never reached the target "
            f"(first error: {errors[0].error}) — the target is unreachable, so these "
            f"results say nothing about authorization"
        )

    if positives and not allowed:
        health.reasons.append(
            f"none of the {len(positives)} expected-allow tests were allowed — the "
            f"credentials or the matrix are wrong, so the negative results cannot be "
            f"trusted"
        )

    return health
