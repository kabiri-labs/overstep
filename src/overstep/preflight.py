"""Check that a matrix could actually run, before it is asked to.

Two things decide whether a run will mean anything, and neither is visible in
the file: the target has to answer, and the credentials have to be accepted.
:mod:`overstep.health` already judges both — but only afterwards, from the
observations a full run produced. That is the right place for a verdict on a
run that has happened. It is the wrong place to find out that a token expired
last week, because by then every negative test has been sent and the answer is
the generic "the credentials or the matrix are wrong".

The check here is the same question asked first, and answered per subject. It
works by borrowing the run's own positive controls: an expected-*allow* case is
by definition a request the matrix says this subject may make, so sending one
and seeing it allowed is the cheapest possible proof that the identity works.
One case per subject is enough — this is a liveness check, not a run.

Nothing here changes state. The probes go through the executor with
``read_only`` set, so a subject whose only positive control is a mutating verb
is reported as unverifiable rather than being verified destructively.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence

from overstep.auth import AuthError
from overstep.auth import authenticate as default_authenticator
from overstep.executor import MUTATING_METHODS
from overstep.matrix import Matrix, Problem, Severity
from overstep.models import Effect, Observation, TestCase
from overstep.planner import plan
from overstep.transports import dispatch as default_executor


def _positive_control(cases: Sequence[TestCase], subject: str) -> Optional[TestCase]:
    """The cheapest case that proves this subject's credential is accepted.

    Non-mutating verbs are preferred so the check stays side-effect free in
    practice as well as in policy: a subject with both a GET and a DELETE it is
    allowed to make is verified with the GET, and never has the DELETE skipped
    under read-only and reported as unverifiable.
    """
    mine = [c for c in cases if c.subject == subject and c.is_positive_control]
    safe = [c for c in mine if c.method.upper() not in MUTATING_METHODS]
    return (safe or mine or [None])[0]


def _target_of(case: TestCase) -> str:
    """A human label for what this case is delivered to."""
    if case.transport == "mcp" and case.mcp is not None:
        if case.mcp.kind == "stdio":
            return f"MCP server '{' '.join(case.mcp.command)}'"
        return f"MCP server {case.mcp.url}"
    return "the target"


def check(
    matrix: Matrix,
    base_url: str = "",
    *,
    verify_tls: bool = True,
    max_retries: int = 0,
    executor: Callable[..., List[Observation]] = default_executor,
    authenticator: Callable[..., None] = default_authenticator,
) -> List[Problem]:
    """Probe the target with one positive control per subject.

    Returns the problems found, worst first — an empty list means every subject
    the matrix can verify was accepted by a live target. Errors mean a run
    started now would be inconclusive; warnings mean a subject could not be
    checked either way, which is not the same as it being broken.
    """
    problems: List[Problem] = []

    try:
        authenticator(matrix, base_url=base_url, verify_tls=verify_tls)
    except AuthError as exc:
        # No token means no probe worth sending: every subject would be denied
        # for a reason that has nothing to do with authorization.
        return [Problem(f"could not obtain credentials: {exc}", Severity.ERROR)]

    cases = plan(matrix)
    controls: Dict[str, TestCase] = {}
    for subject in matrix.subjects:
        control = _positive_control(cases, subject.name)
        if control is None:
            # An anonymous subject carries no credential and is expected to be
            # allowed nothing, so having no positive control is its normal
            # shape, not a gap. Only a subject holding a token has something
            # here that could silently be dead.
            if subject.token:
                problems.append(Problem(
                    f"subject '{subject.name}' holds a credential but has no "
                    f"expected-allow test, so nothing here can prove it works — "
                    f"the negative results for it will be unverified",
                    Severity.WARNING,
                ))
            continue
        controls[subject.name] = control

    if not controls:
        return problems

    observations = {
        obs.test_id: obs
        for obs in executor(
            base_url,
            matrix.subjects,
            list(controls.values()),
            concurrency=len(controls),
            verify_tls=verify_tls,
            read_only=True,
            max_retries=max_retries,
        )
    }

    for name, control in controls.items():
        obs = observations.get(control.id)
        if obs is None:
            # No transport claimed the case; dispatch records this as a delivery
            # failure, so an absent observation means the executor was replaced.
            problems.append(Problem(
                f"subject '{name}': no result came back for its probe", Severity.ERROR
            ))
        elif obs.skipped:
            problems.append(Problem(
                f"subject '{name}' can only be verified with {control.method}, which "
                f"changes state — its credential was left unchecked rather than "
                f"tested destructively",
                Severity.WARNING,
            ))
        elif obs.status == 0:
            # Every transport reserves status 0 for a delivery failure.
            problems.append(Problem(
                f"{_target_of(control)} did not answer {control.method} "
                f"{control.path} ({obs.error or 'no response'}) — a run now would "
                f"report everything as denied because nothing got through",
                Severity.ERROR,
            ))
        elif obs.effect != Effect.ALLOW:
            problems.append(Problem(
                f"subject '{name}' was denied {control.method} {control.path} "
                f"(HTTP {obs.status}), which the matrix expects to be allowed — its "
                f"credential is rejected or expired, or the policy is wrong; every "
                f"negative result for it would be meaningless",
                Severity.ERROR,
            ))

    return sorted(problems, key=lambda p: p.severity is not Severity.ERROR)
