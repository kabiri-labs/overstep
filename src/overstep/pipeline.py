"""The run pipeline: matrix in, RunResult out.

This is the orchestration seam. The CLI (and any embedding application) hands a
matrix to :func:`run_pipeline` and gets back a :class:`RunResult`; all the
input/output concerns — argument parsing, printing, file writing — live in the
CLI, and all the domain logic — planning, executing, classifying, drift — is
composed here. The executor is injectable so the pipeline can be tested without a
live target.
"""
from __future__ import annotations

import os
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from overstep.auth import authenticate as default_authenticator
from overstep.classifier import classify
from overstep.coverage import assess as assess_coverage
from overstep.drift import build_snapshot, diff
from overstep.health import assess as assess_health
from overstep.transports import dispatch as default_executor
from overstep.fixtures import run_setup as default_setup_runner
from overstep.fixtures import run_teardown as default_teardown_runner
from overstep.matrix import Matrix
from overstep.models import (
    EVIDENCE_BODY_LIMIT,
    Effect,
    Observation,
    ProbeCoverage,
    ResourceType,
    RunHealth,
    RunResult,
    Subject,
    TestCase,
)
from overstep.planner import plan
from overstep.repro import credential_values, sanitize_evidence
from overstep.report import all_reporters
from overstep.waivers import Waiver, apply_waivers

# A callable with the same shape as executor.run, so tests can inject a fake.
ExecutorFn = Callable[..., List[Observation]]
# A callable with the shape of auth.authenticate.
AuthenticatorFn = Callable[..., None]
# A callable with the shape of fixtures.run_setup (returns a capture context).
SetupFn = Callable[..., dict]
# A callable with the shape of fixtures.run_teardown (returns warning strings).
TeardownFn = Callable[..., List[str]]
# Called once per case as its result comes back, phase by phase.
ObserverFn = Callable[[TestCase, Observation], None]


class PipelineError(RuntimeError):
    """Raised when a run cannot proceed (e.g. no base URL)."""


class InconclusiveRunError(PipelineError):
    """Raised when a run proved nothing, so its result must not be used.

    Carries the :class:`RunHealth` verdict so a caller can explain *why* — the
    target was unreachable, or nothing the matrix expected to be allowed was.
    """

    def __init__(self, health: RunHealth) -> None:
        super().__init__("; ".join(health.reasons) or "the run tested nothing")
        self.health = health


def resolve_base_url(matrix: Matrix, override: Optional[str] = None) -> str:
    base = override or matrix.base_url
    if not base:
        # The base URL is only needed by the HTTP transport; an all-MCP matrix
        # carries its endpoints on the servers block instead.
        if matrix.resources and all(r.transport != "http" for r in matrix.resources):
            return ""
        raise PipelineError("no base URL (set matrix.base_url or pass an override)")
    return base


def _phase_of(case: TestCase) -> int:
    """Where a case sits in the run: the later, the more it can take from others."""
    if not case.is_mutating:
        return 0
    # Only HTTP names its destructive verb. An MCP tool says `mutating` and no
    # more, so it is held back with the other writes rather than guessed at.
    destructive = case.mcp is None and case.method.upper() == "DELETE"
    return 1 + 2 * destructive + (case.expected == Effect.ALLOW)


def phases(cases: Sequence[TestCase]) -> List[List[TestCase]]:
    """Split the plan into the groups that are safe to send concurrently.

    One pool for everything makes the result depend on timing as soon as an
    allowed operation is destructive: an expected-allow DELETE removes an object
    other in-flight cases still target, and they come back 404. That shows up as
    an unexpected denial on a different test each run — and, more quietly, as an
    expected-deny probe that "passes" against an object that is no longer there,
    which is a missing check reported as a working one.

    So the cases go out in this order, each group finishing before the next
    starts, and concurrency applies within a group:

    1. everything that changes nothing;
    2. writes that are not a DELETE (and every mutating MCP tool) the matrix
       expects refused, then the ones it expects allowed;
    3. DELETEs expected refused, then DELETEs expected allowed.

    Refusals lead inside each step for the reason above: a probe has to meet the
    object it is probing. Plan order is kept within a group, and empty groups
    are dropped so a transport is never handed nothing.
    """
    grouped: Dict[int, List[TestCase]] = {}
    for case in cases:
        grouped.setdefault(_phase_of(case), []).append(case)
    return [grouped[key] for key in sorted(grouped)]


def select(
    matrix: Matrix,
    cases: List[TestCase],
    resources: Sequence[str] = (),
    subjects: Sequence[str] = (),
) -> List[TestCase]:
    """The part of the plan a narrowed run sends.

    A subject narrows by who makes the request, not by whose object it reaches
    for: `--subject alice` keeps alice's probes against bob's object, since
    those are the ones that say what alice can do.

    A name the matrix does not declare is refused rather than matched against
    nothing. A typo would otherwise select no cases — or, beside a valid name,
    quietly fewer — and a run that sent less than was asked for and found
    nothing is the shape this tool exists to refuse.
    """
    known_resources = {r.name for r in matrix.resources}
    known_subjects = {s.name for s in matrix.subjects}
    for kind, asked, known in (
        ("resource", resources, known_resources),
        ("subject", subjects, known_subjects),
    ):
        unknown = sorted(set(asked) - known)
        if unknown:
            raise PipelineError(
                f"no {kind} named {', '.join(repr(u) for u in unknown)} in the matrix "
                f"(declared: {', '.join(sorted(known))})"
            )
    chosen = [
        case
        for case in cases
        if (not resources or case.resource in resources)
        and (not subjects or case.subject in subjects)
    ]
    if not chosen:
        raise PipelineError(
            "the selection matches no test case — the named subjects have no "
            "case on the named resources"
        )
    return chosen


def _dispatch_in_phases(
    executor: ExecutorFn,
    resolved: str,
    matrix: Matrix,
    cases: List[TestCase],
    observer: Optional[ObserverFn] = None,
    **kwargs,
) -> List[Observation]:
    """Send each phase in turn and hand the observations back in plan order.

    Plan order rather than send order, so nothing downstream — the documents a
    run writes least of all — moves because the schedule did.
    """
    observations: List[Observation] = []
    by_id = {case.id: case for case in cases}
    for group in phases(cases):
        seen = executor(resolved, matrix.subjects, group, **kwargs)
        observations.extend(seen)
        if observer is not None:
            for obs in seen:
                if obs.test_id in by_id:
                    observer(by_id[obs.test_id], obs)
    position = {case.id: index for index, case in enumerate(cases)}
    # Stable, so anything a transport returned beyond the plan keeps its place
    # at the end instead of being dropped.
    observations.sort(key=lambda obs: position.get(obs.test_id, len(position)))
    return observations


def _execute_stages(
    matrix: Matrix,
    resolved: str,
    *,
    concurrency: int,
    verify_tls: bool,
    read_only: bool,
    max_retries: int,
    backoff_base: float,
    executor: ExecutorFn,
    authenticator: AuthenticatorFn,
    setup_runner: SetupFn,
    teardown_runner: TeardownFn,
    only_resources: Sequence[str] = (),
    only_subjects: Sequence[str] = (),
    observer: Optional[ObserverFn] = None,
) -> Tuple[List[TestCase], List[Observation], List[str], int]:
    """The stages shared by ``run`` and ``snapshot``.

    Order: authenticate (obtain tokens) → run setup steps (create fixtures,
    capture object ids) → plan (using the captures) → dispatch, one
    :func:`phases` group at a time. Teardown runs in a
    ``finally`` so any fixtures the setup steps created are cleaned up even when
    planning or dispatch raises or the run is interrupted; a teardown failure only
    adds a warning and never masks the original error. Returns the cases that
    were sent, the observations, any teardown warnings, and the size of the
    whole plan — which differs from the first only for a narrowed run.
    """
    if only_resources or only_subjects:
        # Asked of the matrix alone, before anything is sent: a mistyped name
        # must not cost a login and a round of setup fixtures to discover.
        select(matrix, plan(matrix), only_resources, only_subjects)
    authenticator(matrix, base_url=resolved, verify_tls=verify_tls)
    context = setup_runner(matrix, base_url=resolved, verify_tls=verify_tls)
    try:
        cases = plan(matrix, context)
        planned = len(cases)
        if only_resources or only_subjects:
            cases = select(matrix, cases, only_resources, only_subjects)
        observations = _dispatch_in_phases(
            executor,
            resolved,
            matrix,
            cases,
            observer,
            concurrency=concurrency,
            verify_tls=verify_tls,
            read_only=read_only,
            max_retries=max_retries,
            backoff_base=backoff_base,
        )
    finally:
        teardown_warnings = teardown_runner(
            matrix, base_url=resolved, verify_tls=verify_tls, context=context
        )
    return cases, observations, teardown_warnings, planned


def _coverage_of(
    matrix: Matrix, cases: List[TestCase], only_resources: Sequence[str]
) -> ProbeCoverage:
    """Probe coverage, measured over what the run was asked to look at.

    Measured against the whole matrix, a run narrowed to one resource reports
    every other object resource as unprobed, and the advice printed beside
    that — give two subjects different objects — is wrong for all of them:
    nothing is the matter with the matrix, they were left out on purpose. The
    run already says it is partial; this keeps the coverage figure about the
    part it ran.
    """
    coverage = assess_coverage(matrix, cases)
    if not only_resources:
        return coverage
    unprobed = [name for name in coverage.unprobed if name in only_resources]
    declared = sum(
        1
        for resource in matrix.resources
        if resource.type == ResourceType.OBJECT and resource.name in only_resources
    )
    return ProbeCoverage(
        object_resources=declared, probed=declared - len(unprobed), unprobed=unprobed
    )


def run_pipeline(
    matrix: Matrix,
    base_url: Optional[str] = None,
    *,
    baseline: Optional[dict] = None,
    waivers: Optional[List["Waiver"]] = None,
    matrix_errors: Optional[Sequence[str]] = None,
    concurrency: int = 10,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    executor: ExecutorFn = default_executor,
    authenticator: AuthenticatorFn = default_authenticator,
    setup_runner: SetupFn = default_setup_runner,
    teardown_runner: TeardownFn = default_teardown_runner,
    only_resources: Sequence[str] = (),
    only_subjects: Sequence[str] = (),
    observer: Optional[ObserverFn] = None,
) -> RunResult:
    """Plan, execute, classify and (optionally) diff against a baseline.

    Shares :func:`_execute_stages` with ``snapshot`` so both commands authenticate,
    set up, plan, dispatch and tear down identically. The auth, setup and teardown
    stages are no-ops unless the matrix declares them, so simple runs pay nothing.

    ``matrix_errors`` are the caller's error-level diagnostics for the matrix
    file, which only the caller can produce — the placeholder scan reads the
    document, and this function is handed the parsed model. They reach the health
    verdict, so a matrix that cannot describe a usable test is reported as an
    inconclusive run rather than a clean one; see :mod:`overstep.health`.
    """
    resolved = resolve_base_url(matrix, base_url)
    cases, observations, teardown_warnings, planned = _execute_stages(
        matrix,
        resolved,
        concurrency=concurrency,
        verify_tls=verify_tls,
        read_only=read_only,
        max_retries=max_retries,
        backoff_base=backoff_base,
        executor=executor,
        authenticator=authenticator,
        setup_runner=setup_runner,
        teardown_runner=teardown_runner,
        only_resources=only_resources,
        only_subjects=only_subjects,
        observer=observer,
    )
    selection = {
        key: sorted(set(names))
        for key, names in (("resources", only_resources), ("subjects", only_subjects))
        if names
    }

    findings = classify(matrix, cases, observations, base_url=resolved)
    if baseline is not None:
        findings = findings + diff(baseline, cases, observations)

    # Every finding is scrubbed here, whichever path built it. `classify` does
    # this for its own — so a caller using it directly is safe too — but drift
    # findings are appended afterwards and would otherwise carry the response
    # exactly as the target wrote it, credentials and all. Doing it once over
    # the whole list means a future third source of findings is covered without
    # anyone having to remember. Sanitizing twice is the same as once.
    secrets = credential_values(matrix.subjects, cases)
    for finding in findings:
        finding.evidence = sanitize_evidence(
            finding.evidence, secrets, EVIDENCE_BODY_LIMIT
        )

    # Health is decided before the waivers so they can be told whether the run
    # is worth drawing conclusions from: on an unreachable target no finding
    # exists for any waiver to match, and "this one may be fixed" would be a
    # claim about something nobody observed.
    health = assess_health(cases, observations, blocking_problems=matrix_errors or ())

    waived: List = []
    warnings: List[str] = []
    if waivers:
        # A narrowed run is in the same position as an inconclusive one here:
        # a waiver with no finding to match may simply be for a case that was
        # left out, and "this one may be fixed" would be said of something
        # nobody sent.
        findings, waived, warnings = apply_waivers(
            findings, waivers, report_unmatched=not (health.inconclusive or selection)
        )

    warnings = warnings + teardown_warnings

    return RunResult(
        base_url=resolved,
        cases=cases,
        observations=observations,
        findings=findings,
        waived=waived,
        warnings=warnings,
        health=health,
        coverage=_coverage_of(matrix, cases, only_resources),
        read_only=read_only,
        selection=selection,
        planned=planned,
    )


def snapshot_pipeline(
    matrix: Matrix,
    base_url: Optional[str] = None,
    *,
    matrix_errors: Optional[Sequence[str]] = None,
    concurrency: int = 10,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    executor: ExecutorFn = default_executor,
    authenticator: AuthenticatorFn = default_authenticator,
    setup_runner: SetupFn = default_setup_runner,
    teardown_runner: TeardownFn = default_teardown_runner,
    allow_inconclusive: bool = False,
) -> Tuple[dict, List[str]]:
    """Record the current authorization decisions as a drift baseline.

    Runs the same orchestration as :func:`run_pipeline` — including the transport
    dispatcher (so MCP and mixed matrices snapshot correctly) and teardown — but
    instead of classifying, it serializes the observed decision for every case.

    Returns the snapshot alongside any teardown warnings so the caller can surface
    a fixture-cleanup failure instead of writing the baseline silently.

    Raises :class:`InconclusiveRunError` when the run never reached the target or
    was never authenticated: such a baseline records "everything is denied" and
    would report the next healthy run as wholesale authorization drift. Pass
    ``allow_inconclusive=True`` to write it anyway.

    ``matrix_errors`` reaches the same verdict here as in :func:`run_pipeline`,
    and matters more: a baseline is the thing every later run is measured
    against, so one recorded from a matrix with an unfilled placeholder does not
    merely mislead once.
    """
    resolved = resolve_base_url(matrix, base_url)
    cases, observations, teardown_warnings, _planned = _execute_stages(
        matrix,
        resolved,
        concurrency=concurrency,
        verify_tls=verify_tls,
        read_only=read_only,
        max_retries=max_retries,
        backoff_base=backoff_base,
        executor=executor,
        authenticator=authenticator,
        setup_runner=setup_runner,
        teardown_runner=teardown_runner,
    )
    health = assess_health(cases, observations, blocking_problems=matrix_errors or ())
    if health.inconclusive and not allow_inconclusive:
        raise InconclusiveRunError(health)
    return build_snapshot(cases, observations), teardown_warnings


def clear_reports(outdir: str, inputs: Iterable[str] = ()) -> List[str]:
    """Delete the documents a previous run left in ``outdir``; return the paths.

    ``run`` writes its reports last, so a run that dies before that — a matrix
    that will not parse, a setup step that fails, a dispatch that is interrupted
    — leaves the previous run's documents exactly where they were, with nothing
    in them that says they are a week old. The next reader cannot tell them from
    the run they just watched fail. That is the fail-open shape in document form,
    and the clean report is the dangerous half of it: stale findings at least
    look like work to do, while a stale ``Vulnerabilities 0`` reads as a pass.

    Only the filenames the registered reporters own are removed, so a directory
    the user keeps other files in survives. A missing directory is not an error;
    nothing is stale in a directory that does not exist yet.

    A file that cannot be removed raises :class:`PipelineError` rather than being
    passed over. Carrying on would leave exactly the document this function
    exists to remove, and the common cause — a ``report.html`` still open in a
    browser — is one sentence away from fixed.

    ``inputs`` are the paths this run was told to *read* — the matrix, a
    baseline, a waivers file, a dotenv. One of them landing on a name a reporter
    owns is refused here rather than worked around, because the collision has no
    safe resolution: removing the file loses what the run was told to read, and
    sparing it only defers the loss to :func:`write_reports`, which overwrites
    that name at the end. A matrix kept at ``out/findings.json`` would be
    destroyed either way, and silently in the second case — the run succeeds and
    the file is simply gone. Refusing costs one clear message instead.
    """
    owned = {
        os.path.realpath(os.path.join(outdir, spec.filename)): spec.filename
        for spec in all_reporters()
    }
    for given in inputs:
        collides = owned.get(os.path.realpath(given))
        if collides:
            raise PipelineError(
                f"'{given}' is also where this run would write its '{collides}' "
                f"report, so overstep would delete or overwrite it. Move the file, "
                f"or choose another --out directory."
            )

    removed: List[str] = []
    for spec in all_reporters():
        path = os.path.join(outdir, spec.filename)
        try:
            os.remove(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PipelineError(
                f"could not remove the previous run's '{path}' ({exc}) — it would "
                f"be left behind and read as this run's result. Close whatever "
                f"holds the file open, or choose another --out directory."
            ) from exc
        removed.append(path)
    return removed


def write_reports(result: RunResult, outdir: str) -> List[str]:
    """Write every registered reporter into ``outdir``; return the paths written."""
    os.makedirs(outdir, exist_ok=True)
    written = []
    for spec in all_reporters():
        path = os.path.join(outdir, spec.filename)
        spec.write(result, path)
        written.append(path)
    return written
