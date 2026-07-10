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
from typing import Callable, List, Optional, Tuple

from overstep.auth import authenticate as default_authenticator
from overstep.classifier import classify
from overstep.drift import build_snapshot, diff
from overstep.transports import dispatch as default_executor
from overstep.fixtures import run_setup as default_setup_runner
from overstep.fixtures import run_teardown as default_teardown_runner
from overstep.matrix import Matrix
from overstep.models import Observation, RunResult, Subject, TestCase
from overstep.planner import plan
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


class PipelineError(RuntimeError):
    """Raised when a run cannot proceed (e.g. no base URL)."""


def resolve_base_url(matrix: Matrix, override: Optional[str] = None) -> str:
    base = override or matrix.base_url
    if not base:
        # The base URL is only needed by the HTTP transport; an all-MCP matrix
        # carries its endpoints on the servers block instead.
        if matrix.resources and all(r.transport != "http" for r in matrix.resources):
            return ""
        raise PipelineError("no base URL (set matrix.base_url or pass an override)")
    return base


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
) -> Tuple[List[TestCase], List[Observation], List[str]]:
    """The stages shared by ``run`` and ``snapshot``.

    Order: authenticate (obtain tokens) → run setup steps (create fixtures,
    capture object ids) → plan (using the captures) → dispatch. Teardown runs in a
    ``finally`` so any fixtures the setup steps created are cleaned up even when
    planning or dispatch raises or the run is interrupted; a teardown failure only
    adds a warning and never masks the original error. Returns the planned cases,
    the observations, and any teardown warnings.
    """
    authenticator(matrix, base_url=resolved, verify_tls=verify_tls)
    context = setup_runner(matrix, base_url=resolved, verify_tls=verify_tls)
    try:
        cases = plan(matrix, context)
        observations = executor(
            resolved,
            matrix.subjects,
            cases,
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
    return cases, observations, teardown_warnings


def run_pipeline(
    matrix: Matrix,
    base_url: Optional[str] = None,
    *,
    baseline: Optional[dict] = None,
    waivers: Optional[List["Waiver"]] = None,
    concurrency: int = 10,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    executor: ExecutorFn = default_executor,
    authenticator: AuthenticatorFn = default_authenticator,
    setup_runner: SetupFn = default_setup_runner,
    teardown_runner: TeardownFn = default_teardown_runner,
) -> RunResult:
    """Plan, execute, classify and (optionally) diff against a baseline.

    Shares :func:`_execute_stages` with ``snapshot`` so both commands authenticate,
    set up, plan, dispatch and tear down identically. The auth, setup and teardown
    stages are no-ops unless the matrix declares them, so simple runs pay nothing.
    """
    resolved = resolve_base_url(matrix, base_url)
    cases, observations, teardown_warnings = _execute_stages(
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

    findings = classify(matrix, cases, observations, base_url=resolved)
    if baseline is not None:
        findings = findings + diff(baseline, cases, observations)

    waived: List = []
    warnings: List[str] = []
    if waivers:
        findings, waived, warnings = apply_waivers(findings, waivers)

    warnings = warnings + teardown_warnings

    return RunResult(
        base_url=resolved,
        cases=cases,
        observations=observations,
        findings=findings,
        waived=waived,
        warnings=warnings,
    )


def snapshot_pipeline(
    matrix: Matrix,
    base_url: Optional[str] = None,
    *,
    concurrency: int = 10,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    executor: ExecutorFn = default_executor,
    authenticator: AuthenticatorFn = default_authenticator,
    setup_runner: SetupFn = default_setup_runner,
    teardown_runner: TeardownFn = default_teardown_runner,
) -> dict:
    """Record the current authorization decisions as a drift baseline.

    Runs the same orchestration as :func:`run_pipeline` — including the transport
    dispatcher (so MCP and mixed matrices snapshot correctly) and teardown — but
    instead of classifying, it serializes the observed decision for every case.
    """
    resolved = resolve_base_url(matrix, base_url)
    cases, observations, _ = _execute_stages(
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
    return build_snapshot(cases, observations)


def write_reports(result: RunResult, outdir: str) -> List[str]:
    """Write every registered reporter into ``outdir``; return the paths written."""
    os.makedirs(outdir, exist_ok=True)
    written = []
    for spec in all_reporters():
        path = os.path.join(outdir, spec.filename)
        spec.write(result, path)
        written.append(path)
    return written
