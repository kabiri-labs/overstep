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
from typing import Callable, List, Optional

from overstep.auth import authenticate as default_authenticator
from overstep.classifier import classify
from overstep.drift import diff
from overstep.executor import run as default_executor
from overstep.fixtures import run_setup as default_setup_runner
from overstep.matrix import Matrix
from overstep.models import Observation, RunResult, Subject, TestCase
from overstep.planner import plan
from overstep.report import all_reporters

# A callable with the same shape as executor.run, so tests can inject a fake.
ExecutorFn = Callable[..., List[Observation]]
# A callable with the shape of auth.authenticate.
AuthenticatorFn = Callable[..., None]
# A callable with the shape of fixtures.run_setup (returns a capture context).
SetupFn = Callable[..., dict]


class PipelineError(RuntimeError):
    """Raised when a run cannot proceed (e.g. no base URL)."""


def resolve_base_url(matrix: Matrix, override: Optional[str] = None) -> str:
    base = override or matrix.base_url
    if not base:
        raise PipelineError("no base URL (set matrix.base_url or pass an override)")
    return base


def run_pipeline(
    matrix: Matrix,
    base_url: Optional[str] = None,
    *,
    baseline: Optional[dict] = None,
    concurrency: int = 10,
    verify_tls: bool = True,
    executor: ExecutorFn = default_executor,
    authenticator: AuthenticatorFn = default_authenticator,
    setup_runner: SetupFn = default_setup_runner,
) -> RunResult:
    """Plan, execute, classify and (optionally) diff against a baseline.

    Order: authenticate (obtain tokens) → run setup steps (create fixtures,
    capture object ids) → plan (using the captures) → execute. The auth and setup
    stages are no-ops unless the matrix declares them, so simple runs pay nothing.
    """
    resolved = resolve_base_url(matrix, base_url)
    authenticator(matrix, base_url=resolved, verify_tls=verify_tls)
    context = setup_runner(matrix, base_url=resolved, verify_tls=verify_tls)
    cases = plan(matrix, context)
    observations = executor(
        resolved, matrix.subjects, cases, concurrency=concurrency, verify_tls=verify_tls
    )

    findings = classify(matrix, cases, observations)
    if baseline is not None:
        findings = findings + diff(baseline, cases, observations)

    return RunResult(
        base_url=resolved,
        cases=cases,
        observations=observations,
        findings=findings,
    )


def write_reports(result: RunResult, outdir: str) -> List[str]:
    """Write every registered reporter into ``outdir``; return the paths written."""
    os.makedirs(outdir, exist_ok=True)
    written = []
    for spec in all_reporters():
        path = os.path.join(outdir, spec.filename)
        spec.write(result, path)
        written.append(path)
    return written
