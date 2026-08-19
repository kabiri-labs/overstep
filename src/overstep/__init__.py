"""overstep — authorization testing for REST APIs and MCP servers.

Authorization is one problem class: does the callee verify that this caller may
perform this action on this object? REST and MCP are two surfaces on which it
shows up, so they are modules over a shared core rather than two tools.

overstep takes a declarative *authorization matrix* (who is allowed to do what)
and turns it into concrete positive and negative requests, delivered over
whichever transport each resource declares. Negative tests that unexpectedly
succeed are reported as authorization vulnerabilities and classified as BOLA,
BFLA, BOPLA or privilege escalation. Results can be snapshotted so that CI can
fail on *authorization drift* between releases.

The public API mirrors the pipeline stages, so an embedding application can do::

    from overstep import load_matrix, run_pipeline, write_reports

    matrix = load_matrix("matrix.yaml")
    result = run_pipeline(matrix)
    write_reports(result, "out")
    if result.vulnerabilities:
        raise SystemExit(1)
"""

__version__ = "0.37.3"

from overstep.auth import authenticate
from overstep.matrix import Matrix, Problem, Severity, load_matrix
from overstep.models import Finding, RunResult, VulnClass
from overstep.pipeline import run_pipeline, write_reports
from overstep.planner import plan

__all__ = [
    "__version__",
    "Matrix",
    "Problem",
    "Severity",
    "load_matrix",
    "plan",
    "authenticate",
    "run_pipeline",
    "write_reports",
    "RunResult",
    "Finding",
    "VulnClass",
]
