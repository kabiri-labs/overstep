"""Command-line interface for overstep.

The CLI is intentionally thin: it parses arguments, calls into
:mod:`overstep.pipeline`, and renders results. All domain logic lives behind
``run_pipeline`` so it can be reused and tested without the terminal.

Commands:

* ``run``       — generate tests from the matrix, execute them and report.
* ``snapshot``  — record the current authorization decisions as a drift baseline.
* ``plan``      — print the generated test cases without touching the network.
* ``validate``  — check a matrix file for structural problems and placeholders,
  and with ``--live`` probe the target for reachability and credential liveness.
* ``coverage``  — report what the matrix covers, against a spec and against
  its own object surface. Sends nothing.
* ``scaffold``  — emit a starter resources block from an OpenAPI/HAR file.
"""
from __future__ import annotations

import os
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from overstep import __version__
from overstep.auth import AuthError
from overstep.coverage import SpecCoverage, against_spec
from overstep.coverage import assess as assess_coverage
from overstep.documents import DocumentError
from overstep.drift import load_snapshot, save_snapshot
from overstep.fixtures import SetupError
from overstep.matrix import Matrix, MatrixError, Problem, Severity, load_matrix
from overstep.models import Effect, ProbeCoverage, RunHealth, RunResult
from overstep.placeholders import scan as scan_placeholders
from overstep.preflight import check as preflight_check
from overstep.pipeline import (
    InconclusiveRunError,
    PipelineError,
    resolve_base_url,
    run_pipeline,
    snapshot_pipeline,
    write_reports,
)
from overstep.planner import plan
from overstep.report import summarize
from overstep.waivers import WaiverError, load_waivers

# The accepted values for --fail-on, in the order they appear in help text.
FAIL_ON_CHOICES = ("vuln", "drift", "vuln-or-drift", "any", "never")

# Exit code for a run that proved nothing (unreachable target, rejected
# credentials). Distinct from 1 (findings) and 2 (bad input / setup failure) so
# CI can tell "your API is broken" apart from "the scan never ran".
EXIT_INCONCLUSIVE = 3

app = typer.Typer(
    help="overstep — matrix-driven authorization testing for HTTP APIs.",
    add_completion=False,
)
console = Console()
# Warnings that must not pollute a redirected stdout (scaffold writes YAML there).
err_console = Console(stderr=True)


# Set this to anything to silence the "next:" hints.
NO_HINTS_ENV = "OVERSTEP_NO_HINTS"


def _next_step(command: str, why: str) -> None:
    """Point at the next command on the path from a spec to a first real run.

    The commands are individually clear and collectively a sequence nobody is
    told: scaffold, fill in, validate, check the target, read the plan, run. A
    user who stops after any one of them has a file rather than a result, so
    each step ends by naming the next.

    Written to **stderr** so it never lands in a redirected ``scaffold`` file,
    and skipped entirely when ``OVERSTEP_NO_HINTS`` is set — a pipeline knows
    its own next step.
    """
    if os.environ.get(NO_HINTS_ENV):
        return
    err_console.print(f"[dim]next: {command} — {why}[/]")


def _apply_env_file(path: Optional[str]) -> None:
    """Load KEY=VALUE lines from a dotenv file into the process environment."""
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError as exc:
        console.print(f"[bold red]error:[/] could not read env file '{path}': {exc}")
        raise typer.Exit(code=2)


def _load(matrix_path: str, env_file: Optional[str] = None):
    _apply_env_file(env_file)
    try:
        return load_matrix(matrix_path)
    except MatrixError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)


def _diagnose(matrix_path: str, spec: Matrix) -> list[Problem]:
    """Everything wrong with a matrix, from the file and from the model.

    The two scans see different things — only the file has line numbers and
    unfilled placeholders, only the model has resolved references — so both run,
    and placeholders lead because they are the ones that stop a run from meaning
    anything.
    """
    return scan_placeholders(matrix_path) + spec.diagnose()


def _preflight(spec: Matrix, base: Optional[str], *, verify_tls: bool) -> list[Problem]:
    """Ask the target the two questions the file cannot answer.

    Setup steps are deliberately not run: they create fixtures and can change
    state, which a check is not entitled to do. A matrix whose credentials only
    exist after setup is reported as unverified rather than verified wrongly.
    """
    resolved = _resolve(spec, base)
    try:
        return preflight_check(spec, resolved, verify_tls=verify_tls)
    except SetupError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)


def _resolve(spec, override: Optional[str]) -> str:
    try:
        return resolve_base_url(spec, override)
    except PipelineError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)


@app.command()
def run(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    base: Optional[str] = typer.Option(None, help="Base URL override."),
    out: str = typer.Option("out", help="Output directory for reports."),
    baseline: Optional[str] = typer.Option(None, help="Snapshot to compare against for drift."),
    waivers: Optional[str] = typer.Option(None, help="Waivers file of accepted findings."),
    fail_on: str = typer.Option(
        "vuln",
        help="Exit non-zero on: vuln | drift | vuln-or-drift | any | never.",
    ),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    read_only: bool = typer.Option(False, help="Skip mutating verbs (POST/PUT/PATCH/DELETE)."),
    max_retries: int = typer.Option(2, help="Retries on 429/503 with backoff."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
    allow_inconclusive: bool = typer.Option(
        False,
        help="Report a run that never reached the target instead of exiting 3.",
    ),
):
    """Run the matrix against a live target and write reports."""
    _validate_fail_on(fail_on)
    spec = _load(matrix, env_file)
    # Said before the first request goes out: an unfilled placeholder makes the
    # whole run inconclusive, and the file is the only place that says which
    # line to edit. The run still proceeds — the exit code stays the business of
    # --fail-on and the health verdict.
    for problem in _diagnose(matrix, spec):
        level = "bold red" if problem.severity is Severity.ERROR else "yellow"
        console.print(f"[{level}]{problem.severity.value}:[/] {problem}")

    base_url = _resolve(spec, base)
    try:
        snapshot_data = load_snapshot(baseline) if baseline else None
        waiver_list = load_waivers(waivers) if waivers else None
    except (DocumentError, WaiverError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)

    try:
        result = run_pipeline(
            spec,
            base_url,
            baseline=snapshot_data,
            waivers=waiver_list,
            concurrency=concurrency,
            verify_tls=not insecure,
            read_only=read_only,
            max_retries=max_retries,
        )
    except (AuthError, SetupError) as exc:
        console.print(f"[bold red]setup error:[/] {exc}")
        raise typer.Exit(code=2)

    # Anchor SARIF findings to the matrix file they came from.
    result.source = matrix

    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {warning}")

    console.print(
        f"[bold]Planned[/] {len(result.cases)} tests "
        f"from {len(spec.subjects)} subjects × {len(spec.resources)} resources"
    )
    write_reports(result, out)
    _print_summary(result)
    console.print(f"Reports written to [bold]{out}/[/]")

    # An inconclusive run has no findings for the wrong reason, so its exit code
    # must not depend on --fail-on: reporting "clean" here is exactly the
    # fail-open a security gate cannot afford.
    if result.health.inconclusive:
        _print_inconclusive(result.health)
        if not allow_inconclusive:
            raise typer.Exit(code=EXIT_INCONCLUSIVE)

    raise typer.Exit(code=_exit_code(result, fail_on))


@app.command()
def snapshot(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    base: Optional[str] = typer.Option(None, help="Base URL override."),
    out: str = typer.Option("baseline.json", help="Where to write the snapshot."),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    read_only: bool = typer.Option(False, help="Skip mutating verbs (POST/PUT/PATCH/DELETE)."),
    max_retries: int = typer.Option(2, help="Retries on 429/503 with backoff."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
    allow_inconclusive: bool = typer.Option(
        False,
        help="Write the baseline even if the run never reached the target.",
    ),
):
    """Record the current authorization decisions as a drift baseline.

    Uses the same orchestration as ``run`` (transport dispatch + teardown), so
    HTTP, MCP and mixed matrices all snapshot correctly.
    """
    spec = _load(matrix, env_file)
    base_url = _resolve(spec, base)
    try:
        snap, warnings = snapshot_pipeline(
            spec,
            base_url,
            concurrency=concurrency,
            verify_tls=not insecure,
            read_only=read_only,
            max_retries=max_retries,
            allow_inconclusive=allow_inconclusive,
        )
    except InconclusiveRunError as exc:
        _print_inconclusive(exc.health)
        console.print("[bold red]baseline not written[/] — it would record a false 'all denied'")
        raise typer.Exit(code=EXIT_INCONCLUSIVE)
    except (AuthError, SetupError) as exc:
        console.print(f"[bold red]setup error:[/] {exc}")
        raise typer.Exit(code=2)
    for warning in warnings:
        console.print(f"[yellow]warning:[/] {warning}")
    save_snapshot(snap, out)
    console.print(f"Snapshot of {len(snap['decisions'])} decisions written to [bold]{out}[/]")


@app.command(name="plan")
def plan_cmd(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    negative_only: bool = typer.Option(False, help="Show only negative (expected-deny) tests."),
):
    """Print the generated test cases without sending any requests."""
    spec = _load(matrix)
    cases = plan(spec)
    table = Table(title="overstep test plan")
    for col in ("Expected", "Class", "Request", "Subject", "Variant"):
        table.add_column(col)
    for c in cases:
        if negative_only and c.expected != Effect.DENY:
            continue
        style = "red" if c.expected == Effect.DENY else "green"
        table.add_row(
            f"[{style}]{c.expected.value}[/]",
            c.resource_type.value,
            f"{c.method} {c.path}",
            f"{c.subject} ({c.role})",
            c.variant.value,
        )
    console.print(table)
    # The plan is where an unprobed resource is cheapest to fix — before the
    # run, not in the report afterwards.
    _print_unprobed(assess_coverage(spec, cases))
    _next_step(
        f"overstep run {matrix} --out out",
        "send them and report what got through",
    )


@app.command()
def validate(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    strict: bool = typer.Option(
        False, help="Treat warnings as errors (exit 1 on any problem at all)."
    ),
    live: bool = typer.Option(
        False,
        help="Also probe the target: is it reachable, and is each subject's credential accepted?",
    ),
    base: Optional[str] = typer.Option(None, help="Base URL override (with --live)."),
    insecure: bool = typer.Option(False, help="Disable TLS verification (with --live)."),
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
):
    """Check a matrix file for structural problems and unfilled placeholders."""
    spec = _load(matrix, env_file)
    problems = _diagnose(matrix, spec)
    if live:
        problems = problems + _preflight(spec, base, verify_tls=not insecure)
    errors = [p for p in problems if p.severity is Severity.ERROR]
    warnings = [p for p in problems if p.severity is Severity.WARNING]

    for problem in errors:
        console.print(f"[bold red]error:[/] {problem}")
    for problem in warnings:
        console.print(f"[yellow]warning:[/] {problem}")

    if errors:
        # No "next" here: the errors are the next step, and each already says
        # what to do about it.
        raise typer.Exit(code=1)

    if warnings:
        # Warnings describe a matrix that runs and tests less than it looks
        # like, not one that is wrong, so they do not fail the check by
        # default — --strict is there for pipelines that want them to.
        console.print(
            f"[bold yellow]ok with {len(warnings)} warning(s)[/] — "
            f"the matrix runs, but tests less than it appears to"
        )
    else:
        console.print(
            "[bold green]ok[/] — matrix is valid"
            + (" and the target accepted every subject" if live else "")
        )
    # After the verdict, not before it: the hint is what to do next, which only
    # makes sense once the reader knows where they are.
    _validate_next_step(matrix, live)
    raise typer.Exit(code=1 if (warnings and strict) else 0)


def _validate_next_step(matrix: str, live: bool) -> None:
    """Where to go once the file itself is no longer the problem.

    A matrix that lints clean is not yet a matrix that will produce anything:
    the target still has to answer and the credentials still have to work, and
    ``--live`` is the only step that knows. Once that passes, the plan is the
    last thing worth reading before requests go out.
    """
    if live:
        _next_step(f"overstep plan {matrix}", "read what will be sent before sending it")
    else:
        _next_step(
            f"overstep validate {matrix} --live",
            "check the target answers and every credential still works",
        )


@app.command(name="coverage")
def coverage_cmd(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    spec: Optional[str] = typer.Option(
        None, help="OpenAPI/HAR file, or an MCP server URL / tools.json, to compare against."
    ),
    fmt: str = typer.Option("openapi", help="Format of --spec: openapi | har | mcp."),
    only_get: bool = typer.Option(False, help="Only count GET operations from the spec."),
    token: Optional[str] = typer.Option(None, help="MCP: bearer token for fetching tools/list."),
    fail_under: Optional[float] = typer.Option(
        None,
        help="Exit 1 if either coverage percentage is below this (0-100).",
    ),
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
):
    """Report what the matrix covers: the API's operations, and its own object surface.

    Sends nothing. Both numbers bound what a clean run is allowed to claim — an
    operation the matrix never declared and an object resource it never probed
    across owners are equally absent from the findings, and equally invisible
    without this.
    """
    if fail_under is not None and not 0 <= fail_under <= 100:
        console.print("[bold red]error:[/] --fail-under must be between 0 and 100")
        raise typer.Exit(code=2)

    spec_obj = _load(matrix, env_file)
    below: list[str] = []

    if spec is not None:
        result = against_spec(spec_obj, _declared_operations(spec, fmt, only_get, token))
        _print_spec_coverage(result)
        if fail_under is not None and result.ratio * 100 < fail_under:
            below.append(f"API operations {result.ratio:.0%}")

    probe = assess_coverage(spec_obj, plan(spec_obj))
    _print_probe_coverage(probe)
    if fail_under is not None and probe.ratio * 100 < fail_under:
        below.append(f"cross-owner probes {probe.ratio:.0%}")

    if below:
        console.print(
            f"[bold red]below --fail-under {fail_under:g}%:[/] {', '.join(below)}"
        )
        raise typer.Exit(code=1)


def _declared_operations(spec: str, fmt: str, only_get: bool, token: Optional[str]):
    """Read the API's own description of itself, in whichever form it exists."""
    if fmt == "openapi":
        from overstep.loaders.openapi import load_resources
    elif fmt == "har":
        from overstep.loaders.har import load_resources
    elif fmt == "mcp":
        from overstep.loaders.mcp import fetch_tools, load_tools_from_file
        from overstep.models import McpCall, Resource

        try:
            tools = (
                fetch_tools(spec, token=token)
                if spec.startswith(("http://", "https://"))
                else load_tools_from_file(spec)
            )
        except DocumentError as exc:
            # Already names the file and what is wrong with it.
            console.print(f"[bold red]error:[/] {exc}")
            raise typer.Exit(code=2)
        except Exception as exc:  # network / protocol errors
            console.print(f"[bold red]error:[/] could not read MCP tools: {exc}")
            raise typer.Exit(code=2)
        # Only the tool name is compared, so a minimal resource is enough.
        return [
            Resource(name=t["name"], transport="mcp", call=McpCall(server="mcp", tool=t["name"]))
            for t in tools
            if t.get("name")
        ]
    else:
        console.print("[bold red]error:[/] --fmt must be 'openapi', 'har' or 'mcp'")
        raise typer.Exit(code=2)

    try:
        return load_resources(spec, only_get=only_get)
    except DocumentError as exc:
        # Already names the file and what is wrong with it.
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] could not read '{spec}': {exc}")
        raise typer.Exit(code=2)


def _print_spec_coverage(result: SpecCoverage) -> None:
    """Name the operations no run will ever mention, because none will send them."""
    table = Table(title="API surface")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Operations in the spec", str(result.operations))
    style = "" if result.complete else "yellow"
    cell = f"{result.covered}/{result.operations} ({result.ratio:.0%})"
    table.add_row("Declared in the matrix", f"[{style}]{cell}[/]" if style else cell)
    console.print(table)

    if result.missing:
        console.print(
            f"[yellow]note:[/] {len(result.missing)} operation(s) are in the spec but "
            f"not in the matrix, so no run says anything about them:"
        )
        for label in result.missing:
            console.print(f"  [yellow]•[/] {label}")
    if result.extra:
        # Not necessarily wrong — but a typo'd path looks exactly like this.
        console.print(
            f"[dim]note: {len(result.extra)} matrix resource(s) are not in the spec "
            f"(undocumented endpoint, stale spec, or a mistyped path):[/]"
        )
        for label in result.extra:
            console.print(f"  [dim]• {label}[/]")


def _print_probe_coverage(coverage: ProbeCoverage) -> None:
    table = Table(title="Object surface")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Object resources", str(coverage.object_resources))
    style = "" if coverage.complete else "yellow"
    cell = f"{coverage.probed}/{coverage.object_resources} ({coverage.ratio:.0%})"
    table.add_row("Probed across owners", f"[{style}]{cell}[/]" if style else cell)
    console.print(table)
    _print_unprobed(coverage)


@app.command()
def scaffold(
    spec_file: str = typer.Argument(..., help="OpenAPI/HAR file, or an MCP server URL / tools.json (--fmt mcp)."),
    fmt: str = typer.Option("openapi", help="Input format: openapi | har | mcp."),
    only_get: bool = typer.Option(False, help="Only include GET operations."),
    with_policy: bool = typer.Option(
        False,
        "--with-policy",
        help="OpenAPI only: emit a full matrix (roles + subjects + policy) inferred from security schemes.",
    ),
    server_name: str = typer.Option("mcp", help="MCP: name for the scaffolded server."),
    server_url: Optional[str] = typer.Option(None, help="MCP: server URL to embed (defaults to the source URL)."),
    token: Optional[str] = typer.Option(None, help="MCP: bearer token for fetching tools/list from a live server."),
):
    """Emit a starter resources block — or a full matrix — from OpenAPI, HAR or MCP."""
    from overstep.loaders.openapi import resources_to_yaml

    if fmt == "mcp":
        from overstep.loaders.mcp import (
            fetch_tools,
            load_tools_from_file,
            scaffold_matrix_from_tools,
        )

        if spec_file.startswith("http://") or spec_file.startswith("https://"):
            url = server_url or spec_file
            try:
                tools = fetch_tools(spec_file, token=token)
            except Exception as exc:  # network / protocol errors
                console.print(f"[bold red]error:[/] could not reach MCP server: {exc}")
                raise typer.Exit(code=2)
        else:
            url = server_url or "http://localhost:8000/mcp"
            try:
                tools = load_tools_from_file(spec_file)
            except DocumentError as exc:
                console.print(f"[bold red]error:[/] {exc}")
                raise typer.Exit(code=2)

        typer.echo(scaffold_matrix_from_tools(tools, server_name=server_name, server_url=url))
        _scaffold_next_step(full_matrix=True)
        return

    if with_policy:
        if fmt != "openapi":
            console.print("[bold red]error:[/] --with-policy requires --fmt openapi")
            raise typer.Exit(code=2)
        from overstep.loaders.openapi import scaffold_matrix

        # Warn on stderr as well as in the document: stdout is usually
        # redirected into a file the user may not read before running.
        def _warn(message: str) -> None:
            err_console.print(f"[yellow]warning:[/] {message}")

        try:
            document = scaffold_matrix(spec_file, only_get=only_get, warn=_warn)
        except DocumentError as exc:
            console.print(f"[bold red]error:[/] {exc}")
            raise typer.Exit(code=2)
        typer.echo(document)
        _scaffold_next_step(full_matrix=True)
        return

    if fmt == "openapi":
        from overstep.loaders.openapi import load_resources
    elif fmt == "har":
        from overstep.loaders.har import load_resources
    else:
        console.print("[bold red]error:[/] --fmt must be 'openapi', 'har' or 'mcp'")
        raise typer.Exit(code=2)

    try:
        resources = load_resources(spec_file, only_get=only_get)
    except DocumentError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)
    typer.echo(resources_to_yaml(resources))
    _scaffold_next_step(full_matrix=False)


def _scaffold_next_step(*, full_matrix: bool) -> None:
    """What to do with the document that just went to stdout.

    A bare ``resources:`` block is not a matrix and cannot be validated on its
    own, so the two outputs get different instructions — pointing at
    ``validate`` for a fragment would send the user straight into a parse error.
    """
    if not full_matrix:
        _next_step(
            "paste this under 'resources:' in your matrix",
            "it is a fragment: subjects and policy still have to be written",
        )
        return
    _next_step(
        "overstep validate <file> --strict",
        "after filling in every PASTE_.../REPLACE_ME... placeholder it left",
    )


@app.command()
def version():
    """Print the overstep version."""
    typer.echo(__version__)


def _print_summary(result: RunResult) -> None:
    s = summarize(result)
    table = Table(title="overstep summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Tests run", str(s["total_tests"]))
    table.add_row("Positive / negative", f"{s['positive_tests']} / {s['negative_tests']}")
    # One broken endpoint is reported once per identity that reaches it, so the
    # finding count answers "how many probes got through" and the defect count
    # answers "how many things do I have to fix".
    vulns, distinct = s["vulnerabilities"], s["vulnerability_defects"]
    vuln_cell = str(vulns) if vulns == distinct else f"{vulns} ({distinct} defects)"
    table.add_row("[bold red]Vulnerabilities[/]", vuln_cell)
    if s["drift"]:
        table.add_row("Authorization drift", str(s["drift"]))
    if s.get("waived"):
        table.add_row("Waived (accepted)", str(s["waived"]))
    for cls, count in sorted(s["by_class"].items()):
        table.add_row(f"  {cls}", str(count))
    _add_coverage_row(table, result.coverage)
    console.print(table)
    _print_unprobed(result.coverage)


def _add_coverage_row(table: Table, coverage: ProbeCoverage) -> None:
    """State the BOLA surface a clean result is allowed to speak for."""
    if not coverage.object_resources:
        return
    style = "" if coverage.complete else "yellow"
    cell = f"{coverage.probed}/{coverage.object_resources}"
    table.add_row(
        "Object resources probed",
        f"[{style}]{cell}[/]" if style else cell,
    )


def _print_unprobed(coverage: ProbeCoverage) -> None:
    """Name the resources a cross-owner probe was never generated for.

    Without this, a clean run over a matrix whose subjects all point at the same
    object is indistinguishable from a clean run that actually tested something.
    """
    if coverage.complete:
        return
    console.print(
        f"[yellow]note:[/] no cross-owner probe was generated for "
        f"{len(coverage.unprobed)} object resource(s), so this run says nothing "
        f"about BOLA on them:"
    )
    for name in coverage.unprobed:
        console.print(f"  [yellow]•[/] {name}")
    console.print(
        "  [dim]give at least two subjects different objects "
        "(an 'objects:' entry, or the owner attribute)[/]"
    )


def _print_inconclusive(health: RunHealth) -> None:
    """Explain why a run proved nothing, so "0 vulnerabilities" is not believed."""
    console.print(
        "[bold red]inconclusive run[/] — a clean result here would be meaningless:"
    )
    for reason in health.reasons:
        console.print(f"  [red]•[/] {reason}")
    console.print(
        f"  [dim]{health.executed} requests sent, {health.transport_errors} never delivered; "
        f"{health.positive_allowed}/{health.positive_tests} expected-allow tests were allowed[/]"
    )


def _validate_fail_on(fail_on: str) -> None:
    """Reject an unknown --fail-on value up front, before any network work."""
    if fail_on.lower() not in FAIL_ON_CHOICES:
        console.print(
            f"[bold red]error:[/] invalid --fail-on '{fail_on}' "
            f"(choose one of: {', '.join(FAIL_ON_CHOICES)})"
        )
        raise typer.Exit(code=2)


def _exit_code(result: RunResult, fail_on: str) -> int:
    """Map findings to a process exit code per the selected gate.

    * ``vuln``          — active, non-waived vulnerabilities only (default).
    * ``drift``         — authorization drift vs. the baseline only.
    * ``vuln-or-drift`` — either of the above.
    * ``any``           — any active finding (includes unexpected-deny).
    * ``never``         — always exit zero.
    """
    fail_on = fail_on.lower()
    if fail_on == "never":
        return 0
    if fail_on == "any":
        return 1 if result.findings else 0
    if fail_on == "vuln-or-drift":
        return 1 if (result.vulnerabilities or result.drift) else 0
    if fail_on == "drift":
        return 1 if result.drift else 0
    # default: "vuln"
    return 1 if result.vulnerabilities else 0


def main() -> None:
    app()


if __name__ == "__main__":
    main()
