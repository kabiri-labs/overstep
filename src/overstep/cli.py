"""Command-line interface for overstep.

The CLI is intentionally thin: it parses arguments, calls into
:mod:`overstep.pipeline`, and renders results. All domain logic lives behind
``run_pipeline`` so it can be reused and tested without the terminal.

Commands:

* ``run``       — generate tests from the matrix, execute them and report.
* ``snapshot``  — record the current authorization decisions as a drift baseline.
* ``plan``      — print the generated test cases without touching the network.
* ``validate``  — check a matrix file for structural problems.
* ``scaffold``  — emit a starter resources block from an OpenAPI/HAR file.
"""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from overstep import __version__
from overstep.drift import build_snapshot, load_snapshot, save_snapshot
from overstep.executor import run as run_executor
from overstep.matrix import MatrixError, load_matrix
from overstep.models import Effect, RunResult
from overstep.pipeline import PipelineError, resolve_base_url, run_pipeline, write_reports
from overstep.planner import plan
from overstep.report import summarize

app = typer.Typer(
    help="overstep — matrix-driven authorization testing for HTTP APIs.",
    add_completion=False,
)
console = Console()


def _load(matrix_path: str):
    try:
        return load_matrix(matrix_path)
    except MatrixError as exc:
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
    fail_on: str = typer.Option("vuln", help="Exit non-zero on: vuln | drift | any | never."),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
):
    """Run the matrix against a live target and write reports."""
    spec = _load(matrix)
    for problem in spec.validate_refs():
        console.print(f"[yellow]warning:[/] {problem}")

    base_url = _resolve(spec, base)
    snapshot_data = load_snapshot(baseline) if baseline else None

    result = run_pipeline(
        spec,
        base_url,
        baseline=snapshot_data,
        concurrency=concurrency,
        verify_tls=not insecure,
    )

    console.print(
        f"[bold]Planned[/] {len(result.cases)} tests "
        f"from {len(spec.subjects)} subjects × {len(spec.resources)} resources"
    )
    write_reports(result, out)
    _print_summary(result)
    console.print(f"Reports written to [bold]{out}/[/]")

    raise typer.Exit(code=_exit_code(result, fail_on))


@app.command()
def snapshot(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    base: Optional[str] = typer.Option(None, help="Base URL override."),
    out: str = typer.Option("baseline.json", help="Where to write the snapshot."),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
):
    """Record the current authorization decisions as a drift baseline."""
    spec = _load(matrix)
    base_url = _resolve(spec, base)
    cases = plan(spec)
    observations = run_executor(
        base_url, spec.subjects, cases, concurrency=concurrency, verify_tls=not insecure
    )
    save_snapshot(build_snapshot(cases, observations), out)
    console.print(f"Snapshot of {len(cases)} decisions written to [bold]{out}[/]")


@app.command(name="plan")
def plan_cmd(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    negative_only: bool = typer.Option(False, help="Show only negative (expected-deny) tests."),
):
    """Print the generated test cases without sending any requests."""
    spec = _load(matrix)
    table = Table(title="overstep test plan")
    for col in ("Expected", "Class", "Request", "Subject", "Variant"):
        table.add_column(col)
    for c in plan(spec):
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


@app.command()
def validate(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
):
    """Check a matrix file for structural problems."""
    spec = _load(matrix)
    problems = spec.validate_refs()
    if not problems:
        console.print("[bold green]ok[/] — matrix is valid")
        raise typer.Exit(code=0)
    for p in problems:
        console.print(f"[red]•[/] {p}")
    raise typer.Exit(code=1)


@app.command()
def scaffold(
    spec_file: str = typer.Argument(..., help="OpenAPI YAML or HAR file."),
    fmt: str = typer.Option("openapi", help="Input format: openapi | har."),
    only_get: bool = typer.Option(False, help="Only include GET operations."),
):
    """Emit a starter resources block from an OpenAPI or HAR file."""
    from overstep.loaders.openapi import resources_to_yaml

    if fmt == "openapi":
        from overstep.loaders.openapi import load_resources
    elif fmt == "har":
        from overstep.loaders.har import load_resources
    else:
        console.print("[bold red]error:[/] --fmt must be 'openapi' or 'har'")
        raise typer.Exit(code=2)

    typer.echo(resources_to_yaml(load_resources(spec_file, only_get=only_get)))


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
    table.add_row("[bold red]Vulnerabilities[/]", str(s["vulnerabilities"]))
    if s["drift"]:
        table.add_row("Authorization drift", str(s["drift"]))
    for cls, count in sorted(s["by_class"].items()):
        table.add_row(f"  {cls}", str(count))
    console.print(table)


def _exit_code(result: RunResult, fail_on: str) -> int:
    fail_on = fail_on.lower()
    if fail_on == "never":
        return 0
    if fail_on == "any":
        return 1 if result.findings else 0
    if fail_on == "drift":
        return 1 if (result.vulnerabilities or result.drift) else 0
    # default: "vuln"
    return 1 if result.vulnerabilities else 0


def main() -> None:
    app()


if __name__ == "__main__":
    main()
