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

import os
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from overstep import __version__
from overstep.auth import AuthError, authenticate
from overstep.drift import build_snapshot, load_snapshot, save_snapshot
from overstep.executor import run as run_executor
from overstep.fixtures import SetupError, run_setup
from overstep.matrix import MatrixError, load_matrix
from overstep.models import Effect, RunResult
from overstep.pipeline import PipelineError, resolve_base_url, run_pipeline, write_reports
from overstep.planner import plan
from overstep.report import summarize
from overstep.waivers import WaiverError, load_waivers

app = typer.Typer(
    help="overstep — matrix-driven authorization testing for HTTP APIs.",
    add_completion=False,
)
console = Console()


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
    fail_on: str = typer.Option("vuln", help="Exit non-zero on: vuln | drift | any | never."),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    read_only: bool = typer.Option(False, help="Skip mutating verbs (POST/PUT/PATCH/DELETE)."),
    max_retries: int = typer.Option(2, help="Retries on 429/503 with backoff."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
):
    """Run the matrix against a live target and write reports."""
    spec = _load(matrix, env_file)
    for problem in spec.validate_refs():
        console.print(f"[yellow]warning:[/] {problem}")

    base_url = _resolve(spec, base)
    snapshot_data = load_snapshot(baseline) if baseline else None
    try:
        waiver_list = load_waivers(waivers) if waivers else None
    except WaiverError as exc:
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

    for warning in result.warnings:
        console.print(f"[yellow]warning:[/] {warning}")

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
    env_file: Optional[str] = typer.Option(None, help="dotenv file with ${VAR} values."),
):
    """Record the current authorization decisions as a drift baseline."""
    spec = _load(matrix, env_file)
    base_url = _resolve(spec, base)
    try:
        authenticate(spec, base_url=base_url, verify_tls=not insecure)
        context = run_setup(spec, base_url=base_url, verify_tls=not insecure)
    except (AuthError, SetupError) as exc:
        console.print(f"[bold red]setup error:[/] {exc}")
        raise typer.Exit(code=2)
    cases = plan(spec, context)
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
    if s.get("waived"):
        table.add_row("Waived (accepted)", str(s["waived"]))
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
