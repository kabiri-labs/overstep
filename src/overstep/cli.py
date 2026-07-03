"""Command-line interface for overstep.

Commands:

* ``run``       — generate tests from the matrix, execute them and report.
* ``snapshot``  — record the current authorization decisions as a drift baseline.
* ``plan``      — print the generated test cases without touching the network.
* ``validate``  — check a matrix file for structural problems.
* ``scaffold``  — emit a starter resources block from an OpenAPI/HAR file.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from overstep import __version__
from overstep.classifier import classify
from overstep.drift import build_snapshot, diff, load_snapshot, save_snapshot
from overstep.executor import run as run_engine
from overstep.matrix import MatrixError, load_matrix
from overstep.models import Effect, VulnClass
from overstep.planner import plan
from overstep.report import summarize
from overstep.report import html_report, json_report, junit, sarif

app = typer.Typer(
    help="overstep — matrix-driven authorization testing for HTTP APIs.",
    add_completion=False,
)
console = Console()

# Which finding classes count as a real security failure for exit codes.
_VULN_CLASSES = {
    VulnClass.BOLA,
    VulnClass.BFLA,
    VulnClass.PRIVILEGE_ESCALATION,
}


def _load(matrix_path: str):
    try:
        return load_matrix(matrix_path)
    except MatrixError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=2)


def _resolve_base(matrix, override: Optional[str]) -> str:
    base = override or matrix.base_url
    if not base:
        console.print("[bold red]error:[/] no base URL given (set matrix.base_url or pass --base)")
        raise typer.Exit(code=2)
    return base


@app.command()
def run(
    matrix: str = typer.Argument(..., help="Path to the authorization matrix YAML."),
    base: Optional[str] = typer.Option(None, help="Base URL override."),
    out: str = typer.Option("out", help="Output directory for reports."),
    baseline: Optional[str] = typer.Option(None, help="Snapshot to compare against for drift."),
    fail_on: str = typer.Option(
        "vuln",
        help="Exit non-zero on: vuln | drift | any | never.",
    ),
    concurrency: int = typer.Option(10, help="Max concurrent requests."),
    insecure: bool = typer.Option(False, help="Disable TLS verification."),
):
    """Run the matrix against a live target and write reports."""
    spec = _load(matrix)
    problems = spec.validate_refs()
    if problems:
        for p in problems:
            console.print(f"[yellow]warning:[/] {p}")

    base_url = _resolve_base(spec, base)
    cases = plan(spec)
    console.print(
        f"[bold]Planned[/] {len(cases)} tests "
        f"from {len(spec.subjects)} subjects × {len(spec.resources)} resources"
    )

    observations = run_engine(
        base_url, spec.subjects, cases, concurrency=concurrency, verify_tls=not insecure
    )
    findings = classify(spec, cases, observations)

    drift_findings = []
    if baseline:
        drift_findings = diff(load_snapshot(baseline), cases, observations)
        findings = findings + drift_findings

    os.makedirs(out, exist_ok=True)
    json_report.write(cases, findings, os.path.join(out, "findings.json"))
    html_report.write(cases, findings, os.path.join(out, "report.html"))
    sarif.write(findings, os.path.join(out, "overstep.sarif"))
    junit.write(cases, findings, os.path.join(out, "junit.xml"))

    _print_summary(cases, findings)
    console.print(f"Reports written to [bold]{out}/[/]")

    code = _exit_code(findings, fail_on)
    raise typer.Exit(code=code)


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
    base_url = _resolve_base(spec, base)
    cases = plan(spec)
    observations = run_engine(
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
    cases = plan(spec)

    table = Table(title="overstep test plan", show_lines=False)
    table.add_column("Expected")
    table.add_column("Class")
    table.add_column("Request")
    table.add_column("Subject")
    table.add_column("Variant")
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
    if fmt == "openapi":
        from overstep.loaders.openapi import load_resources, resources_to_yaml

        resources = load_resources(spec_file, only_get=only_get)
        typer.echo(resources_to_yaml(resources))
    elif fmt == "har":
        from overstep.loaders.har import load_resources
        from overstep.loaders.openapi import resources_to_yaml

        resources = load_resources(spec_file, only_get=only_get)
        typer.echo(resources_to_yaml(resources))
    else:
        console.print("[bold red]error:[/] --fmt must be 'openapi' or 'har'")
        raise typer.Exit(code=2)


@app.command()
def version():
    """Print the overstep version."""
    typer.echo(__version__)


def _print_summary(cases, findings) -> None:
    s = summarize(cases, findings)
    table = Table(title="overstep summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Tests run", str(s["total_tests"]))
    table.add_row("Positive / negative", f"{s['positive_tests']} / {s['negative_tests']}")
    table.add_row("[bold red]Vulnerabilities[/]", str(s["vulnerabilities"]))
    for cls, count in sorted(s["by_class"].items()):
        table.add_row(f"  {cls}", str(count))
    console.print(table)


def _exit_code(findings, fail_on: str) -> int:
    fail_on = fail_on.lower()
    if fail_on == "never":
        return 0

    has_vuln = any(f.vuln_class in _VULN_CLASSES for f in findings)
    has_drift = any(f.vuln_class == VulnClass.AUTHORIZATION_DRIFT for f in findings)

    if fail_on == "any" and findings:
        return 1
    if fail_on == "drift" and (has_vuln or has_drift):
        return 1
    if fail_on == "vuln" and has_vuln:
        return 1
    return 0


def main() -> None:
    app()


if __name__ == "__main__":
    main()
