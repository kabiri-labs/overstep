"""What `run` prints is enough to act on without opening a report.

In a CI log or over SSH the terminal is all a person sees. It used to show
counts - "Vulnerabilities 8 (3 defects)" - and leave which endpoint and which
subject to a file on another machine.
"""
import os

import pytest
from typer.testing import CliRunner

import overstep.cli as cli
from overstep.cli import FINDING_ROWS, app
from overstep.models import Effect, Finding, Observation, RunResult, Variant, VulnClass
from test_cli_surface import _Demo


def _finding(index: int, vuln_class: VulnClass, **overrides) -> Finding:
    fields = dict(
        test_id=f"res{index}::alice::other",
        vuln_class=vuln_class,
        severity="high",
        resource=f"res{index}",
        subject="alice",
        role="user",
        method="GET",
        path=f"/things/{index}",
        expected=Effect.DENY,
        observed=Effect.ALLOW,
        status=200,
        variant=Variant.OTHER,
        detail="d",
        evidence=Observation(test_id="t", status=200, effect=Effect.ALLOW),
    )
    fields.update(overrides)
    return Finding(**fields)


def _printed(result: RunResult, monkeypatch, width: int = 80) -> str:
    """What `_print_findings` writes to a terminal of the given width."""
    from rich.console import Console

    console = Console(width=width, record=True, force_terminal=False)
    monkeypatch.setattr(cli, "console", console)
    cli._print_findings(result)
    return console.export_text()


# --- against the bundled demo -----------------------------------------------


def test_the_rest_demo_names_its_three_defects_in_the_terminal(tmp_path):
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"))

    lines = [l.strip() for l in result.output.splitlines()]
    start = lines.index("Defects (3) — one line per thing to fix:")
    defects = lines[start + 1:start + 4]

    assert all(l.split()[0] in {"BOLA", "privilege-escalation"} for l in defects)
    # Method and path, not the resource's name in the matrix.
    assert any("GET /users/{id}" in l for l in defects)
    assert any("alice" in l and "bob" in l for l in defects), "subjects show blast radius"
    assert all("(high, " in l for l in defects)
    # Printed after the summary a reader has just been given the counts by.
    assert result.output.index("overstep summary") < result.output.index("Defects (3)")


def test_a_clean_run_prints_no_findings_section(tmp_path):
    secure = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "examples", "secure_api")
    d = _Demo("rest")
    d.matrix = os.path.join(secure, "matrix.yaml")
    d._server = "examples/secure_api/server.py"
    with d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"))

    assert result.exit_code == 0, result.output
    assert "Defects" not in result.output
    assert "Unexpected denials" not in result.output


# --- the list itself --------------------------------------------------------


def test_the_list_is_capped_and_says_how_many_it_left_out(monkeypatch):
    findings = [_finding(i, VulnClass.BOLA) for i in range(FINDING_ROWS + 7)]
    text = _printed(RunResult(base_url="http://t", findings=findings), monkeypatch)

    assert f"Defects ({FINDING_ROWS + 7})" in text
    assert text.count("BOLA  GET /things/") == FINDING_ROWS
    assert "+7 more in report.html" in text


def test_exactly_the_cap_mentions_nothing_hidden(monkeypatch):
    findings = [_finding(i, VulnClass.BOLA) for i in range(FINDING_ROWS)]
    text = _printed(RunResult(base_url="http://t", findings=findings), monkeypatch)

    assert "more in report.html" not in text


def test_unexpected_denials_are_listed_apart_from_defects(monkeypatch):
    findings = [
        _finding(1, VulnClass.BOLA),
        _finding(
            2, VulnClass.UNEXPECTED_DENY, test_id="patch_order::root::self",
            method="PATCH", path="/orders/o-r", status=404,
            expected=Effect.ALLOW, observed=Effect.DENY, severity="low",
        ),
    ]
    text = _printed(RunResult(base_url="http://t", findings=findings), monkeypatch)

    assert "Defects (1)" in text, "a denial is not a defect and must not be counted as one"
    assert "Unexpected denials (1)" in text
    assert text.index("Defects (1)") < text.index("Unexpected denials (1)")
    assert "patch_order::root::self  PATCH /orders/o-r  (HTTP 404)" in text
    assert "usually the matrix is what is wrong" in text


def test_a_long_line_is_not_broken_inside_its_path(monkeypatch):
    path = "/api/v1/tenants/acme/projects/alpha/environments/production/orders/1234567890"
    result = RunResult(
        base_url="http://t",
        findings=[_finding(1, VulnClass.BOLA, path=path, subject="alice")],
    )
    text = _printed(result, monkeypatch, width=40)

    assert path in text


def test_a_path_that_looks_like_markup_is_printed_as_written(monkeypatch):
    result = RunResult(
        base_url="http://t", findings=[_finding(1, VulnClass.BOLA, path="/items[red]/x[/]")]
    )

    assert "/items[red]/x[/]" in _printed(result, monkeypatch)


# --- the two small ones ------------------------------------------------------


def test_the_report_path_is_printed_on_one_line(tmp_path):
    """A path broken across two lines is a path nobody can copy.

    rich wraps at the terminal width, which lands mid-path. The Artifacts
    section prints it `soft_wrap`ped for that reason, and this is what holds it
    there however long the directory name gets.
    """
    out = tmp_path / ("a-long-directory-name-" * 6) / "out"
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(out))

    assert f"{out}/" in result.output
    path_lines = [line for line in result.output.splitlines() if f"{out}/" in line]
    assert len(path_lines) == 1, path_lines


def _summary_row(output: str, label: str):
    for line in output.splitlines():
        cells = [c.strip() for c in line.strip("│┃| ").replace("┃", "│").split("│")]
        if cells and cells[0] == label:
            return cells[-1]
    return None


def test_read_only_shows_what_was_sent_apart_from_what_was_planned(tmp_path):
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"), "--read-only")

    sent = int(_summary_row(result.output, "Tests run"))
    planned = int(_summary_row(result.output, "Planned"))
    skipped = int(_summary_row(result.output, "Skipped (--read-only)"))

    assert planned == 18, "the demo plans 18 cases with or without the flag"
    assert skipped > 0
    assert sent == planned - skipped


def test_a_full_run_has_no_planned_row_to_disagree_with(tmp_path):
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"))

    assert _summary_row(result.output, "Tests run") == "18"
    assert _summary_row(result.output, "Planned") is None
