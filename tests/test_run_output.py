"""The shape of what a run prints, held to a contract.

Most of this output is read by somebody scrolling a CI log days after the run,
with one of five questions: what ran, what the matrix complained about, what was
found, whether the run is worth believing, and where the documents went. It used
to answer them in no particular order — warnings came out before anything that
gave them context, the report path sat between the findings and the verdict on
whether the findings meant anything — and it never said which version or which
settings had produced any of it, so a pasted log could not be reproduced and a
full run could not be told from one narrowed to a single resource.

So the sections, their order, and the facts the configuration block has to carry
are asserted rather than eyeballed. The individual numbers are pinned by
`test_terminal_findings.py`; this is about the frame around them.
"""
import os
import re

import pytest

from test_terminal_findings import _Demo

SECTIONS = ("Configuration", "Warnings", "Results", "Health", "Artifacts")


@pytest.fixture(scope="module")
def mcp_run(tmp_path_factory):
    """One run of the bundled MCP demo, shared by every assertion here."""
    out = tmp_path_factory.mktemp("out")
    with _Demo("mcp") as demo:
        return demo.invoke("run", demo.matrix, "--out", str(out)).output


def test_the_banner_names_the_version_that_produced_the_output(mcp_run):
    """The one thing a banner owes the reader of a pasted log."""
    from overstep import __version__

    first = mcp_run.splitlines()[0]

    assert first.strip() == f"overstep {__version__}"


def test_every_section_appears_exactly_once_and_in_order(mcp_run):
    positions = []
    for name in SECTIONS:
        found = [
            i for i, line in enumerate(mcp_run.splitlines())
            if line.startswith(name + " ")
        ]
        assert len(found) == 1, f"{name!r} appears {len(found)} times"
        positions.append(found[0])

    assert positions == sorted(positions), dict(zip(SECTIONS, positions))


def _config(output: str) -> dict:
    """The Configuration block as the key/value pairs a reader would grep."""
    lines = output.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Configuration "))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("Warnings "))
    pairs = {}
    for line in lines[start + 1:end]:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            pairs[parts[0]] = parts[1].strip()
    return pairs


def test_the_configuration_block_says_what_was_tested(mcp_run):
    """Enough to reproduce the run, or to know you cannot."""
    config = _config(mcp_run)

    assert config["matrix"].endswith("matrix.yaml")
    assert "127.0.0.1:9000/mcp" in config["targets"]
    assert config["overstep"]
    assert config["started"]


def test_the_configuration_block_says_what_could_change_the_numbers(mcp_run):
    """A setting that cannot change the result does not earn a line.

    These can: the gate, the pacing, and which optional probes were on — the
    last being the commonest reason a run finds less than its reader expected.
    """
    config = _config(mcp_run)

    assert config["fail-on"] == "vuln"
    assert config["concurrency"] == "10"
    assert config["timeout"] == "15s"
    assert "session-binding" in config["probes"]
    assert "metadata-identity" in config["probes"]
    # Off by default, and therefore absent rather than listed as off.
    assert "open-registration" not in config["probes"]


def test_the_run_metadata_matches_what_the_documents_record(tmp_path):
    """One source for it, so the terminal and findings.json cannot disagree.

    They did not disagree because nobody compared them: the terminal printed
    none of this. The configuration block reads `report.run_info`, which is what
    the documents open with, and this is what keeps it reading from there.
    """
    import json

    out = tmp_path / "out"
    with _Demo("mcp") as demo:
        output = demo.invoke("run", demo.matrix, "--out", str(out)).output

    config = _config(output)
    recorded = json.loads((out / "findings.json").read_text(encoding="utf-8"))["run"]

    assert config["overstep"] == recorded["overstep_version"]
    assert config["started"] == recorded["started_at"]
    assert config["targets"] == ", ".join(recorded["targets"])


def test_a_read_only_run_says_so_in_the_configuration(tmp_path):
    """The setting that most changes what a clean result is worth."""
    out = tmp_path / "out"
    with _Demo("mcp") as demo:
        output = demo.invoke(
            "run", demo.matrix, "--out", str(out), "--read-only"
        ).output

    assert "mutating operations were not sent" in _config(output)["read-only"]


def test_a_narrowed_run_names_what_it_was_narrowed_to(tmp_path):
    out = tmp_path / "out"
    with _Demo("mcp") as demo:
        output = demo.invoke(
            "run", demo.matrix, "--out", str(out), "--subject", "alice"
        ).output

    assert "subjects alice" in _config(output)["partial"]


def test_a_clean_warnings_section_says_none_rather_than_nothing(mcp_run):
    """An empty space under a heading reads as output that got cut off."""
    lines = mcp_run.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Warnings "))

    assert lines[start + 1].strip() == "none"


def test_the_health_section_reports_a_conclusive_run_too(mcp_run):
    """The counts behind the verdict used to print only when it went badly.

    Which left the reader of a clean run without the one thing they most need
    to check — did the requests arrive, were the credentials accepted — anywhere
    in the output. A clean result that cannot be audited is not worth trusting.
    """
    lines = mcp_run.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Health "))
    body = " ".join(l.strip() for l in lines[start + 1:start + 4])

    assert "conclusive" in body
    assert re.search(r"\d+ requests sent", body), body
    assert re.search(r"\d+/\d+ expected-allow tests were allowed", body), body


def test_the_output_carries_no_escape_codes_when_colour_is_off(tmp_path, monkeypatch):
    """A log file is the normal destination for this, not a terminal.

    rich turns colour off for `NO_COLOR` on its own; what this pins is that
    nothing here is drawn *only* in colour — strip the styling and every section
    heading and every value is still there to be read and grepped.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    out = tmp_path / "out"
    with _Demo("mcp") as demo:
        output = demo.invoke("run", demo.matrix, "--out", str(out)).output

    assert "\x1b[" not in output
    for name in SECTIONS:
        assert any(line.startswith(name + " ") for line in output.splitlines()), name
    assert "Defects (" in output


def test_nothing_in_the_output_has_trailing_whitespace(mcp_run):
    """Trailing spaces are noise in every diff the log ever appears in.

    The summary table was padded to the terminal width when it was first
    indented, which gave every one of its rows a tail of spaces.
    """
    offenders = [
        line for line in mcp_run.splitlines()
        # The table's centred title is rich's own rendering and is left alone.
        if line != line.rstrip() and "overstep summary" not in line
    ]

    assert offenders == [], offenders


# --- what the review of this change turned up --------------------------------


def test_a_proxy_credential_is_not_printed(tmp_path):
    """`http://user:password@proxy:8080` is a legal proxy URL and httpx takes one.

    The configuration block exists to be copied into tickets and it lands in
    retained CI logs, so a password in it is a password published. Nothing could
    have caught this by matching known secrets either: the value arrived inside
    a URL, so the run was never told it was a credential.
    """
    out = tmp_path / "out"
    with _Demo("rest") as demo:
        output = demo.invoke(
            "run", demo.matrix, "--out", str(out),
            "--proxy", "http://ci-user:sup3rs3cret@proxy.internal:8080",
        ).output

    assert "sup3rs3cret" not in output
    assert "ci-user" not in output
    # The host survives: which proxy was in the way is what a reader needs.
    assert "proxy.internal:8080" in _config(output)["proxy"]


def test_a_credential_in_a_target_url_is_not_printed(tmp_path):
    """The same hole one field over, and the same reason nothing caught it."""
    out = tmp_path / "out"
    with _Demo("rest") as demo:
        output = demo.invoke(
            "run", demo.matrix, "--out", str(out),
            "--base", "http://u:p4ssw0rd@127.0.0.1:8000",
        ).output

    assert "p4ssw0rd" not in output
    assert "127.0.0.1:8000" in _config(output)["targets"]
