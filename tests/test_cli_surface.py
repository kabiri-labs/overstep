"""Every command, invoked the way a user invokes it, on the path that works.

The suite covered the pipeline thoroughly and the CLI almost not at all. Every
`run` and `snapshot` invocation pointed at a dead target, `plan` and `version`
were never invoked at all, and `coverage` was only ever pointed at a server that
refuses. So the layer between a terminal and `run_pipeline` — argument parsing,
report paths, the summary table, the exit code — was exercised only where it
fails.

That is not a hypothetical gap. `overstep coverage --fmt mcp` was completely
broken against a reachable server for two releases: the comparison logic had
tests, the refusal path had tests, and nothing ran the command against a server
that answers. It shipped, and the suite stayed green.

These cases are the happy paths. Each drives the real CLI over the bundled demo
servers in process, and asserts what a user would actually notice: the exit code
their pipeline branches on, the files they open afterwards, and the numbers they
read.
"""
import importlib
import importlib.util
import json
import os

import httpx
import pytest
from typer.testing import CliRunner

from overstep.cli import EXIT_INCONCLUSIVE, app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEMOS = {
    "rest": ("examples/rest_api/matrix.yaml", "examples/rest_api/server.py",
             "overstep.modules.rest.executor"),
    "mcp": ("examples/mcp_api/matrix.yaml", "examples/mcp_api/server.py",
            "overstep.modules.mcp.transport"),
}


def _load_app(rel: str):
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location(
        "overstep_cli_demo_" + rel.replace("/", "_").replace(".", "_"),
        os.path.join(ROOT, rel),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


class _Demo:
    """The CLI, run against a demo server that is actually answering."""

    def __init__(self, name):
        self.matrix, server, self.module = DEMOS[name]
        self.matrix = os.path.join(ROOT, self.matrix)
        self._server = server

    def __enter__(self):
        app_obj = _load_app(self._server)
        self._mod = importlib.import_module(self.module)
        self._original = httpx.AsyncClient

        def factory(*args, **kwargs):
            kwargs["transport"] = httpx.ASGITransport(app=app_obj)
            return self._original(*args, **kwargs)

        self._mod.httpx.AsyncClient = factory
        return self

    def __exit__(self, *exc):
        self._mod.httpx.AsyncClient = self._original

    def invoke(self, *args):
        return CliRunner().invoke(app, [a for a in args])


@pytest.mark.parametrize("demo,tests,vulns", [("rest", "18", "8"), ("mcp", "27", "16")])
def test_run_against_a_working_target_reports_and_exits_one(demo, tests, vulns, tmp_path):
    """The command the whole tool exists for, through the CLI rather than the pipeline.

    Exit 1 is what a pipeline gates on, and the four report files are what a
    person opens next — neither was covered by a test that invoked `run`.
    """
    out = tmp_path / "out"
    with _Demo(demo) as d:
        result = d.invoke("run", d.matrix, "--out", str(out))

    assert result.exit_code == 1, result.output
    assert tests in result.output and vulns in result.output

    for name in ("findings.json", "report.html", "overstep.sarif", "junit.xml"):
        assert (out / name).exists(), f"{name} was not written"

    payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["inconclusive"] is False
    assert payload["summary"]["vulnerabilities"] == int(vulns)


def test_fail_on_never_exits_zero_on_a_run_that_did_happen(tmp_path):
    """The counterpart to the dead-target case: here the flag may be believed.

    `--fail-on never` is overridden by an inconclusive verdict, which is tested.
    That it works as documented on a *conclusive* run with real findings was not.
    """
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"),
                          "--fail-on", "never")

    assert result.exit_code == 0, result.output
    assert "Vulnerabilities" in result.output


def test_a_baseline_written_then_compared_reports_no_drift(tmp_path):
    """The two-command workflow the README puts in front of every CI user."""
    baseline = tmp_path / "baseline.json"

    with _Demo("mcp") as d:
        snapshot = d.invoke("snapshot", d.matrix, "--out", str(baseline))
    assert snapshot.exit_code == 0, snapshot.output
    assert baseline.exists()

    recorded = json.loads(baseline.read_text(encoding="utf-8"))
    assert recorded["decisions"], "a baseline with no decisions is not a baseline"

    with _Demo("mcp") as d:
        rerun = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"),
                         "--baseline", str(baseline), "--fail-on", "drift")

    # Findings are unchanged, so the drift-only gate must pass.
    assert rerun.exit_code == 0, rerun.output


def test_a_waiver_moves_a_finding_out_of_the_gate(tmp_path):
    """Accepted risk, end to end, which only the pipeline had exercised."""
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        "waivers:\n"
        "  - id: get_user::alice::other\n"
        "    vuln_class: BOLA\n"
        "    reason: 'tracked in SEC-1'\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"

    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(out), "--waivers", str(waivers))

    assert result.exit_code == 1, "the other findings still fail the build"
    payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["waived"] == 1
    assert "get_user::alice::other" not in {f["test_id"] for f in payload["findings"]}


def test_read_only_skips_the_mutating_half(tmp_path):
    """The flag people reach for before pointing this at anything they care about."""
    out = tmp_path / "out"
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(out), "--read-only")

    assert result.exit_code in (0, 1), result.output
    payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    # delete_user is the only mutating resource in the REST demo.
    assert not any(f["resource"] == "delete_user" for f in payload["findings"])


def test_plan_prints_the_cases_and_touches_nothing(tmp_path):
    """Never invoked before, despite being the command the README says to run first.

    No demo server is started here on purpose: `plan` claiming to send nothing is
    only worth anything if it holds with no target present at all.
    """
    result = CliRunner().invoke(
        app, ["plan", os.path.join(ROOT, "examples/rest_api/matrix.yaml")]
    )

    assert result.exit_code == 0, result.output
    assert "GET /users/u1" in result.output      # a positive control
    assert "GET /users/u2" in result.output      # the cross-owner probe
    assert "other" in result.output and "self" in result.output


def test_plan_reports_a_resource_it_could_not_probe(tmp_path):
    """The note that stops a missing probe reading as a clean resource."""
    matrix = tmp_path / "m.yaml"
    matrix.write_text(
        "roles: [user]\n"
        "modules: {rest: {base_url: 'http://x'}}\n"
        "subjects:\n"
        "  - {name: a, role: user, token: t, attributes: {user_id: u1}}\n"
        "  - {name: b, role: user, token: t2, attributes: {user_id: u1}}\n"
        "resources: [{name: get_user, request: {method: GET, path: '/u/{id}'},\n"
        "             type: object, owner: id}]\n"
        "policy: {get_user: {allow: [{role: user, scope: own}]}}\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["plan", str(matrix)])

    assert result.exit_code == 0
    # Both subjects resolve to u1, so no cross-owner probe exists to generate.
    assert "no cross-owner probe" in result.output


def test_version_prints_the_installed_version():
    """Trivial, and the one command a support conversation always starts with."""
    from overstep import __version__

    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_validate_passes_every_bundled_matrix():
    """The examples are the documentation; a broken one teaches a broken matrix."""
    for rel in ("examples/rest_api/matrix.yaml", "examples/mcp_api/matrix.yaml",
                "examples/mcp_api/matrix_stdio.yaml", "examples/mcp_api/matrix_setup.yaml",
                "examples/injections/matrix.yaml", "examples/crapi/matrix.yaml"):
        result = CliRunner().invoke(app, ["validate", os.path.join(ROOT, rel)])
        assert result.exit_code == 0, f"{rel}: {result.output}"


def test_an_unreadable_matrix_exits_two_not_three(tmp_path):
    """Bad input and a run that never happened are different problems.

    A pipeline branches on these, and conflating them would send somebody looking
    at their network for a typo in their YAML.
    """
    broken = tmp_path / "m.yaml"
    broken.write_text("subjects:\n- name: a\n   role: user\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["run", str(broken), "--out", str(tmp_path / "out")])

    assert result.exit_code == 2
    assert result.exit_code != EXIT_INCONCLUSIVE
