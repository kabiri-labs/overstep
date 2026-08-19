"""The serialized surface of a run, pinned byte for byte against golden files.

Three things overstep produces are consumed by something other than a human, and
therefore cannot change without breaking it:

* ``test_id`` — the key a drift baseline and a waivers file are written against.
  Change its shape and every committed ``baseline.json`` reports the whole
  surface as drift, and every waiver stops matching the finding it excused.
* the ``vuln_class`` wire values — the string a waiver narrows on, the id a SARIF
  rule carries, and the label a dashboard groups by.
* the report documents themselves — ``findings.json``, ``overstep.sarif``,
  ``junit.xml``, ``report.html`` and a snapshot's ``baseline.json``.

None of that is protected by the rest of the suite, which tests behaviour through
Python objects and would stay green while the serialized form moved underneath
it. So this module runs both bundled demos end to end and compares every artifact
against a stored copy.

**These files are change detectors, not a freeze.** The reorganisation ahead of
1.0.0 will change some of them deliberately. When it does, regenerate with
``OVERSTEP_UPDATE_GOLDEN=1 pytest tests/test_wire_contract.py`` and review the
diff — that diff *is* the record of what a release breaks, which is exactly what
a pre-1.0 project cutting a stable version needs to be able to state precisely.
Regenerating without reading the diff defeats the entire module.

Both demos are driven in-process over ASGI, so this needs no port and no
subprocess, and the artifacts are deterministic apart from the three volatile
values normalized below.
"""
import importlib.util
import json
import os
import re

import httpx
import pytest

from overstep import __version__
from overstep.drift import build_snapshot, diff, save_snapshot
from overstep.matrix import load_matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline, write_reports
from overstep.waivers import Waiver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")

UPDATE = bool(os.environ.get("OVERSTEP_UPDATE_GOLDEN"))

# Every artifact a run writes, plus the snapshot `overstep snapshot` writes.
ARTIFACTS = ("findings.json", "overstep.sarif", "junit.xml", "report.html", "baseline.json")

# Measured, not assumed: two consecutive runs of both demos differ in exactly
# these. `latency_ms` and `generated_at` are wall-clock; the package version
# appears in a snapshot's header and in the SARIF tool block, and would otherwise
# make every version bump look like a broken contract.
VOLATILE_KEYS = ("latency_ms", "generated_at")

# The two demos. Each is a matrix, the server module backing it, and the
# transport module whose httpx client has to be pointed at the ASGI app.
DEMOS = {
    "rest": {
        "matrix": "examples/mock_api/matrix.yaml",
        "server": "examples/mock_api/server.py",
        "module": "overstep.modules.rest.executor",
    },
    "mcp": {
        "matrix": "examples/mcp_api/matrix.yaml",
        "server": "examples/mcp_api/server.py",
        "module": "overstep.modules.mcp.transport",
    },
}


def _load_app(rel: str):
    """Import a demo server module by path; `examples/` is not a package."""
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location(
        "overstep_wire_demo_" + re.sub(r"\W", "_", rel), os.path.join(ROOT, rel)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def _run_demo(name: str):
    """Run one demo against its own server, in process.

    A fresh server module per call: the demos mutate their own state, and a
    second run against a first run's leftovers is not the run the golden files
    describe.
    """
    demo = DEMOS[name]
    app = _load_app(demo["server"])
    transport_module = importlib.import_module(demo["module"])

    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.ASGITransport(app=app)
        return original(*args, **kwargs)

    transport_module.httpx.AsyncClient = factory
    try:
        return run_pipeline(load_matrix(os.path.join(ROOT, demo["matrix"])))
    finally:
        transport_module.httpx.AsyncClient = original


@pytest.fixture(scope="module")
def results():
    """Both demos, run once for the whole module."""
    return {name: _run_demo(name) for name in DEMOS}


def _scrub(value):
    """Replace wall-clock values in a parsed document, keeping the key present.

    Deleting the keys instead would let a reporter drop `latency_ms` entirely
    without any test noticing — the shape is part of the contract even where the
    value cannot be.
    """
    if isinstance(value, dict):
        return {
            key: "<VOLATILE>" if key in VOLATILE_KEYS else _scrub(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _normalize(text: str) -> str:
    """A document reduced to what must not change between two builds.

    The package version is replaced textually rather than by key, because SARIF
    carries two `version` fields — its own schema version, which is a real part
    of the contract, and the tool version, which is not.
    """
    text = text.replace(__version__, "<VERSION>")
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return json.dumps(_scrub(json.loads(text)), indent=2, ensure_ascii=False) + "\n"
    return text


def _artifacts(result, tmp_path) -> dict:
    """Every document one run produces, normalized and keyed by filename."""
    outdir = str(tmp_path)
    write_reports(result, outdir)
    save_snapshot(
        build_snapshot(result.cases, result.observations),
        os.path.join(outdir, "baseline.json"),
    )
    documents = {}
    for name in ARTIFACTS:
        with open(os.path.join(outdir, name), "r", encoding="utf-8") as handle:
            documents[name] = _normalize(handle.read())
    return documents


@pytest.mark.parametrize("demo", sorted(DEMOS))
@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_artifact_matches_golden(demo, artifact, results, tmp_path):
    """One stored document per demo per reporter, compared in full.

    Parametrized per file rather than asserted as one blob so a failure names the
    document that moved instead of reporting "the reports changed".
    """
    produced = _artifacts(results[demo], tmp_path)[artifact]
    path = os.path.join(GOLDEN, demo, artifact)

    if UPDATE:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(produced)
        pytest.skip(f"regenerated {demo}/{artifact}")

    assert os.path.exists(path), (
        f"no golden file for {demo}/{artifact} — regenerate with "
        f"OVERSTEP_UPDATE_GOLDEN=1"
    )
    with open(path, "r", encoding="utf-8") as handle:
        expected = handle.read()

    assert produced == expected, (
        f"{demo}/{artifact} differs from its golden copy. If the change is "
        f"intended, regenerate with OVERSTEP_UPDATE_GOLDEN=1 and review the diff "
        f"— it is what this release breaks for anyone consuming that document."
    )


def test_every_golden_file_is_tracked_by_git():
    """A golden file that exists locally but is not committed is worse than none.

    `.gitignore` carries `*.sarif` so a user's run output stays out of the
    repository, and it silently swallowed both SARIF copies the first time they
    were generated: the suite passed on the machine that wrote them and would
    have failed on a fresh clone. The comparison above cannot see this — the file
    is right there — so the check has to ask git rather than the filesystem.
    """
    import subprocess

    on_disk = {
        os.path.relpath(os.path.join(root, name), ROOT).replace(os.sep, "/")
        for root, _, names in os.walk(GOLDEN)
        for name in names
    }
    assert on_disk, "no golden files on disk"

    listed = subprocess.run(
        ["git", "ls-files", "tests/golden"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()

    assert not on_disk - set(listed), (
        f"golden files not tracked by git: {sorted(on_disk - set(listed))} — "
        f"check .gitignore"
    )


def test_the_artifacts_are_deterministic_once_normalized(results, tmp_path):
    """The normalization has to actually cover everything that moves.

    Without this, a newly volatile field would not fail the comparison above with
    a useful message — it would fail intermittently, on whichever run happened to
    straddle a clock tick, and get dismissed as flake.
    """
    first = _artifacts(results["mcp"], tmp_path / "one")
    second = _artifacts(_run_demo("mcp"), tmp_path / "two")

    for artifact in ARTIFACTS:
        assert first[artifact] == second[artifact], (
            f"{artifact} differs between two runs of the same build: something "
            f"volatile is not covered by VOLATILE_KEYS"
        )


# Every id the two demos generate. Written out in full rather than derived,
# because a derivation would reproduce whatever bug changed them.
REST_TEST_IDS = {
    "admin_list_users::alice::na",
    "admin_list_users::anon::na",
    "admin_list_users::bob::na",
    "admin_list_users::root::na",
    "delete_user::alice::other",
    "delete_user::alice::self",
    "delete_user::anon::other",
    "delete_user::bob::other",
    "delete_user::bob::self",
    "delete_user::root::other",
    "delete_user::root::self",
    "get_user::alice::other",
    "get_user::alice::self",
    "get_user::anon::other",
    "get_user::bob::other",
    "get_user::bob::self",
    "get_user::root::other",
    "get_user::root::self",
}

MCP_TEST_IDS = {
    "list_all_users::alice::na",
    "list_all_users::anon::na",
    "list_all_users::bob::na",
    "list_all_users::root::na",
    "mcp:docs::alice::enumerate",
    "mcp:docs::alice::session",
    "mcp:docs::anon::enumerate",
    "mcp:docs::bob::enumerate",
    "mcp:docs::bob::session",
    "mcp:docs::root::enumerate",
    "mcp:docs::root::session",
    "read_doc_resource::alice::other",
    "read_doc_resource::alice::self",
    "read_doc_resource::anon::other",
    "read_doc_resource::bob::other",
    "read_doc_resource::bob::self",
    "read_doc_resource::root::other",
    "read_document::alice::other",
    "read_document::alice::self",
    "read_document::anon::other",
    "read_document::bob::other",
    "read_document::bob::self",
    "read_document::root::other",
    "reset_tenant::alice::na",
    "reset_tenant::anon::na",
    "reset_tenant::bob::na",
    "reset_tenant::root::na",
}


@pytest.mark.parametrize(
    "demo,expected", [("rest", REST_TEST_IDS), ("mcp", MCP_TEST_IDS)]
)
def test_test_ids_are_exactly_these(demo, expected, results):
    """The key a baseline and a waivers file are written against.

    An id that changes shape is not a cosmetic edit: every `baseline.json` in
    somebody's repository is keyed on the old one, so the next run finds nothing
    to compare and reports the entire surface as newly added.
    """
    produced = {case.id for case in results[demo].cases}

    assert produced == expected, (
        f"test ids changed: added {sorted(produced - expected)}, "
        f"removed {sorted(expected - produced)}"
    )


# The enum member is a Python name and may be renamed freely. The value is what
# lands in findings.json, in a SARIF rule id and in a waiver's `vuln_class`.
VULN_CLASS_WIRE_VALUES = {
    "BOLA": "BOLA",
    "BFLA": "BFLA",
    "BOPLA": "BOPLA",
    "PRIVILEGE_ESCALATION": "privilege-escalation",
    "TOKEN_AUDIENCE": "token-audience",
    "SESSION_HIJACK": "session-hijack",
    "TOOL_ENUMERATION": "tool-enumeration",
    "AUTHORIZATION_DRIFT": "authorization-drift",
    "UNEXPECTED_DENY": "unexpected-deny",
}

# The `variant` segment of every test id, so this table and the ids above move
# together or not at all.
VARIANT_WIRE_VALUES = {
    "SELF": "self",
    "OTHER": "other",
    "NA": "na",
    "AUDIENCE": "audience",
    "SESSION": "session",
    "ENUMERATE": "enumerate",
}


def test_vuln_class_wire_values_are_unchanged():
    """Renaming the member is free; renaming the value breaks waivers and SARIF."""
    produced = {member.name: member.value for member in VulnClass}

    assert produced == VULN_CLASS_WIRE_VALUES, (
        "a VulnClass wire value changed — this silently voids every waiver "
        "narrowed by class and every SARIF suppression keyed on the rule id"
    )


def test_variant_wire_values_are_unchanged():
    """These are the third segment of every test id."""
    produced = {member.name: member.value for member in Variant}

    assert produced == VARIANT_WIRE_VALUES, "a Variant wire value changed"


@pytest.mark.parametrize("demo", sorted(DEMOS))
def test_a_baseline_taken_from_this_build_reports_no_drift(demo, results):
    """The round trip a user performs on every pull request.

    Snapshot, then diff the same decisions against it. Anything non-zero here
    means a baseline and a run disagree about their own keys — which is how a
    refactor turns every user's next CI run into a wall of false drift.
    """
    result = results[demo]
    snapshot = build_snapshot(result.cases, result.observations)

    drift = diff(snapshot, result.cases, result.observations)

    assert drift == [], f"a baseline of this build drifts against itself: {drift}"


def test_a_baseline_notices_a_decision_that_flipped(results):
    """The guard above is only meaningful if the diff can see a change at all."""
    result = results["mcp"]
    snapshot = build_snapshot(result.cases, result.observations)
    target = "read_document::alice::other"
    assert target in snapshot["decisions"], "the demo no longer produces this id"
    snapshot["decisions"][target]["observed"] = Effect.DENY.value

    drift = diff(snapshot, result.cases, result.observations)

    assert [f.test_id for f in drift] == [target]


def test_a_waiver_narrowed_by_class_still_matches_its_finding(results):
    """`vuln_class` in a waivers file is matched against the wire value.

    Asserted through a real finding rather than a constructed one, so a change to
    either side of the comparison fails.
    """
    finding = next(
        f for f in results["mcp"].findings if f.vuln_class == VulnClass.BOLA
    )

    exact = Waiver(id=finding.test_id, reason="r", vuln_class="BOLA")
    wrong_class = Waiver(id=finding.test_id, reason="r", vuln_class="BFLA")
    any_class = Waiver(id=finding.test_id, reason="r")

    assert exact.matches(finding)
    assert any_class.matches(finding)
    assert not wrong_class.matches(finding)


def test_the_cli_surface_is_unchanged():
    """Command and option names are the interface a pipeline is written against.

    `test_readme_contract.py` asserts the README documents whatever the CLI has;
    this asserts what the CLI has. Without both, renaming a flag and its
    documentation together would pass.
    """
    from typer.main import get_command

    from overstep.cli import app

    command = get_command(app)
    assert set(command.commands) == {
        "run", "snapshot", "plan", "validate", "coverage", "scaffold", "version",
    }

    def options(name):
        return {
            opt
            for param in command.commands[name].params
            for opt in param.opts
            if opt.startswith("--")
        }

    # Asserted as equality for `run` — the command a pipeline actually invokes,
    # where a silently added flag is as much a surface change as a removed one.
    assert options("run") == {
        "--base", "--out", "--baseline", "--waivers", "--fail-on", "--concurrency",
        "--read-only", "--max-retries", "--insecure", "--env-file",
        "--allow-inconclusive",
    }
    assert {"--base", "--out", "--concurrency", "--read-only", "--max-retries",
            "--insecure", "--env-file", "--allow-inconclusive"} <= options("snapshot")
    assert {"--strict", "--live", "--base", "--insecure", "--env-file"} <= options("validate")
    assert {"--spec", "--fmt", "--only-get", "--token", "--fail-under",
            "--env-file"} <= options("coverage")
    assert {"--fmt", "--only-get", "--with-policy", "--server-name", "--server-url",
            "--token", "--protocol-version"} <= options("scaffold")


def test_the_gate_maps_findings_to_exit_codes():
    """0 clean, 1 findings, 2 bad input, 3 inconclusive — a pipeline branches on these.

    Exercised through the CLI's own mapping rather than restated, so a change to
    the gate's semantics fails here even when every finding-level test passes.
    """
    from overstep.cli import EXIT_INCONCLUSIVE, FAIL_ON_CHOICES, _exit_code

    assert EXIT_INCONCLUSIVE == 3
    assert FAIL_ON_CHOICES == ("vuln", "drift", "vuln-or-drift", "any", "never")

    class _Result:
        def __init__(self, vulnerabilities, drift, findings):
            self.vulnerabilities = vulnerabilities
            self.drift = drift
            self.findings = findings

    vuln_only = _Result(["v"], [], ["v"])
    drift_only = _Result([], ["d"], ["d"])
    benign = _Result([], [], ["unexpected-deny"])
    clean = _Result([], [], [])

    assert [_exit_code(vuln_only, gate) for gate in FAIL_ON_CHOICES] == [1, 0, 1, 1, 0]
    assert [_exit_code(drift_only, gate) for gate in FAIL_ON_CHOICES] == [0, 1, 1, 1, 0]
    assert [_exit_code(benign, gate) for gate in FAIL_ON_CHOICES] == [0, 0, 0, 1, 0]
    assert [_exit_code(clean, gate) for gate in FAIL_ON_CHOICES] == [0, 0, 0, 0, 0]
