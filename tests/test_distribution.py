"""Tests for the CI distribution artifacts (Docker, GitHub Action, pre-commit).

These files are how a DevSecOps team actually adopts the tool, so their shape is
part of the contract: the Action must expose the inputs the docs promise and run
the CLI; the pre-commit hook must call a real subcommand; the Dockerfile must
install the package and default to the entrypoint. The version a user sees is
part of that contract too, so the three places it is published — the package,
the wheel metadata and the README badge — are asserted to agree.
"""
import os
import re

import yaml

from overstep import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
        return f.read()


def test_dockerfile_installs_package_and_sets_entrypoint():
    df = _read("Dockerfile")
    assert "pip install" in df
    # The image must expose the overstep CLI as its entrypoint.
    assert 'ENTRYPOINT ["overstep"]' in df


def test_action_yml_declares_matrix_input_and_runs():
    action = yaml.safe_load(_read("action.yml"))
    assert action["name"]
    assert "matrix" in action["inputs"]
    assert action["inputs"]["matrix"]["required"] is True
    # Composite action so it runs on any GitHub-hosted runner.
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    assert any("overstep run" in (s.get("run") or "") for s in steps)


def test_action_exposes_documented_inputs():
    action = yaml.safe_load(_read("action.yml"))
    for name in (
        "matrix", "base-url", "out", "fail-on", "waivers", "baseline",
        "read-only", "env-file", "concurrency", "max-retries",
        "allow-inconclusive", "version",
    ):
        assert name in action["inputs"], f"action.yml missing input {name}"


def test_every_action_input_reaches_the_cli():
    """An input nobody passes on is a lie in the interface — it silently does
    nothing. Every optional input must appear in the step that builds the argv."""
    action = yaml.safe_load(_read("action.yml"))
    run_step = next(
        s for s in action["runs"]["steps"] if "overstep run" in (s.get("run") or "")
    )
    for name in action["inputs"]:
        if name == "version":  # consumed by the install step, not the run step
            continue
        assert f"inputs.{name}" in run_step["run"], f"action.yml input {name} is never used"


def test_precommit_hooks_call_validate():
    hooks = yaml.safe_load(_read(".pre-commit-hooks.yaml"))
    assert isinstance(hooks, list) and hooks
    ids = {h["id"] for h in hooks}
    assert "overstep-validate" in ids
    validate = next(h for h in hooks if h["id"] == "overstep-validate")
    assert "validate" in validate["entry"]


def test_dockerignore_excludes_git():
    di = _read(".dockerignore")
    assert ".git" in di


def test_pyproject_version_matches_package_version():
    # Parsed with a regex rather than tomllib so the test still runs on 3.10.
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
    assert match, "pyproject.toml has no version"
    assert match.group(1) == __version__, (
        f"pyproject.toml says {match.group(1)}, __version__ says {__version__}"
    )


def test_readme_version_badge_matches_package_version():
    match = re.search(
        r"!\[Version\]\(https://img\.shields\.io/badge/version-([0-9]+\.[0-9]+\.[0-9]+)-",
        _read("README.md"),
    )
    assert match, "README.md has no version badge"
    assert match.group(1) == __version__, (
        f"README badge says {match.group(1)}, __version__ says {__version__}"
    )
