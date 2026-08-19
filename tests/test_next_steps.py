"""Tests for the "next:" hints that chain the commands into a sequence.

The commands are individually clear and collectively a sequence nobody is told.
These cases pin the chain, and — more importantly — the two things that would
make it harmful: landing in a redirected `scaffold` file, and pointing a user
somewhere that cannot work.
"""
import pytest
from typer.testing import CliRunner

from overstep.cli import NO_HINTS_ENV, app

SPEC = """
openapi: 3.0.0
info: { title: t, version: '1' }
paths:
  /users/{id}:
    get: { summary: get user, responses: { '200': { description: ok } } }
"""

CLEAN_MATRIX = """
modules:
  rest:
    base_url: http://127.0.0.1:1
roles: [user, admin]
subjects:
  - { name: a, role: user, token: t1, attributes: { user_id: u1 } }
  - { name: b, role: user, token: t2, attributes: { user_id: u2 } }
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner_param: id
    owner_attr: user_id
policy:
  get_user: { allow: [{ role: user, scope: own }] }
"""

# No policy entry -> one warning, no errors.
WARNING_MATRIX = """
subjects:
  - { name: a, role: user, token: t }
resources:
  - { name: r, request: { method: GET, path: /x } }
"""


@pytest.fixture(autouse=True)
def hints_on(monkeypatch):
    """The hints are opt-out, so make sure the environment is not opting out."""
    monkeypatch.delenv(NO_HINTS_ENV, raising=False)


@pytest.fixture
def spec_file(tmp_path):
    path = tmp_path / "api.yaml"
    path.write_text(SPEC, encoding="utf-8")
    return path


@pytest.fixture
def clean_matrix(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(CLEAN_MATRIX, encoding="utf-8")
    return path


def _run(args):
    """Invoke the CLI.

    ``result.output`` is the two streams combined; ``result.stdout`` and
    ``result.stderr`` are kept apart, which is what the redirect cases need.
    """
    return CliRunner().invoke(app, args, catch_exceptions=False)


# --- the chain --------------------------------------------------------------


def test_scaffold_points_at_validate(spec_file):
    result = _run(["scaffold", str(spec_file), "--with-policy"])

    assert "next: overstep validate" in result.output
    assert "placeholder" in result.output


def test_a_bare_resources_block_does_not_point_at_validate(spec_file):
    """It is a fragment: `validate` on it would fail to parse, not help."""
    result = _run(["scaffold", str(spec_file)])

    assert "next: overstep validate" not in result.output
    assert "fragment" in result.output


def test_validate_points_at_live(clean_matrix):
    result = _run(["validate", str(clean_matrix)])

    assert "next: overstep validate" in result.output
    assert "--live" in result.output


def test_a_failed_live_check_names_no_next_step(clean_matrix):
    """The target is dead: the errors are what to do, not a step past them."""
    result = _run(["validate", str(clean_matrix), "--live"])

    assert result.exit_code == 1
    assert "next:" not in result.output


def test_a_passing_live_check_points_at_plan(clean_matrix, monkeypatch):
    monkeypatch.setattr("overstep.cli.preflight_check", lambda *a, **k: [])

    result = _run(["validate", str(clean_matrix), "--live"])

    assert result.exit_code == 0
    assert "next: overstep plan" in result.output
    assert "--live" not in result.stderr, "it must not point back at the step just run"


def test_plan_points_at_run(clean_matrix):
    result = _run(["plan", str(clean_matrix)])

    assert "next: overstep run" in result.output


def test_a_matrix_with_only_warnings_still_gets_a_next_step(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(WARNING_MATRIX, encoding="utf-8")

    result = _run(["validate", str(path)])

    assert result.exit_code == 0
    assert "next:" in result.output


def test_errors_are_the_next_step_so_none_is_printed(spec_file, tmp_path):
    """An unfilled scaffold: every error already says what to do about it."""
    scaffolded = _run(["scaffold", str(spec_file), "--with-policy"])
    path = tmp_path / "matrix.yaml"
    path.write_text(scaffolded.stdout, encoding="utf-8")

    result = _run(["validate", str(path)])

    assert result.exit_code == 1
    assert "next:" not in result.output


# --- the two ways this could do harm ----------------------------------------


def test_the_hint_never_lands_in_a_redirected_scaffold(spec_file):
    """stdout is piped into a matrix file; a hint in it would be a parse error."""
    result = _run(["scaffold", str(spec_file), "--with-policy"])

    assert "next:" not in result.stdout
    assert "next:" in result.stderr


def test_a_redirected_scaffold_is_still_valid_yaml(spec_file):
    import yaml

    result = _run(["scaffold", str(spec_file), "--with-policy"])
    parsed = yaml.safe_load(result.stdout)

    assert "subjects" in parsed and "resources" in parsed


def test_hints_can_be_switched_off(clean_matrix, monkeypatch):
    monkeypatch.setenv(NO_HINTS_ENV, "1")

    result = _run(["validate", str(clean_matrix)])

    assert result.exit_code == 0
    assert "next:" not in result.output
    assert "matrix is valid" in result.output, "the verdict itself is not a hint"


def test_switching_hints_off_changes_no_exit_code(clean_matrix, monkeypatch):
    with_hints = _run(["validate", str(clean_matrix)]).exit_code
    monkeypatch.setenv(NO_HINTS_ENV, "1")
    without = _run(["validate", str(clean_matrix)]).exit_code

    assert with_hints == without == 0


def test_the_verdict_comes_before_the_hint(clean_matrix):
    """A hint reads as an instruction; it only makes sense after the result."""
    result = _run(["validate", str(clean_matrix)])

    assert "matrix is valid" in result.stdout
    assert "next:" in result.stderr


def test_strict_still_fails_on_warnings_with_the_hint_in_place(tmp_path):
    """The restructure that moved the hint must not have moved the exit code."""
    path = tmp_path / "matrix.yaml"
    path.write_text(WARNING_MATRIX, encoding="utf-8")

    assert _run(["validate", str(path), "--strict"]).exit_code == 1
    assert _run(["validate", str(path)]).exit_code == 0
