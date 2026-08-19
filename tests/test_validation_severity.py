"""Tests for validation severity and the unfilled-placeholder scan.

Two behaviours are covered together because they are two halves of one problem:
an untouched `overstep scaffold` output used to be reported as a valid matrix,
while a deliberate deny-by-default resource used to fail the same check.
"""
import pytest
from typer.testing import CliRunner

from overstep.cli import app
from overstep.modules.rest.openapi import scaffold_matrix
from overstep.matrix import Matrix, Problem, Severity
from overstep.placeholders import scan

SPEC = """
openapi: 3.0.0
info: { title: t, version: '1' }
paths:
  /users/{id}:
    get:
      summary: Get user by id
      responses: { '200': { description: ok } }
"""


@pytest.fixture
def scaffolded(tmp_path):
    """An untouched scaffold — placeholders and all — written to disk."""
    spec = tmp_path / "api.yaml"
    spec.write_text(SPEC, encoding="utf-8")
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(scaffold_matrix(str(spec)), encoding="utf-8")
    return matrix


# --- severity ---------------------------------------------------------------


def test_missing_policy_entry_is_a_warning_not_an_error():
    """Deny-by-default is a stance, not a defect: it over-reports, never mistests."""
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
    )
    problems = m.diagnose()

    assert [p.severity for p in problems] == [Severity.WARNING]
    assert "no policy entry" in problems[0].message


def test_broken_reference_is_an_error():
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"ghost": {"allow": [{"role": "user"}]}, "r": {"allow": [{"role": "user"}]}},
    )
    problems = m.diagnose()

    assert [p.severity for p in problems] == [Severity.ERROR]
    assert "unknown resource 'ghost'" in problems[0].message


def test_undiscriminated_objects_warn_because_the_run_is_smaller_not_wrong():
    """No two subjects own different objects: the BOLA probe is dropped, not broken."""
    m = Matrix(
        subjects=[
            {"name": "a", "role": "user", "attributes": {"user_id": "u1"}},
            {"name": "b", "role": "user", "attributes": {"user_id": "u1"}},
        ],
        resources=[{
            "name": "r",
            "request": {"method": "GET", "path": "/x/{id}"},
            "type": "object",
            "owner_param": "id",
            "owner_attr": "user_id",
        }],
        policy={"r": {"allow": [{"role": "user", "scope": "own"}]}},
    )

    assert [p.severity for p in m.diagnose()] == [Severity.WARNING]


def test_diagnose_puts_errors_before_warnings():
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        # 'r' has no policy entry (warning); 'ghost' does not exist (error).
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"ghost": {"allow": [{"role": "user"}]}},
    )
    severities = [p.severity for p in m.diagnose()]

    assert severities == [Severity.ERROR, Severity.WARNING]


def test_validate_refs_still_returns_plain_strings():
    """The pre-severity API is unchanged for callers that only want the messages."""
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
    )
    problems = m.validate_refs()

    assert all(isinstance(p, str) for p in problems)
    assert any("no policy entry" in p for p in problems)


def test_problem_prefixes_its_line_only_when_it_has_one():
    assert str(Problem("x", Severity.ERROR, 7)) == "line 7: x"
    assert str(Problem("x", Severity.ERROR)) == "x"


# --- placeholders -----------------------------------------------------------


def test_untouched_scaffold_is_not_a_valid_matrix(scaffolded):
    """The regression: this reported "ok — matrix is valid" and exited 0."""
    result = CliRunner().invoke(app, ["validate", str(scaffolded)])

    assert result.exit_code == 1
    assert "PASTE_" in result.stdout
    assert "matrix is valid" not in result.stdout


def test_placeholders_are_reported_with_the_line_to_edit(scaffolded):
    problems = scan(str(scaffolded))
    lines = scaffolded.read_text(encoding="utf-8").split("\n")

    assert problems
    for problem in problems:
        assert problem.severity is Severity.ERROR
        # The reported line really is the one holding the placeholder.
        placeholder = problem.message.split("'")[1]
        assert placeholder in lines[problem.line - 1]


def test_placeholders_are_reported_in_file_order(scaffolded):
    lines = [p.line for p in scan(str(scaffolded))]

    assert lines == sorted(lines)


def test_token_and_identifier_placeholders_get_different_advice(scaffolded):
    messages = {p.message.split("'")[1]: p.message for p in scan(str(scaffolded))}
    token = next(m for k, m in messages.items() if k.startswith("PASTE_"))
    identifier = next(m for k, m in messages.items() if k.startswith("REPLACE_ME"))

    assert "${ENV_VAR}" in token
    assert "cross-owner probe" in identifier


def test_scan_names_the_path_to_the_offending_value(scaffolded):
    paths = [p.message.split(" is still")[0] for p in scan(str(scaffolded))]

    assert any(path.startswith("subjects[") and path.endswith(".token") for path in paths)


def test_a_real_credential_that_merely_mentions_the_marker_is_kept(tmp_path):
    """Anchored matching: only a whole-value placeholder is a placeholder."""
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "subjects:\n"
        "  - { name: a, role: user, token: PASTE_ME_A_REAL_TOKEN_PLEASE }\n"
        "resources: []\n",
        encoding="utf-8",
    )

    assert scan(str(matrix)) == []


def test_placeholders_in_mapping_keys_are_found(tmp_path):
    """An `objects:` entry keyed by an unrenamed subject is just as dead."""
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "resources:\n"
        "  - name: r\n"
        "    objects:\n"
        "      REPLACE_ME_1: o1\n",
        encoding="utf-8",
    )
    problems = scan(str(matrix))

    assert len(problems) == 1
    assert problems[0].line == 4


def test_env_references_are_not_placeholders(tmp_path):
    """The recommended fix must not itself trip the check."""
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "subjects:\n"
        "  - { name: a, role: user, token: '${ALICE_TOKEN}' }\n",
        encoding="utf-8",
    )

    assert scan(str(matrix)) == []


def test_scan_stays_quiet_on_an_unreadable_file(tmp_path):
    """Whoever loads the matrix reports these in more detail; don't double up."""
    unparseable = tmp_path / "bad.yaml"
    unparseable.write_text("subjects: [\n", encoding="utf-8")

    assert scan(str(unparseable)) == []
    assert scan(str(tmp_path / "does-not-exist.yaml")) == []


# --- exit codes -------------------------------------------------------------


def test_warnings_alone_do_not_fail_validate(tmp_path):
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "subjects:\n"
        "  - { name: a, role: user, token: t }\n"
        "resources:\n"
        "  - { name: r, request: { method: GET, path: /x } }\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["validate", str(matrix)])

    assert result.exit_code == 0
    assert "warning:" in result.stdout


def test_strict_turns_warnings_into_a_failure(tmp_path):
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "subjects:\n"
        "  - { name: a, role: user, token: t }\n"
        "resources:\n"
        "  - { name: r, request: { method: GET, path: /x } }\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["validate", str(matrix), "--strict"])

    assert result.exit_code == 1


def test_a_clean_matrix_still_passes(tmp_path):
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "subjects:\n"
        "  - { name: a, role: user, token: t }\n"
        "resources:\n"
        "  - { name: r, request: { method: GET, path: /x } }\n"
        "policy:\n"
        "  r: { allow: [{ role: user }] }\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["validate", str(matrix)])

    assert result.exit_code == 0
    assert "matrix is valid" in result.stdout


def test_run_names_the_placeholder_line_before_sending_anything(scaffolded, tmp_path):
    """The whole point: the diagnosis arrives before the network, not after it."""
    result = CliRunner().invoke(
        app,
        ["run", str(scaffolded), "--base", "http://127.0.0.1:1", "--out", str(tmp_path / "out")],
    )

    assert "PASTE_" in result.stdout
    # Printed ahead of the run's own output rather than buried in the summary.
    assert result.stdout.index("PASTE_") < result.stdout.index("Planned")
