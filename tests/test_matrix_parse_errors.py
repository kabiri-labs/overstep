"""A mistyped key is reported where the user is: in the file, by name, with the fix.

pydantic's own message for one is ``resources.2.forbiden_fields - Extra inputs
are not permitted`` and a link to its documentation. The index has to be counted
by hand, the line is not given, and the word that was meant is not offered.
"""
import os

import pytest
from typer.testing import CliRunner

from overstep.cli import app
from overstep.matrix import MatrixError, load_matrix

MATRIX = """\
modules: { rest: { base_url: "http://127.0.0.1:1" } }
roles: [user]
subjects:
  - { name: alice, role: user, token: t }
resources:
  - name: list_orders
    request: { method: GET, path: /orders }
  - name: get_order
    request: { method: GET, path: "/orders/{id}" }
    forbiden_fields: [password_hash]
policy:
  list_orders: { allow: [{ role: user }] }
"""


def _error(tmp_path, text) -> str:
    path = tmp_path / "matrix.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(MatrixError) as caught:
        load_matrix(str(path))
    return str(caught.value)


def test_a_misspelled_key_names_the_resource_the_line_and_the_spelling(tmp_path):
    message = _error(tmp_path, MATRIX)

    assert "line 10: resource 'get_order' has an unknown key 'forbiden_fields'" in message
    assert "did you mean 'forbidden_fields'?" in message


def test_the_message_carries_no_link_and_no_validator_jargon(tmp_path):
    message = _error(tmp_path, MATRIX)

    assert "pydantic" not in message
    assert "http" not in message.replace("http://127.0.0.1:1", "")
    assert "Extra inputs" not in message


def test_a_key_under_an_alias_is_suggested_as_it_is_written(tmp_path):
    """`run_as` is spelled `as` in a matrix, so that is the word to offer."""
    text = MATRIX + "setup:\n  - { ass: alice, request: { method: POST, path: /orders } }\n"
    message = _error(tmp_path, text)

    assert "unknown key 'ass'" in message
    assert "did you mean 'as'?" in message


def test_a_key_with_no_near_neighbour_lists_what_is_valid_instead(tmp_path):
    text = MATRIX.replace("forbiden_fields: [password_hash]", "zzzzzz: 1")
    message = _error(tmp_path, text)

    assert "resource 'get_order' has an unknown key 'zzzzzz'" in message
    assert "did you mean" not in message
    assert "valid keys here:" in message and "forbidden_fields" in message


def test_a_top_level_typo_is_located_too(tmp_path):
    message = _error(tmp_path, MATRIX.replace("policy:", "polcy:"))

    assert "line 11: the top level has an unknown key 'polcy'" in message
    assert "did you mean 'policy'?" in message


def test_every_problem_is_reported_not_only_the_first(tmp_path):
    text = MATRIX.replace("- { name: alice, role: user, token: t }", "- { name: alice, tokn: t }")
    text = text.replace("policy:", "  - request: { method: GET, path: /nameless }\npolicy:")
    message = _error(tmp_path, text)

    assert "subject 'alice' has an unknown key 'tokn'" in message
    assert "did you mean 'token'?" in message
    assert "resource 'get_order' has an unknown key 'forbiden_fields'" in message
    # A missing required field is not a typo, but it is located the same way.
    assert "line 11: resources[2].name: Field required" in message


def test_the_cli_prints_it_and_exits_two(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    result = CliRunner().invoke(app, ["validate", str(path)])
    flat = " ".join(result.stdout.split())

    assert result.exit_code == 2
    assert "resource 'get_order' has an unknown key 'forbiden_fields'" in flat


# --- the hint that follows ----------------------------------------------------

ENV_MATRIX = MATRIX.replace("    forbiden_fields: [password_hash]\n", "").replace(
    "token: t", 'token: "${ALICE_TOKEN}"'
)


@pytest.fixture
def env_matrix(tmp_path, monkeypatch):
    monkeypatch.delenv("ALICE_TOKEN", raising=False)
    monkeypatch.delenv("OVERSTEP_NO_HINTS", raising=False)
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(ENV_MATRIX, encoding="utf-8")
    env = tmp_path / "secrets.env"
    env.write_text("ALICE_TOKEN=abc\n", encoding="utf-8")
    yield matrix, env
    # --env-file writes into the process environment; do not leak it onward.
    os.environ.pop("ALICE_TOKEN", None)


def _hint(result) -> str:
    return " ".join(result.output.split())


def test_validate_suggests_a_command_that_can_load_the_matrix(env_matrix):
    matrix, env = env_matrix
    result = CliRunner().invoke(app, ["validate", str(matrix), "--env-file", str(env)])

    assert "--live --env-file" in _hint(result)


def test_plan_suggests_a_run_that_can_load_the_matrix(env_matrix):
    matrix, env = env_matrix
    result = CliRunner().invoke(app, ["plan", str(matrix), "--env-file", str(env)])

    assert "--out out --env-file" in _hint(result)


def test_without_an_env_file_the_hint_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv("OVERSTEP_NO_HINTS", raising=False)
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(ENV_MATRIX.replace('"${ALICE_TOKEN}"', "t"), encoding="utf-8")
    result = CliRunner().invoke(app, ["validate", str(matrix)])

    assert "next: overstep validate" in _hint(result)
    assert "--env-file" not in result.output
