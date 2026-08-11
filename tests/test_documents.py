"""Every file the CLI is pointed at fails as a message, not as a traceback.

The two most common mistakes anyone makes with this tool are typing a path that
is not there and mis-indenting a YAML file. Both used to escape as a raw Python
traceback from whichever loader happened to open the file, so these tests pin
the two halves of the fix: the loaders raise a domain error carrying the file
name and the parser's position, and every command that reads a file exits 2
with that message instead of unwinding.
"""
import json

import pytest
from typer.testing import CliRunner

from overstep.cli import app
from overstep.documents import DocumentError, read_json, read_yaml
from overstep.drift import load_snapshot
from overstep.matrix import MatrixError, load_matrix
from overstep.waivers import WaiverError, load_waivers

runner = CliRunner()

# Mis-indented so the scanner stops inside the mapping, not at the first line:
# the point of the assertion is that the reported position is the real one.
BAD_YAML = "subjects:\n- name: alice\n   role: user\n"

MATRIX = """
base_url: http://127.0.0.1:1
subjects:
  - name: alice
    role: user
    token: a
    attributes: {user_id: u1}
  - name: bob
    role: user
    token: b
    attributes: {user_id: u2}
resources:
  - name: get_user
    request: {method: GET, path: "/users/{id}"}
    type: object
    owner_param: id
    owner_attr: user_id
policy:
  get_user:
    allow:
      - {role: user, scope: own}
"""


@pytest.fixture
def matrix_file(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    return str(path)


# --- documents.read_yaml / read_json -----------------------------------------


def test_missing_file_names_the_path(tmp_path):
    with pytest.raises(DocumentError) as exc:
        read_yaml(str(tmp_path / "nope.yaml"), "matrix")
    assert "matrix" in str(exc.value)
    assert "nope.yaml" in str(exc.value)
    assert "does not exist" in str(exc.value)


def test_directory_is_reported_as_a_directory(tmp_path):
    with pytest.raises(DocumentError) as exc:
        read_yaml(str(tmp_path), "matrix")
    assert "is a directory" in str(exc.value)


def test_malformed_yaml_reports_line_and_column(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")
    with pytest.raises(DocumentError) as exc:
        read_yaml(str(path), "matrix")
    message = str(exc.value)
    assert "not valid YAML" in message
    # The mis-indentation is on the third line; 1-indexed, as an editor shows it.
    assert "line 3" in message
    assert "column" in message


def test_malformed_json_reports_line_and_column(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"a": 1,\n "b": }\n', encoding="utf-8")
    with pytest.raises(DocumentError) as exc:
        read_json(str(path), "baseline")
    message = str(exc.value)
    assert "not valid JSON" in message
    assert "line 2" in message


def test_binary_file_is_not_reported_as_a_syntax_error(tmp_path):
    path = tmp_path / "capture.har"
    path.write_bytes(b"\x1f\x8b\x08\x00\xff\xfe")
    with pytest.raises(DocumentError) as exc:
        read_json(str(path), "HAR file")
    assert "binary" in str(exc.value)


def test_empty_yaml_is_a_document_not_an_error(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    assert read_yaml(str(path), "matrix") is None


def test_valid_documents_still_parse(tmp_path):
    yaml_path = tmp_path / "ok.yaml"
    yaml_path.write_text("a: 1\n", encoding="utf-8")
    json_path = tmp_path / "ok.json"
    json_path.write_text('{"a": 1}', encoding="utf-8")
    assert read_yaml(str(yaml_path), "matrix") == {"a": 1}
    assert read_json(str(json_path), "baseline") == {"a": 1}


# --- the loaders, each mapping onto its own domain error ----------------------


@pytest.mark.parametrize("content", [None, BAD_YAML])
def test_load_matrix_raises_matrix_error(tmp_path, content):
    """Both failures arrive as MatrixError, which the CLI already handles."""
    path = tmp_path / "matrix.yaml"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(MatrixError) as exc:
        load_matrix(str(path))
    assert "matrix" in str(exc.value)


def test_load_waivers_raises_waiver_error(tmp_path):
    path = tmp_path / "waivers.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")
    with pytest.raises(WaiverError) as exc:
        load_waivers(str(path))
    assert "waivers file" in str(exc.value)


def test_load_snapshot_raises_document_error(tmp_path):
    with pytest.raises(DocumentError) as exc:
        load_snapshot(str(tmp_path / "baseline.json"))
    assert "baseline" in str(exc.value)


def test_openapi_loader_raises_document_error(tmp_path):
    from overstep.loaders.openapi import load_resources, scaffold_matrix

    path = tmp_path / "spec.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")
    for call in (load_resources, scaffold_matrix):
        with pytest.raises(DocumentError) as exc:
            call(str(path))
        assert "OpenAPI spec" in str(exc.value)


def test_openapi_loader_rejects_a_non_mapping_document(tmp_path):
    """A YAML list parses fine and is still not a spec; say so, don't AttributeError."""
    from overstep.loaders.openapi import load_resources

    path = tmp_path / "spec.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(DocumentError) as exc:
        load_resources(str(path))
    assert "not an OpenAPI document" in str(exc.value)


def test_har_loader_raises_document_error(tmp_path):
    from overstep.loaders.har import load_resources

    path = tmp_path / "capture.har"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(DocumentError) as exc:
        load_resources(str(path))
    assert "HAR file" in str(exc.value)


def test_har_loader_rejects_a_non_object_document(tmp_path):
    from overstep.loaders.har import load_resources

    path = tmp_path / "capture.har"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(DocumentError) as exc:
        load_resources(str(path))
    assert "not a HAR document" in str(exc.value)


def test_mcp_tools_loader_raises_document_error(tmp_path):
    from overstep.loaders.mcp import load_tools_from_file

    with pytest.raises(DocumentError) as exc:
        load_tools_from_file(str(tmp_path / "tools.json"))
    assert "MCP tools file" in str(exc.value)


def test_valid_har_and_tools_files_still_load(tmp_path):
    """The type guards reject documents of the wrong shape, not the right one."""
    from overstep.loaders.har import load_resources
    from overstep.loaders.mcp import load_tools_from_file

    har = tmp_path / "capture.har"
    har.write_text(json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": "http://x/users/42"}}
    ]}}), encoding="utf-8")
    assert [r.request.path for r in load_resources(str(har))] == ["/users/{id}"]

    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"result": {"tools": [{"name": "get_order"}]}}), encoding="utf-8")
    assert load_tools_from_file(str(tools)) == [{"name": "get_order"}]


# --- the CLI: a bad input file is an exit code, never an unwind ---------------


def _flat(output: str) -> str:
    """Undo rich's line wrapping so a message can be matched as one string."""
    return " ".join(output.split())


def _assert_clean_failure(result, *needles: str) -> None:
    """Exit 2 with a message — the two things a traceback is not.

    ``result.exception`` is what CliRunner sets when an exception reached the
    top level; a handled error leaves only ``SystemExit`` from ``typer.Exit``.
    """
    assert result.exit_code == 2, result.output
    if result.exception is not None:
        assert isinstance(result.exception, SystemExit), result.exception
    flat = _flat(result.output)
    for needle in needles:
        assert needle in flat, result.output


def test_cli_reports_a_missing_matrix(tmp_path):
    missing = str(tmp_path / "nope.yaml")
    for command in ("validate", "plan", "run", "snapshot", "coverage"):
        _assert_clean_failure(
            runner.invoke(app, [command, missing]), "does not exist", "nope.yaml"
        )


def test_cli_reports_malformed_matrix_yaml(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")
    for command in ("validate", "plan", "run", "snapshot", "coverage"):
        _assert_clean_failure(
            runner.invoke(app, [command, str(path)]), "not valid YAML", "line 3"
        )


def test_cli_reports_a_bad_baseline(tmp_path, matrix_file):
    _assert_clean_failure(
        runner.invoke(app, ["run", matrix_file, "--baseline", str(tmp_path / "no.json")]),
        "baseline",
        "does not exist",
    )


def test_cli_reports_a_bad_waivers_file(tmp_path, matrix_file):
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(BAD_YAML, encoding="utf-8")
    _assert_clean_failure(
        runner.invoke(app, ["run", matrix_file, "--waivers", str(waivers)]),
        "waivers file",
        "not valid YAML",
    )


def test_cli_reports_a_bad_scaffold_source(tmp_path):
    spec = tmp_path / "spec.yaml"
    spec.write_text(BAD_YAML, encoding="utf-8")
    missing = str(tmp_path / "nope.yaml")
    cases = [
        (["scaffold", missing], "does not exist"),
        (["scaffold", str(spec)], "not valid YAML"),
        (["scaffold", str(spec), "--with-policy"], "not valid YAML"),
        (["scaffold", missing, "--fmt", "har"], "does not exist"),
        (["scaffold", missing, "--fmt", "mcp"], "does not exist"),
    ]
    for args, needle in cases:
        _assert_clean_failure(runner.invoke(app, args), needle)


def test_cli_reports_a_bad_coverage_spec(tmp_path, matrix_file):
    spec = tmp_path / "spec.yaml"
    spec.write_text(BAD_YAML, encoding="utf-8")
    _assert_clean_failure(
        runner.invoke(app, ["coverage", matrix_file, "--spec", str(spec)]),
        "OpenAPI spec",
        "not valid YAML",
    )
    # The message is the loader's own, not wrapped in a second "could not read".
    again = runner.invoke(app, ["coverage", matrix_file, "--spec", str(spec)])
    assert "could not read" not in _flat(again.output)
