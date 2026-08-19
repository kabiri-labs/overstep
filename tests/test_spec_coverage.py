"""Tests for `overstep coverage` — the matrix measured against the API itself.

The matrix *is* the specification, so a gap in it is invisible from inside a
run: an operation nobody declared is an operation nobody tests, and nothing in
the findings mentions it. These cases pin the comparison that makes it visible.
"""
import json
import pytest
from typer.testing import CliRunner

from overstep.cli import app
from overstep.coverage import _normalize, against_spec
from overstep.modules.rest.openapi import load_resources
from overstep.matrix import Matrix
from overstep.models import McpCall, Request, Resource, ResourceType

SPEC = """
openapi: 3.0.0
info: { title: t, version: '1' }
paths:
  /users/{user_id}:
    get: { summary: get user, responses: { '200': { description: ok } } }
    delete: { summary: del user, responses: { '200': { description: ok } } }
  /admin/users:
    get: { summary: list, responses: { '200': { description: ok } } }
  /orders/{id}:
    get: { summary: get order, responses: { '200': { description: ok } } }
"""


@pytest.fixture
def spec_file(tmp_path):
    path = tmp_path / "api.yaml"
    path.write_text(SPEC, encoding="utf-8")
    return path


def _http(name, method, path, type_="function"):
    return Resource(
        name=name, request=Request(method=method, path=path), type=ResourceType(type_)
    )


def _matrix(*resources):
    return Matrix(
        modules={"rest": {"base_url": "http://t"}},
        subjects=[{"name": "a", "role": "user", "token": "t"}],
        resources=list(resources),
        policy={r.name: {"allow": [{"role": "user"}]} for r in resources},
    )


def test_missing_operations_are_named(spec_file):
    m = _matrix(_http("get_user", "GET", "/users/{id}"))
    result = against_spec(m, load_resources(str(spec_file)))

    assert result.operations == 4
    assert result.covered == 1
    assert sorted(result.missing) == [
        "DELETE /users/{user_id}",
        "GET /admin/users",
        "GET /orders/{id}",
    ]


def test_parameter_names_do_not_create_phantom_gaps(spec_file):
    """The spec says {user_id}, the matrix says {id}: one operation, not two."""
    m = _matrix(
        _http("get_user", "GET", "/users/{id}"),
        _http("del_user", "DELETE", "/users/{whatever}"),
    )
    result = against_spec(m, load_resources(str(spec_file)))

    assert "GET /users/{user_id}" not in result.missing
    assert "DELETE /users/{user_id}" not in result.missing
    assert result.extra == []


def test_a_trailing_slash_is_not_a_separate_operation(spec_file):
    m = _matrix(_http("list", "GET", "/admin/users/"))
    result = against_spec(m, load_resources(str(spec_file)))

    assert "GET /admin/users" not in result.missing
    assert result.extra == []


def test_normalize_ignores_case_whitespace_and_parameter_naming():
    """The unit contract. `Request.method` is an uppercase Literal, so a matrix
    cannot smuggle a lowercase verb past pydantic — but the key builder is a
    plain function and does not rely on that."""
    assert _normalize("get", " /users/{id} ") == _normalize("GET", "/users/{user_id}")
    assert _normalize("GET", "/admin/users/") == _normalize("GET", "/admin/users")
    assert _normalize("GET", "/") == "GET /"
    assert _normalize("GET", "/a/{x}/b/{y}") != _normalize("GET", "/a/{x}/b")


def test_a_resource_the_spec_does_not_mention_is_reported_as_extra(spec_file):
    """Undocumented endpoint, stale spec — or a mistyped path in the matrix."""
    m = _matrix(_http("secret", "GET", "/internal/debug"))
    result = against_spec(m, load_resources(str(spec_file)))

    assert result.extra == ["GET /internal/debug"]


def test_a_mistyped_path_shows_up_on_both_sides(spec_file):
    """The failure this catches: it reads as one gap and one stray, not a match."""
    m = _matrix(_http("list", "GET", "/admin/user"))  # missing the 's'
    result = against_spec(m, load_resources(str(spec_file)))

    assert "GET /admin/users" in result.missing
    assert "GET /admin/user" in result.extra


def test_full_coverage_is_complete(spec_file):
    m = _matrix(
        _http("a", "GET", "/users/{id}"),
        _http("b", "DELETE", "/users/{id}"),
        _http("c", "GET", "/admin/users"),
        _http("d", "GET", "/orders/{id}"),
    )
    result = against_spec(m, load_resources(str(spec_file)))

    assert result.complete
    assert result.ratio == 1.0
    assert result.missing == [] and result.extra == []


def test_an_empty_spec_is_not_zero_percent_covered():
    """Nothing to cover is full coverage, not a division by zero."""
    result = against_spec(_matrix(), [])

    assert result.ratio == 1.0
    assert result.complete


def test_duplicate_operations_in_the_spec_are_counted_once():
    m = _matrix()
    declared = [_http("a", "GET", "/x/{id}"), _http("b", "GET", "/x/{other}")]

    assert against_spec(m, declared).operations == 1


def test_mcp_resources_are_matched_by_tool_name():
    m = Matrix(
        modules={"mcp": {"servers": [{"name": "mcp", "url": "http://t/mcp"}]}},
        subjects=[{"name": "a", "role": "user", "token": "t"}],
        resources=[Resource(name="read_doc",                            call=McpCall(server="mcp", tool="read_doc"))],
        policy={"read_doc": {"allow": [{"role": "user"}]}},
    )
    declared = [
        Resource(name="read_doc", call=McpCall(server="s", tool="read_doc")),
        Resource(name="delete_doc", call=McpCall(server="s", tool="delete_doc")),
    ]
    result = against_spec(m, declared)

    assert result.missing == ["tool delete_doc"]
    assert result.extra == []


def test_mcp_resource_reads_are_matched_by_uri_shape():
    """A declared read must not be reported as a stray against its own server.

    The two sides name the URI placeholder independently — the server's template
    says `{doc_id}`, the matrix may say `{id}` — so they are compared by shape,
    the way a path is.
    """
    from overstep.models import McpResourceRead

    m = Matrix(
        modules={"mcp": {"servers": [{"name": "mcp", "url": "http://t/mcp"}]}},
        subjects=[{"name": "a", "role": "user", "token": "t"}],
        resources=[Resource(name="doc",                            read=McpResourceRead(server="mcp", uri="doc://acme/{id}"))],
        policy={"doc": {"allow": [{"role": "user"}]}},
    )
    declared = [
        Resource(name="doc",                 read=McpResourceRead(server="s", uri="doc://acme/{doc_id}")),
        Resource(name="other",                 read=McpResourceRead(server="s", uri="note://{note_id}")),
    ]
    result = against_spec(m, declared)

    assert result.missing == ["resource note://{note_id}"]
    assert result.extra == []


# --- CLI --------------------------------------------------------------------

MATRIX = """
modules:
  rest:
    base_url: http://t
subjects:
  - { name: a, role: user, token: t }
resources:
  - { name: get_user, request: { method: GET, path: "/users/{id}" } }
policy:
  get_user: { allow: [{ role: user }] }
"""


@pytest.fixture
def matrix_file(tmp_path):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    return path


def test_coverage_lists_the_gap(matrix_file, spec_file):
    result = CliRunner().invoke(
        app, ["coverage", str(matrix_file), "--spec", str(spec_file)]
    )

    assert result.exit_code == 0
    assert "GET /admin/users" in result.stdout


def test_coverage_without_a_spec_still_reports_the_object_surface(matrix_file):
    result = CliRunner().invoke(app, ["coverage", str(matrix_file)])

    assert result.exit_code == 0
    assert "Object surface" in result.stdout
    assert "API surface" not in result.stdout


def test_fail_under_gates_on_the_percentage(matrix_file, spec_file):
    result = CliRunner().invoke(
        app, ["coverage", str(matrix_file), "--spec", str(spec_file), "--fail-under", "80"]
    )

    assert result.exit_code == 1
    assert "below --fail-under" in result.stdout


def test_fail_under_passes_when_the_bar_is_met(matrix_file, spec_file):
    result = CliRunner().invoke(
        app, ["coverage", str(matrix_file), "--spec", str(spec_file), "--fail-under", "20"]
    )

    assert result.exit_code == 0


def test_fail_under_rejects_a_percentage_outside_the_range(matrix_file):
    result = CliRunner().invoke(app, ["coverage", str(matrix_file), "--fail-under", "150"])

    assert result.exit_code == 2


def test_an_unknown_format_is_rejected(matrix_file, spec_file):
    result = CliRunner().invoke(
        app, ["coverage", str(matrix_file), "--spec", str(spec_file), "--fmt", "nope"]
    )

    assert result.exit_code == 2


def test_coverage_sends_nothing(matrix_file, spec_file):
    """The base_url points nowhere; the command must not care."""
    result = CliRunner().invoke(
        app, ["coverage", str(matrix_file), "--spec", str(spec_file)]
    )

    assert result.exit_code == 0


def test_coverage_fails_loudly_when_the_mcp_surface_cannot_be_read(matrix_file):
    """A failed listing must not become an empty denominator.

    `--fail-under` gates on that number, so swallowing the failure would let a
    matrix pass for covering a surface that was never measured.
    """
    import httpx

    import overstep.modules.mcp.loader as mod

    def broken(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        if msg.get("method") == "notifications/initialized":
            return httpx.Response(202)
        if msg.get("method") == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
        raise httpx.ConnectError("connection reset")   # the templates listing

    orig = httpx.Client
    mod.httpx.Client = lambda *a, **kw: orig(*a, transport=httpx.MockTransport(broken), **kw)
    try:
        result = CliRunner().invoke(
            app,
            ["coverage", str(matrix_file), "--spec", "http://t/mcp", "--fmt", "mcp",
             "--fail-under", "100"],
        )
    finally:
        mod.httpx.Client = orig

    assert result.exit_code == 2, result.output
    assert "could not read the MCP surface" in result.output
