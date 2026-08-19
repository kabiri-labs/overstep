"""The two-level matrix: shared core at the top, per-surface config under `modules`.

A matrix declares two kinds of thing. Subjects, resources, policy, credentials
and fixtures describe *what* is being tested and mean the same whatever carries
the request. A base URL, a deny signal, a list of MCP servers and the protocol
probes only mean something to one surface.

They used to sit side by side at the top level, which made five of the fifteen
keys MCP-only while reading as global — `servers`, `mcp_access` and the three
`probe_*` switches. A REST-only matrix carried settings that could never apply
to it, and nothing in the file said which of the two the next key belonged to.

These cases pin the split, the migration errors that make an out-of-date file an
instruction rather than a silent misread, and the one thing the split makes
possible: a resource's module is now read off its body, so it cannot contradict
itself.
"""
import pytest

from overstep.matrix import RELOCATED_KEYS, Matrix, MatrixError, load_matrix
from overstep.models import McpCall, McpResourceRead, Request, Resource

CORE = {
    "roles": ["anonymous", "user", "admin"],
    "subjects": [{"name": "alice", "role": "user", "token": "a"}],
    "policy": {"r": {"allow": [{"role": "user"}]}},
}

REST_RESOURCE = {"name": "r", "request": {"method": "GET", "path": "/r"}, "type": "function"}
MCP_RESOURCE = {"name": "r", "call": {"server": "docs", "tool": "r"}, "type": "function"}


def _write(tmp_path, text: str) -> str:
    path = tmp_path / "matrix.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- the split ---------------------------------------------------------------


def test_each_module_carries_its_own_configuration():
    matrix = Matrix(
        **CORE,
        resources=[REST_RESOURCE],
        modules={
            "rest": {"base_url": "http://api.test", "access": {"allow_status": [200, 202]}},
            "mcp": {
                "servers": [{"name": "docs", "url": "http://docs.test/mcp"}],
                "access": {"is_error_is_deny": False},
                "probes": {"tool_enumeration": True},
            },
        },
    )

    assert matrix.modules.rest.base_url == "http://api.test"
    assert matrix.modules.rest.access.allow_status == [200, 202]
    assert matrix.modules.mcp.servers[0].name == "docs"
    assert matrix.modules.mcp.access.is_error_is_deny is False
    assert matrix.modules.mcp.probes.tool_enumeration is True


def test_a_matrix_that_declares_no_modules_still_has_both_defaults():
    """A single-module matrix should not have to write an empty block for the other."""
    matrix = Matrix(**CORE, resources=[REST_RESOURCE])

    assert matrix.modules.rest.base_url is None
    assert matrix.modules.mcp.servers == []
    # The defaults the probes carried when they were top-level keys.
    assert matrix.modules.mcp.probes.token_audience is True
    assert matrix.modules.mcp.probes.session_binding is True
    assert matrix.modules.mcp.probes.tool_enumeration is False


@pytest.mark.parametrize("key", sorted(RELOCATED_KEYS))
def test_a_relocated_key_is_an_error_that_names_its_new_home(tmp_path, key):
    """Silently ignoring one is the worst available outcome.

    Pydantic's default is to drop an unknown key. A matrix still declaring
    `servers:` at the top level would then load, plan no MCP cases at all, and
    report a clean run against a server it never contacted — a false negative
    from a security tool, produced by an out-of-date file rather than a bug.
    """
    path = _write(
        tmp_path,
        f"{key}: whatever\n"
        "subjects:\n  - {name: alice, role: user, token: a}\n"
        "resources: []\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    assert "flat layout" in str(excinfo.value)
    assert RELOCATED_KEYS[key] in str(excinfo.value)


def test_every_relocated_key_is_reported_at_once(tmp_path):
    """One pass per file, not one error per edit-and-rerun cycle."""
    path = _write(
        tmp_path,
        "base_url: http://api.test\n"
        "servers: []\n"
        "probe_tool_enumeration: true\n"
        "subjects:\n  - {name: alice, role: user, token: a}\n"
        "resources: []\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    message = str(excinfo.value)
    for key in ("base_url", "servers", "probe_tool_enumeration"):
        assert RELOCATED_KEYS[key] in message


def test_an_unknown_key_is_rejected_rather_than_ignored(tmp_path):
    """The same guarantee for a typo, which no relocation table can enumerate."""
    path = _write(
        tmp_path,
        "subjectss:\n  - {name: alice, role: user, token: a}\n"
        "subjects: []\n"
        "resources: []\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    assert "subjectss" in str(excinfo.value)


def test_a_programmatic_caller_cannot_pass_the_old_keyword():
    """The library API and the file format have to agree about what exists.

    `load_matrix` names the relocated keys, but it builds the model by splatting
    a dict — so without this, `Matrix(servers=[...])` from Python would be
    accepted and dropped while the same key in YAML was refused.
    """
    with pytest.raises(Exception) as excinfo:
        Matrix(**CORE, resources=[REST_RESOURCE], servers=[{"name": "docs", "url": "http://x"}])

    assert "servers" in str(excinfo.value)


# --- the module is read off the body -----------------------------------------


@pytest.mark.parametrize("body,expected", [
    ({"request": Request(method="GET", path="/r")}, "http"),
    ({"call": McpCall(server="docs", tool="r")}, "mcp"),
    ({"read": McpResourceRead(server="docs", uri="doc://{id}")}, "mcp"),
])
def test_a_resources_module_follows_from_what_it_sends(body, expected):
    assert Resource(name="r", **body).transport == expected


def test_a_resource_has_no_transport_field_to_contradict_its_body():
    """The point of deriving it: the disagreeing state cannot be written down."""
    assert "transport" not in Resource.model_fields


def test_the_matrix_plans_a_mixed_run_without_either_resource_declaring_a_module():
    """One matrix, both surfaces, and nothing naming a transport anywhere."""
    from overstep.planner import plan

    matrix = Matrix(
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "token": "a"}],
        modules={
            "rest": {"base_url": "http://api.test"},
            "mcp": {"servers": [{"name": "docs", "url": "http://docs.test/mcp"}],
                    "probes": {"session_binding": False}},
        },
        resources=[
            {"name": "rest_op", "request": {"method": "GET", "path": "/r"}, "type": "function"},
            {"name": "mcp_op", "call": {"server": "docs", "tool": "t"}, "type": "function"},
        ],
        policy={"rest_op": {"allow": [{"role": "user"}]},
                "mcp_op": {"allow": [{"role": "user"}]}},
    )

    by_resource = {c.resource: c.transport for c in plan(matrix)}

    assert by_resource == {"rest_op": "http", "mcp_op": "mcp"}


# --- one access key, the module's schema -------------------------------------


def test_a_rest_resource_reads_access_as_a_response_matcher():
    resource = Resource(
        name="r",
        request={"method": "GET", "path": "/r"},
        access={"allow_status": [200, 202], "deny_body_regex": "nope"},
    )

    assert resource.access.allow_status == [200, 202]
    assert resource.mcp_access is None


def test_an_mcp_resource_reads_the_same_key_as_an_mcp_matcher():
    """Same key, different schema — which is why the body has to decide."""
    resource = Resource(
        name="r",
        call={"server": "docs", "tool": "t"},
        access={"is_error_is_deny": False, "deny_status": ["5xx"]},
    )

    assert resource.mcp_access.is_error_is_deny is False
    assert resource.mcp_access.deny_status == ["5xx"]
    assert resource.access is None


def test_an_mcp_matcher_on_a_rest_resource_is_refused():
    """The routing has to be a real check, not a relabelling.

    `is_error_is_deny` means nothing over HTTP, so a REST resource given an MCP
    matcher is a mistake — and one worth an error, because the keys would
    otherwise be dropped and the resource would silently use the defaults.
    """
    with pytest.raises(Exception) as excinfo:
        Resource(name="r", request={"method": "GET", "path": "/r"},
                 access={"is_error_is_deny": False})

    assert "is_error_is_deny" in str(excinfo.value)


# --- the examples are the documentation --------------------------------------


@pytest.mark.parametrize("path", [
    "examples/mock_api/matrix.yaml",
    "examples/mcp_api/matrix.yaml",
    "examples/mcp_api/matrix_stdio.yaml",
    "examples/mcp_api/matrix_setup.yaml",
    "examples/injections/matrix.yaml",
    "examples/crapi/matrix.yaml",
])
def test_every_bundled_matrix_uses_the_module_layout(path):
    """A shipped example on the old layout would not load at all."""
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    matrix = load_matrix(os.path.join(root, path))

    assert matrix.resources, f"{path} declares no resources"


# --- the README examples are copy-pasteable ----------------------------------


def _readme_yaml_blocks():
    """Every fenced yaml block in the README, with its position for the message."""
    import os
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "README.md"), "r", encoding="utf-8") as handle:
        text = handle.read()
    return [
        (text[:m.start()].count("\n") + 1, m.group(1))
        for m in re.finditer(r"```yaml\n(.*?)```", text, re.DOTALL)
    ]


def test_every_readme_yaml_block_parses():
    """A fragment nobody can paste is worse than no example.

    `${VAR}` inside a *flow* mapping opens a nested mapping unless it is quoted,
    so `- { name: alice, token: ${T} }` is a YAML syntax error while the same
    thing in block style is fine. The README's headline subjects block had that
    shape and had never been parsed by anything.
    """
    import yaml

    broken = []
    for line, block in _readme_yaml_blocks():
        try:
            yaml.safe_load(block)
        except yaml.YAMLError as exc:
            broken.append(f"README.md:{line}: {str(exc).splitlines()[0]}")

    assert not broken, "unparseable yaml in the README:\n" + "\n".join(broken)


def test_no_readme_example_shows_the_flat_layout():
    """The documentation cannot demonstrate a file the loader now refuses."""
    import yaml

    stale = []
    for line, block in _readme_yaml_blocks():
        doc = yaml.safe_load(block)
        if not isinstance(doc, dict):
            continue
        for key in RELOCATED_KEYS:
            if key in doc:
                stale.append(f"README.md:{line}: '{key}' -> {RELOCATED_KEYS[key]}")

    assert not stale, "README examples still on the flat layout:\n" + "\n".join(stale)
