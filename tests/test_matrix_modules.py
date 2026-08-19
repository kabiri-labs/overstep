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
    "examples/rest_api/matrix.yaml",
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


# --- a dropped key is never a comment ----------------------------------------
#
# Both cases below came from review of this change. They are the same failure
# mode the split was written to remove, found one level deeper than it was fixed.


def test_a_typo_inside_the_probes_block_is_refused(tmp_path):
    """The most expensive typo in the file, and it used to load.

    `tool_enumeraton: true` left the probe off and the run reported clean —
    a security check silently not performed, which is the exact shape of finding
    this tool exists to catch in other people's systems.
    """
    path = _write(
        tmp_path,
        "roles: [user]\n"
        "modules:\n"
        "  mcp:\n"
        "    servers: [{name: docs, url: 'http://x/mcp'}]\n"
        "    probes: {tool_enumeraton: true}\n"
        "subjects: [{name: a, role: user, token: t}]\n"
        "resources: [{name: r, call: {server: docs, tool: t}, type: function}]\n"
        "policy: {r: {allow: [{role: user}]}}\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    assert "tool_enumeraton" in str(excinfo.value)


@pytest.mark.parametrize("model_path", [
    "modules", "modules.rest", "modules.mcp", "modules.mcp.probes",
])
def test_every_module_configuration_model_forbids_extras(model_path):
    """Asserted per model, so a block added later cannot quietly stay permissive."""
    from overstep.matrix import Matrix as _M

    model = _M.model_fields["modules"].annotation
    for step in model_path.split(".")[1:]:
        model = model.model_fields[step].annotation

    assert model.model_config.get("extra") == "forbid", f"{model_path} accepts unknown keys"


def test_a_resource_that_still_declares_transport_is_told_to_delete_it(tmp_path):
    """`extra=forbid` alone refuses it; this says what to write instead.

    Without the message the failure is "extra inputs are not permitted", which
    does not tell somebody holding last release's matrix that the right fix is to
    delete the line rather than to find the key's new home.
    """
    path = _write(
        tmp_path,
        "roles: [user]\n"
        "modules: {rest: {base_url: 'http://x'}}\n"
        "subjects: [{name: a, role: user, token: t}]\n"
        "resources: [{name: r, request: {method: GET, path: /r}, type: function,\n"
        "             transport: carrier-pigeon}]\n"
        "policy: {r: {allow: [{role: user}]}}\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    message = str(excinfo.value)
    assert "read off its body" in message
    assert "deleted" in message


def test_a_resource_that_still_spells_the_override_mcp_access_is_redirected(tmp_path):
    path = _write(
        tmp_path,
        "roles: [user]\n"
        "modules:\n"
        "  mcp:\n"
        "    servers: [{name: docs, url: 'http://x/mcp'}]\n"
        "subjects: [{name: a, role: user, token: t}]\n"
        "resources: [{name: r, call: {server: docs, tool: t}, type: function,\n"
        "             mcp_access: {is_error_is_deny: false}}]\n"
        "policy: {r: {allow: [{role: user}]}}\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    assert "spelled 'access'" in str(excinfo.value)


def test_no_matrix_facing_model_accepts_unknown_keys():
    """The rule, applied to every model a matrix file can reach.

    Enumerated by walking the models rather than listed by hand: a model added
    later is covered the day it is added, which a hand-written list would not be.
    """
    from overstep import models as m
    from overstep.matrix import Matrix

    permissive = []
    seen = set()

    def walk(model):
        if model in seen or not hasattr(model, "model_fields"):
            return
        seen.add(model)
        if model.model_config.get("extra") != "forbid":
            permissive.append(model.__name__)
        for field in model.model_fields.values():
            for arg in (getattr(field.annotation, "__args__", None) or (field.annotation,)):
                walk(arg)
                for inner in (getattr(arg, "__args__", None) or ()):
                    walk(inner)

    walk(Matrix)

    assert not permissive, f"these accept unknown keys: {sorted(permissive)}"


# --- one way to name the object identifier -----------------------------------


@pytest.mark.parametrize("body,location", [
    ({"request": {"method": "GET", "path": "/u/{id}"}}, "path"),
    ({"call": {"server": "docs", "tool": "read"}}, "mcp_argument"),
    ({"read": {"server": "docs", "uri": "doc://{doc_id}"}}, "mcp_resource_uri"),
])
def test_owner_goes_where_the_body_carries_it(body, location):
    """One key, and the place follows from what the resource sends.

    It was three — `owner_param`, `owner_arg`, `owner_uri` — one per place, each
    named for a transport. They expressed a single idea and made the author
    restate what the body already said, in a name that could contradict it.
    """
    resource = Resource(name="r", type="object", owner="doc_id", **body)

    injections = resource.effective_injections()

    assert [i.location.value for i in injections] == [location]
    assert [i.selector for i in injections] == ["doc_id"]


@pytest.mark.parametrize("legacy", ["owner_param", "owner_arg", "owner_uri"])
def test_each_removed_locator_says_what_to_write_instead(tmp_path, legacy):
    """`extra=forbid` refuses them; this tells the reader the new spelling."""
    path = _write(
        tmp_path,
        "roles: [user]\n"
        "modules: {rest: {base_url: 'http://x'}}\n"
        "subjects: [{name: a, role: user, token: t}]\n"
        f"resources: [{{name: r, request: {{method: GET, path: '/u/{{id}}'}},\n"
        f"             type: object, {legacy}: id}}]\n"
        "policy: {r: {allow: [{role: user}]}}\n",
    )

    with pytest.raises(MatrixError) as excinfo:
        load_matrix(path)

    message = str(excinfo.value)
    assert legacy in message
    assert "spelled 'owner'" in message


def test_explicit_injections_still_win_over_the_shorthand():
    """`owner` is the common case; an id somewhere unusual still says so.

    A query string, a header, or two places at once cannot be inferred from the
    body, which is why the general model stays.
    """
    resource = Resource(
        name="r", type="object",
        request={"method": "GET", "path": "/orders"},
        owner="ignored",
        ownership={"injections": [
            {"location": "query", "selector": "order_id"},
            {"location": "header", "selector": "X-Tenant", "owner_attr": "tenant"},
        ]},
    )

    injections = resource.effective_injections()

    assert [i.location.value for i in injections] == ["query", "header"]
    assert [i.selector for i in injections] == ["order_id", "X-Tenant"]


def test_a_validation_failure_names_the_place_to_fill_in():
    """"Set owner" is not actionable without saying where it goes."""
    rest = Matrix(
        roles=["user"], subjects=[{"name": "a", "role": "user", "token": "t"}],
        modules={"rest": {"base_url": "http://x"}},
        resources=[{"name": "r", "request": {"method": "GET", "path": "/u/{id}"},
                    "type": "object"}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    mcp = Matrix(
        roles=["user"], subjects=[{"name": "a", "role": "user", "token": "t"}],
        modules={"mcp": {"servers": [{"name": "docs", "url": "http://x/mcp"}]}},
        resources=[{"name": "r", "read": {"server": "docs", "uri": "doc://{d}"},
                    "type": "object"}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )

    assert any("path parameter" in p for p in rest.validate_refs())
    assert any("URI placeholder" in p for p in mcp.validate_refs())
