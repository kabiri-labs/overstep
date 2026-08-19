"""Tests for matrix validation and the OpenAPI/HAR scaffolders."""
import json

from overstep.modules.rest.har import load_resources as load_har, normalize_path
from overstep.modules.rest.openapi import load_resources as load_openapi
from overstep.matrix import Matrix
from overstep.models import ResourceType


def test_validate_flags_object_without_a_locator():
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x/{id}"}, "type": "object"}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    problems = m.validate_refs()
    assert any("must set 'owner'" in p for p in problems)


def test_validate_flags_unknown_policy_resource():
    m = Matrix(
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"ghost": {"allow": [{"role": "user"}]}},
    )
    assert any("unknown resource 'ghost'" in p for p in m.validate_refs())


def test_role_rank_orders_privilege():
    m = Matrix(roles=["anonymous", "user", "admin"], subjects=[], resources=[])
    assert m.role_rank("admin") > m.role_rank("user") > m.role_rank("anonymous")


def test_openapi_scaffold_guesses_object_type(tmp_path):
    spec = tmp_path / "api.yaml"
    spec.write_text(
        "openapi: 3.0.0\n"
        "info: { title: t, version: '1' }\n"
        "paths:\n"
        "  /users/{id}:\n"
        "    get: { summary: read }\n"
        "  /admin/ping:\n"
        "    get: { summary: ping }\n"
    )
    resources = {r.name: r for r in load_openapi(str(spec))}
    assert resources["get_users_id"].type == ResourceType.OBJECT
    assert resources["get_users_id"].owner == "id"
    assert resources["get_admin_ping"].type == ResourceType.FUNCTION


def test_har_normalizes_ids():
    assert normalize_path("/users/12345/orders/98") == "/users/{id}/orders/{id}"


def test_har_scaffold(tmp_path):
    har = {
        "log": {
            "entries": [
                {"request": {"method": "GET", "url": "http://x/users/42"}},
                {"request": {"method": "GET", "url": "http://x/users/77"}},  # folds with above
                {"request": {"method": "GET", "url": "http://x/health"}},
            ]
        }
    }
    f = tmp_path / "t.har"
    f.write_text(json.dumps(har))
    resources = load_har(str(f))
    names = {r.name for r in resources}
    assert "get_users_id" in names        # the two /users/N calls collapsed
    assert "get_health" in names
    assert len(resources) == 2


def test_validate_warns_when_no_two_subjects_own_different_objects():
    """The planner drops an other-probe it cannot make meaningful; validate says why."""
    from overstep.matrix import Matrix

    matrix = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"pid": "p-1"}},
            {"name": "carol", "role": "user", "token": "c", "attributes": {"pid": "p-1"}},
        ],
        resources=[
            {
                "name": "get_project",
                "request": {"method": "GET", "path": "/projects/{pid}"},
                "type": "object",
                "owner": "pid",
                "owner_attr": "pid",
            }
        ],
        policy={"get_project": {"allow": [{"role": "user", "scope": "own"}]}},
    )

    problems = matrix.validate_refs()

    assert any("no two subjects with different objects" in p for p in problems)
    assert any("p-1" in p for p in problems)


def test_validate_is_quiet_when_objects_differ():
    from overstep.matrix import Matrix

    matrix = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"pid": "p-1"}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"pid": "p-2"}},
        ],
        resources=[
            {
                "name": "get_project",
                "request": {"method": "GET", "path": "/projects/{pid}"},
                "type": "object",
                "owner": "pid",
                "owner_attr": "pid",
            }
        ],
        policy={"get_project": {"allow": [{"role": "user", "scope": "own"}]}},
    )

    assert not any("different objects" in p for p in matrix.validate_refs())
