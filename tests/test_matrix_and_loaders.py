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


def _conditioned(condition: str) -> Matrix:
    """One resource guarded by ``condition``, with two real attributes to typo."""
    return Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "attributes": {"user_id": "u1", "department": "eng"}},
            {"name": "root", "role": "admin", "attributes": {"user_id": "u9", "department": "eng"}},
        ],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"r": {"allow": [{"role": "admin"}, {"role": "user", "condition": condition}]}},
    )


def test_validate_flags_a_condition_naming_an_attribute_nobody_declares():
    """The typo that used to grant access, caught before the run.

    `subject.dept` for an attribute really called `department` evaluated to
    `None == None` and granted, which turned the negative test the resource
    needed into a positive one and left a real broken endpoint unprobed.
    """
    problems = _conditioned("subject.dept == target.dept").validate_refs()
    assert any("subject.dept" in p and "no subject declares" in p for p in problems)
    assert any("target.dept" in p for p in problems)


def test_validate_accepts_a_condition_only_some_subjects_can_satisfy():
    """Subjects are allowed to differ; a narrowing rule is not a typo."""
    m = _conditioned("subject.department == target.department")
    assert not [p for p in m.validate_refs() if "department" in p]


def test_validate_flags_a_condition_that_does_not_parse():
    assert any("does not parse" in p for p in _conditioned("subject.a ==").validate_refs())


def test_validate_flags_a_condition_naming_something_that_is_not_an_identity():
    problems = _conditioned("request.path == '/x'").validate_refs()
    assert any("'request'" in p and "use 'subject' or 'target'" in p for p in problems)


def test_a_refused_condition_still_grants_nothing():
    """The negative half: reporting the typo must not start honouring it."""
    from overstep.models import Effect
    from overstep.planner import plan

    cases = {c.id: c for c in plan(_conditioned("subject.dept == target.dept"))}
    assert cases["r::alice::na"].expected == Effect.DENY
    # The admin rule carries no condition, so it is untouched by any of this.
    assert cases["r::root::na"].expected == Effect.ALLOW


def test_unreadable_status_entries_are_refused_at_load():
    """A spec the matcher cannot read matches nothing, so every response reads
    as deny and every negative test passes for the wrong reason."""
    import pytest

    for bad in (["2OO"], ["20x"], ["banana"], [2000], ["299-200"]):
        with pytest.raises(Exception, match="not status specifications"):
            Matrix(
                modules={"rest": {"base_url": "http://api.test", "access": {"allow_status": bad}}},
                subjects=[{"name": "a", "role": "user"}],
                resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
                policy={"r": {"allow": [{"role": "user"}]}},
            )


def test_readable_status_entries_still_load():
    m = Matrix(
        modules={
            "rest": {
                "base_url": "http://api.test",
                "access": {"allow_status": ["2xx", 200, "201-204", "302"]},
            }
        },
        subjects=[{"name": "a", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    assert m.access.allow_status == ["2xx", 200, "201-204", "302"]


def _matrix_with_access(access: dict) -> dict:
    return {
        "modules": {"rest": {"base_url": "http://api.test", "access": access}},
        "subjects": [{"name": "a", "role": "user"}],
        "resources": [{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        "policy": {"r": {"allow": [{"role": "user"}]}},
    }


def test_a_matcher_with_no_route_to_allow_is_refused():
    """`allow_status: []` is read correctly and matches nothing.

    Not garbage the parser skips — a list it reads and that no status satisfies.
    Every response then reads as denied, every negative test passes for the wrong
    reason, and an all-negative matrix has no positive control whose failure
    would give it away.
    """
    import pytest

    with pytest.raises(Exception, match="can never allow"):
        Matrix(**_matrix_with_access({"allow_status": []}))
    # treat_redirect_as: status falls through to the empty list, so it is no
    # rescue either.
    with pytest.raises(Exception, match="can never allow"):
        Matrix(**_matrix_with_access({"allow_status": [], "treat_redirect_as": "status"}))
    # A deny signal is not a route to allow.
    with pytest.raises(Exception, match="can never allow"):
        Matrix(**_matrix_with_access({"allow_status": [], "deny_body_regex": "denied"}))


def test_any_surviving_route_to_allow_is_accepted():
    """The condition is exact, so nothing legitimate is refused."""
    m = Matrix(**_matrix_with_access({"allow_status": [], "allow_body_regex": "\"ok\":true"}))
    assert m.access.allow_status == []
    assert Matrix(**_matrix_with_access(
        {"allow_status": [], "treat_redirect_as": "allow"}
    )).access.treat_redirect_as == "allow"
    assert Matrix(**_matrix_with_access({"allow_status": ["2xx"]})).access.allow_status == ["2xx"]
    # And the default matcher, which is what almost every matrix uses.
    assert Matrix(**_matrix_with_access({})).access.allow_status


def test_the_mcp_matcher_is_not_subject_to_this():
    """MCP falls through to allow, so an empty deny_status is not a dead matcher.

    `deny_status: []` is documented as the setting for a server that reports
    denials in-band under a non-2xx status of its own.
    """
    from overstep.models import McpMatcher

    assert McpMatcher(deny_status=[]).deny_status == []
