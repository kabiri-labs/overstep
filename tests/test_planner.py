"""Tests for matrix -> test case generation."""
from overstep.models import Effect, ResourceType, Variant
from overstep.planner import make_test_id, plan


def _by_id(cases):
    return {c.id: c for c in cases}


def test_object_resource_expands_to_self_and_other(matrix):
    cases = _by_id(plan(matrix))

    alice_self = cases["get_user::alice::self"]
    assert alice_self.variant == Variant.SELF
    assert alice_self.path == "/users/u1"        # own id substituted
    assert alice_self.expected == Effect.ALLOW   # positive test

    alice_other = cases["get_user::alice::other"]
    assert alice_other.variant == Variant.OTHER
    assert alice_other.path != "/users/u1"       # someone else's id
    assert alice_other.expected == Effect.DENY    # negative test (BOLA probe)


def test_admin_reads_any_object(matrix):
    cases = _by_id(plan(matrix))
    assert cases["get_user::root::other"].expected == Effect.ALLOW


def test_function_resource_is_single_variant(matrix):
    cases = _by_id(plan(matrix))
    assert cases["admin_list::alice::na"].variant == Variant.NA
    assert cases["admin_list::alice::na"].expected == Effect.DENY   # user denied
    assert cases["admin_list::root::na"].expected == Effect.ALLOW   # admin allowed


def test_anonymous_gets_only_negative_object_test(matrix):
    cases = plan(matrix)
    anon_ids = [c.id for c in cases if c.subject == "anon"]
    # anon has no user_id, so no SELF variant is generated for the object resource
    assert "get_user::anon::self" not in anon_ids
    assert "get_user::anon::other" in anon_ids


def test_make_test_id_is_stable():
    assert make_test_id("get_user", "alice", Variant.OTHER) == "get_user::alice::other"


def test_condition_narrows_allow(matrix):
    # Replace the policy with a tenant-isolation condition and confirm it is honoured.
    from overstep.models import AllowRule

    matrix.policy["get_user"].allow = [
        AllowRule(role="user", scope="any", condition="subject.tenant == target.tenant")
    ]
    cases = _by_id(plan(matrix))
    # alice (t1) reaching bob (t2) -> condition false -> deny
    assert cases["get_user::alice::other"].expected == Effect.DENY
    # alice reaching her own object -> condition true -> allow
    assert cases["get_user::alice::self"].expected == Effect.ALLOW


def _shared_object_matrix(same_id: str = "p-1"):
    """Two peers pointing at one object, plus an outsider with a different one."""
    from overstep.matrix import Matrix

    return Matrix(
        base_url="http://testserver",
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"pid": same_id}},
            {"name": "carol", "role": "user", "token": "c", "attributes": {"pid": same_id}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"pid": "p-2"}},
        ],
        resources=[
            {
                "name": "get_project",
                "request": {"method": "GET", "path": "/projects/{pid}"},
                "type": "object",
                "owner_param": "pid",
                "owner_attr": "pid",
            }
        ],
        policy={"get_project": {"allow": [{"role": "user", "scope": "own"}]}},
    )


def test_other_probe_never_targets_the_subjects_own_object():
    """Peers can share an object; pairing a subject with one produced an OTHER
    probe identical to its own SELF probe, testing nothing."""
    cases = plan(_shared_object_matrix())

    for case in cases:
        if case.variant == Variant.OTHER:
            twin = [
                c for c in cases
                if c.subject == case.subject and c.resource == case.resource
                and c.variant == Variant.SELF
            ]
            assert not twin or twin[0].path != case.path, (
                f"{case.subject}'s other-probe re-sends its own request: {case.path}"
            )


def test_a_shared_object_peer_is_skipped_for_a_real_victim():
    """alice and carol share p-1, so bob's p-2 is the only true cross-owner target."""
    cases = plan(_shared_object_matrix())

    others = {c.subject: c.path for c in cases if c.variant == Variant.OTHER}

    assert others["alice"] == "/projects/p-2"
    assert others["carol"] == "/projects/p-2"
    assert others["bob"] in ("/projects/p-1",)


def test_no_other_probe_when_every_subject_shares_one_object():
    """With nothing to compare against, the probe is dropped rather than faked."""
    from overstep.matrix import Matrix

    matrix = Matrix(
        base_url="http://testserver",
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
                "owner_param": "pid",
                "owner_attr": "pid",
            }
        ],
        policy={"get_project": {"allow": [{"role": "user", "scope": "own"}]}},
    )

    cases = plan(matrix)

    assert {c.variant for c in cases} == {Variant.SELF}
    assert len(cases) == 2


def test_distinct_objects_still_pair_normally(matrix):
    """The ordinary case is untouched: alice probes bob's object."""
    others = [c for c in plan(matrix) if c.variant == Variant.OTHER and c.subject == "alice"]

    assert others and all(c.path == "/users/u2" for c in others)
