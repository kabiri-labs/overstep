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
