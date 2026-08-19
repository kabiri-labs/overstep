"""Tests for the cross-owner probe coverage measurement.

The measurement answers the question a finding count cannot: when a run reports
no BOLA, how much of the declared object surface was it actually able to ask
about?
"""
from overstep.coverage import assess
from overstep.matrix import Matrix
from overstep.models import Effect, Variant
from overstep.planner import plan

OBJECT_RESOURCE = {
    "name": "get_user",
    "request": {"method": "GET", "path": "/users/{id}"},
    "type": "object",
    "owner": "id",
    "owner_attr": "user_id",
}


def _matrix(*subjects, resources=(OBJECT_RESOURCE,)):
    return Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user", "admin"],
        subjects=list(subjects),
        resources=list(resources),
        policy={r["name"]: {"allow": [{"role": "user", "scope": "own"}]} for r in resources},
    )


def test_distinct_objects_count_as_probed():
    m = _matrix(
        {"name": "a", "role": "user", "token": "1", "attributes": {"user_id": "u1"}},
        {"name": "b", "role": "user", "token": "2", "attributes": {"user_id": "u2"}},
    )
    coverage = assess(m, plan(m))

    assert (coverage.object_resources, coverage.probed) == (1, 1)
    assert coverage.unprobed == []
    assert coverage.complete


def test_shared_objects_leave_the_resource_unprobed():
    """The planner drops the probe rather than faking it; the count must say so."""
    m = _matrix(
        {"name": "a", "role": "user", "token": "1", "attributes": {"user_id": "u1"}},
        {"name": "b", "role": "user", "token": "2", "attributes": {"user_id": "u1"}},
    )
    coverage = assess(m, plan(m))

    assert (coverage.object_resources, coverage.probed) == (1, 0)
    assert coverage.unprobed == ["get_user"]
    assert not coverage.complete


def test_a_victimless_other_probe_does_not_count_as_coverage():
    """The over-count this measurement exists to avoid.

    When nobody can resolve an object the planner still emits an OTHER case so
    the endpoint is exercised, but it reaches for a default id belonging to no
    subject. Counting the variant alone would report full coverage for a
    resource whose ownership was never tested.
    """
    resource = dict(OBJECT_RESOURCE, owner_attr="order_id")
    m = _matrix(
        {"name": "a", "role": "user", "token": "1", "attributes": {"user_id": "u1"}},
        {"name": "b", "role": "user", "token": "2", "attributes": {"user_id": "u2"}},
        resources=(resource,),
    )
    cases = plan(m)

    assert any(c.variant == Variant.OTHER for c in cases), "the OTHER case is still planned"
    assert all(c.victim is None for c in cases), "but it reaches for nobody's object"
    assert assess(m, cases).unprobed == ["get_user"]


def test_a_resource_nobody_can_reach_is_still_counted():
    """Counting from the cases alone would drop the worst offenders entirely."""
    m = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user", "admin"],
        subjects=[{"name": "a", "role": "admin", "token": "1"}],
        resources=[OBJECT_RESOURCE],
        policy={},
    )
    coverage = assess(m, [])

    assert (coverage.object_resources, coverage.probed) == (1, 0)
    assert coverage.unprobed == ["get_user"]


def test_function_resources_are_not_part_of_the_object_surface():
    m = Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user", "admin"],
        subjects=[{"name": "a", "role": "admin", "token": "1"}],
        resources=[{"name": "admin_list", "request": {"method": "GET", "path": "/admin"}, "type": "function"}],
        policy={"admin_list": {"allow": [{"role": "admin"}]}},
    )
    coverage = assess(m, plan(m))

    assert coverage.object_resources == 0
    assert coverage.ratio == 1.0, "a matrix with no object surface is not 0% covered"


def test_ratio_reports_the_probed_share(matrix):
    """The shared fixture: alice and bob own different objects, root differs again."""
    coverage = assess(matrix, plan(matrix))

    assert coverage.object_resources == 1
    assert coverage.ratio == 1.0


def test_victim_names_the_subject_whose_object_is_reached_for():
    m = _matrix(
        {"name": "a", "role": "user", "token": "1", "attributes": {"user_id": "u1"}},
        {"name": "b", "role": "user", "token": "2", "attributes": {"user_id": "u2"}},
    )
    others = [c for c in plan(m) if c.variant == Variant.OTHER]

    assert others
    for case in others:
        assert case.victim is not None and case.victim != case.subject


def test_self_and_function_cases_carry_no_victim(matrix):
    for case in plan(matrix):
        if case.variant != Variant.OTHER:
            assert case.victim is None


def test_adding_the_victim_field_did_not_change_any_test_id(matrix):
    """Test ids anchor baselines and waivers, so they are a stability contract."""
    ids = {c.id for c in plan(matrix)}

    assert "get_user::alice::self" in ids
    assert "get_user::alice::other" in ids
    # The victim suffix stays reserved for subjects that probe more than one
    # object, which is what `probe_victims: all` turns on.
    assert not any("@" in test_id for test_id in ids)


def test_coverage_reaches_the_run_result_and_the_summary():
    from overstep.models import Observation, RunResult
    from overstep.report import summarize

    m = _matrix(
        {"name": "a", "role": "user", "token": "1", "attributes": {"user_id": "u1"}},
        {"name": "b", "role": "user", "token": "2", "attributes": {"user_id": "u1"}},
    )
    cases = plan(m)
    result = RunResult(
        base_url="http://t",
        cases=cases,
        observations=[Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases],
        coverage=assess(m, cases),
    )
    s = summarize(result)

    assert s["object_resources"] == 1
    assert s["object_resources_probed"] == 0
    assert s["object_resources_unprobed"] == ["get_user"]


def test_a_result_built_without_coverage_still_works():
    """Backward compatibility: the field defaults to an empty, honest verdict."""
    from overstep.models import RunResult

    result = RunResult(base_url="http://t")

    assert result.coverage.object_resources == 0
    assert result.coverage.complete
