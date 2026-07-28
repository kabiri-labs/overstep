"""Tests for the inconclusive-run verdict.

The property under test is that overstep never reports a clean result for a run
that proved nothing — an unreachable target or rejected credentials must not read
as "0 vulnerabilities".
"""
import pytest

from overstep.health import assess
from overstep.models import Effect, Observation, ResourceType, TestCase, Variant


def _case(case_id: str, expected: Effect) -> TestCase:
    return TestCase(
        id=case_id,
        resource="r",
        subject="s",
        role="user",
        method="GET",
        path_template="/x/{id}",
        path="/x/1",
        variant=Variant.NA,
        expected=expected,
        resource_type=ResourceType.FUNCTION,
    )


def _delivered(case_id: str, effect: Effect) -> Observation:
    status = 200 if effect == Effect.ALLOW else 403
    return Observation(test_id=case_id, status=status, effect=effect)


def _undelivered(case_id: str) -> Observation:
    return Observation(
        test_id=case_id, status=0, effect=Effect.DENY, error="All connection attempts failed"
    )


def test_healthy_run_is_conclusive():
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]
    obs = [_delivered("a", Effect.ALLOW), _delivered("b", Effect.DENY)]

    health = assess(cases, obs)

    assert not health.inconclusive
    assert health.reasons == []
    assert (health.executed, health.transport_errors) == (2, 0)
    assert (health.positive_allowed, health.positive_tests) == (1, 1)


def test_unreachable_target_is_inconclusive():
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]
    obs = [_undelivered("a"), _undelivered("b")]

    health = assess(cases, obs)

    assert health.inconclusive
    assert health.transport_errors == 2
    assert any("never reached the target" in r for r in health.reasons)
    # The underlying transport error is quoted so the cause is actionable.
    assert any("All connection attempts failed" in r for r in health.reasons)


def test_one_flaky_request_does_not_condemn_a_run():
    """A single timeout among healthy traffic is noise, not an unreachable target."""
    cases = [_case(str(i), Effect.ALLOW) for i in range(5)]
    obs = [_undelivered("0")] + [_delivered(str(i), Effect.ALLOW) for i in range(1, 5)]

    health = assess(cases, obs)

    assert not health.inconclusive
    assert health.transport_errors == 1


def test_error_ratio_at_the_threshold_is_inconclusive():
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.ALLOW)]
    obs = [_undelivered("a"), _delivered("b", Effect.ALLOW)]

    assert assess(cases, obs).inconclusive


def test_rejected_credentials_are_inconclusive():
    """Requests arrive, but nothing the matrix expects to be allowed is."""
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.ALLOW), _case("c", Effect.DENY)]
    obs = [
        _delivered("a", Effect.DENY),
        _delivered("b", Effect.DENY),
        _delivered("c", Effect.DENY),
    ]

    health = assess(cases, obs)

    assert health.inconclusive
    assert health.positive_allowed == 0 and health.positive_tests == 2
    assert any("credentials or the matrix are wrong" in r for r in health.reasons)


def test_partial_positive_success_is_conclusive():
    """One accepted identity is enough to prove the run was really exercised."""
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.ALLOW)]
    obs = [_delivered("a", Effect.ALLOW), _delivered("b", Effect.DENY)]

    assert not assess(cases, obs).inconclusive


def test_a_matrix_with_no_positive_tests_is_not_condemned():
    """An all-negative matrix can't be judged by its positive tests."""
    cases = [_case("a", Effect.DENY), _case("b", Effect.DENY)]
    obs = [_delivered("a", Effect.DENY), _delivered("b", Effect.DENY)]

    assert not assess(cases, obs).inconclusive


def test_everything_skipped_is_inconclusive():
    cases = [_case("a", Effect.ALLOW)]
    obs = [Observation(test_id="a", status=0, effect=Effect.DENY, skipped=True, error="skipped")]

    health = assess(cases, obs)

    assert health.inconclusive
    assert health.executed == 0
    assert any("every planned test was skipped" in r for r in health.reasons)


def test_skipped_tests_do_not_count_as_transport_errors():
    """--read-only skips carry status 0 too; they are deliberate, not failures."""
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]
    obs = [
        _delivered("a", Effect.ALLOW),
        Observation(test_id="b", status=0, effect=Effect.DENY, skipped=True, error="skipped"),
    ]

    health = assess(cases, obs)

    assert not health.inconclusive
    assert health.executed == 1 and health.transport_errors == 0


def test_mcp_jsonrpc_error_is_a_denial_not_a_delivery_failure():
    """An MCP denial sets `error` but carries a real HTTP status — that is a deny."""
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]
    obs = [
        _delivered("a", Effect.ALLOW),
        Observation(test_id="b", status=200, effect=Effect.DENY, error="permission denied"),
    ]

    health = assess(cases, obs)

    assert not health.inconclusive
    assert health.transport_errors == 0


@pytest.mark.parametrize("ratio", [0.25, 0.75])
def test_threshold_is_tunable(ratio):
    cases = [_case(str(i), Effect.ALLOW) for i in range(4)]
    obs = [_undelivered("0")] + [_delivered(str(i), Effect.ALLOW) for i in range(1, 4)]

    # One error in four: condemned at a 0.25 threshold, tolerated at 0.75.
    assert assess(cases, obs, unreachable_ratio=ratio).inconclusive is (ratio == 0.25)
