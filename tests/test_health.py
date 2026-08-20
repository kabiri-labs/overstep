"""Tests for the inconclusive-run verdict.

The property under test is that overstep never reports a clean result for a run
that proved nothing — an unreachable target or rejected credentials must not read
as "0 vulnerabilities".
"""
import pytest

from overstep.health import assess
from overstep.models import (
    Effect,
    McpInvocation,
    Observation,
    ResourceType,
    TestCase,
    Variant,
)


def _case(
    case_id: str,
    expected: Effect,
    mcp: McpInvocation = None,
    resource: str = "r",
) -> TestCase:
    return TestCase(
        id=case_id,
        resource=resource,
        subject="s",
        role="user",
        method="GET",
        path_template="/x/{id}",
        path="/x/1",
        variant=Variant.NA,
        expected=expected,
        resource_type=ResourceType.FUNCTION,
        transport="mcp" if mcp else "http",
        mcp=mcp,
    )


def _mcp(url: str = "http://127.0.0.1:9000/mcp") -> McpInvocation:
    return McpInvocation(kind="http", url=url, tool="t")


def _skipped(case_id: str) -> Observation:
    return Observation(
        test_id=case_id, status=0, effect=Effect.DENY, skipped=True, error="skipped"
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


def test_a_dead_stdio_server_is_a_delivery_failure():
    """A stdio call that times out or hits EOF yields status 0 with *no* error
    string (transports/mcp.py turns the empty message into status 0), so the
    status alone has to be the signal."""
    cases = [_case("a", Effect.DENY), _case("b", Effect.DENY)]
    obs = [
        Observation(test_id="a", status=0, effect=Effect.DENY),
        Observation(test_id="b", status=0, effect=Effect.DENY),
    ]

    health = assess(cases, obs)

    assert health.inconclusive
    assert health.transport_errors == 2
    assert any("never reached the target" in r for r in health.reasons)


def test_positive_controls_all_skipped_is_inconclusive():
    """--read-only can skip every expected-allow test, leaving no positive
    control: the negative results are then unverified, not clean."""
    cases = [_case("post", Effect.ALLOW), _case("get", Effect.DENY)]
    obs = [_skipped("post"), _delivered("get", Effect.DENY)]

    health = assess(cases, obs)

    assert health.inconclusive
    assert any("every expected-allow test was skipped" in r for r in health.reasons)


def test_an_all_negative_matrix_is_still_not_condemned():
    """No positive control was *planned*, so none can be missing — unchanged."""
    cases = [_case("a", Effect.DENY), _case("b", Effect.DENY)]
    obs = [_delivered("a", Effect.DENY), _delivered("b", Effect.DENY)]

    assert not assess(cases, obs).inconclusive


def test_a_healthy_target_cannot_mask_an_unreachable_one():
    """The regression this guards: aggregating over a mixed matrix let a busy
    HTTP target outvote an MCP server that answered nothing."""
    http_cases = [_case(f"h{i}", Effect.ALLOW) for i in range(6)]
    mcp_cases = [_case(f"m{i}", Effect.DENY, mcp=_mcp()) for i in range(4)]
    obs = [_delivered(f"h{i}", Effect.ALLOW) for i in range(6)]
    obs += [_undelivered(f"m{i}") for i in range(4)]

    health = assess(http_cases + mcp_cases, obs)

    # Globally only 4 of 10 failed — under the threshold — and the HTTP
    # positives passed, so the whole run used to read as conclusive.
    assert health.transport_errors / health.executed < 0.5
    assert health.inconclusive
    assert any("MCP server http://127.0.0.1:9000/mcp" in r for r in health.reasons)


def test_each_mcp_server_is_judged_on_its_own():
    up, down = _mcp("http://up:9000/mcp"), _mcp("http://down:9001/mcp")
    cases = [
        _case("u1", Effect.ALLOW, mcp=up),
        _case("u2", Effect.DENY, mcp=up),
        _case("d1", Effect.ALLOW, mcp=down),
    ]
    obs = [_delivered("u1", Effect.ALLOW), _delivered("u2", Effect.DENY), _undelivered("d1")]

    health = assess(cases, obs)

    assert health.inconclusive
    assert any("http://down:9001/mcp" in r for r in health.reasons)
    assert not any("http://up:9000/mcp" in r for r in health.reasons)


def test_a_stdio_server_is_named_by_its_command():
    """A local process has no URL, so the argv identifies it in the verdict."""
    stdio = McpInvocation(kind="stdio", command=["python", "server.py"], tool="t")
    cases = [_case("http-ok", Effect.ALLOW), _case("stdio-dead", Effect.ALLOW, mcp=stdio)]
    obs = [_delivered("http-ok", Effect.ALLOW), Observation(test_id="stdio-dead", status=0, effect=Effect.DENY)]

    health = assess(cases, obs)

    assert health.inconclusive
    assert any("MCP server 'python server.py'" in r for r in health.reasons)


def test_a_custom_transport_is_its_own_target():
    """The registry takes any transport name, and one that answers nothing must
    not be folded into HTTP where a healthy majority would outvote it."""
    http_cases = [_case(f"h{i}", Effect.ALLOW) for i in range(6)]
    custom = [
        TestCase(
            id=f"c{i}",
            resource="r",
            subject="s",
            role="user",
            method="GET",
            path_template="/x",
            path="/x",
            variant=Variant.NA,
            expected=Effect.DENY,
            resource_type=ResourceType.FUNCTION,
            transport="grpc",
        )
        for i in range(4)
    ]
    obs = [_delivered(f"h{i}", Effect.ALLOW) for i in range(6)]
    obs += [_undelivered(f"c{i}") for i in range(4)]

    health = assess(http_cases + custom, obs)

    assert health.transport_errors / health.executed < 0.5  # 40%, under the threshold
    assert health.inconclusive
    assert any("the 'grpc' transport" in r for r in health.reasons)


def test_a_single_target_verdict_is_not_prefixed():
    """The common case stays readable — no target label when there is only one."""
    cases = [_case("a", Effect.ALLOW)]
    obs = [_undelivered("a")]

    reason = assess(cases, obs).reasons[0]

    assert reason.startswith(("1 of 1", "none of"))


@pytest.mark.parametrize("ratio", [0.25, 0.75])
def test_threshold_is_tunable(ratio):
    cases = [_case(str(i), Effect.ALLOW) for i in range(4)]
    obs = [_undelivered("0")] + [_delivered(str(i), Effect.ALLOW) for i in range(1, 4)]

    # One error in four: condemned at a 0.25 threshold, tolerated at 0.75.
    assert assess(cases, obs, unreachable_ratio=ratio).inconclusive is (ratio == 0.25)


# --- one endpoint down behind a healthy target ------------------------------


def test_a_blacked_out_resource_condemns_the_run():
    """A healthy target can still hold an endpoint that answered nothing.

    The target ratio is deliberately blunt enough to survive a flaky timeout, so
    a single wedged route sits far below it. Its negative tests are recorded as
    denied — which is what the matrix expected — so they produce no finding and
    read exactly like probes that ran and found the endpoint sound.
    """
    cases = [
        _case("ok::allow", Effect.ALLOW, resource="healthy"),
        _case("ok::deny", Effect.DENY, resource="healthy"),
        _case("ok::deny2", Effect.DENY, resource="healthy"),
        _case("wedged::allow", Effect.ALLOW, resource="wedged"),
        _case("wedged::deny", Effect.DENY, resource="wedged"),
    ]
    obs = [
        _delivered("ok::allow", Effect.ALLOW),
        _delivered("ok::deny", Effect.DENY),
        _delivered("ok::deny2", Effect.DENY),
        _undelivered("wedged::allow"),
        _undelivered("wedged::deny"),
    ]

    health = assess(cases, obs)

    # 2 of 5 is below the target ratio, so the target itself is not condemned.
    assert health.transport_errors == 2
    assert health.inconclusive
    assert health.untested_resources == ["wedged"]
    assert any("resource 'wedged'" in r and "not tested" in r for r in health.reasons)
    # And the healthy resource is not dragged in with it.
    assert not any("healthy" in r for r in health.reasons)


def test_one_flaky_timeout_does_not_condemn_the_run():
    """The negative half, and the more important one.

    Condemning a run for a single lost probe would teach the reader to pass
    --allow-inconclusive permanently, which costs more than the check saves. A
    resource that got something through was tested; only one that got nothing
    through was not.
    """
    cases = [
        _case("r::allow", Effect.ALLOW),
        _case("r::deny", Effect.DENY),
        _case("r::deny2", Effect.DENY),
    ]
    obs = [
        _delivered("r::allow", Effect.ALLOW),
        _delivered("r::deny", Effect.DENY),
        _undelivered("r::deny2"),
    ]

    health = assess(cases, obs)

    assert not health.inconclusive
    assert health.reasons == []
    assert health.untested_resources == []
    # Silent is what it must not be: the loss is still counted.
    assert health.transport_errors == 1
    assert health.undelivered_negative == 1


def test_undelivered_negative_tests_are_counted_apart():
    """A lost negative test is the expensive kind: it leaves no trace at all."""
    cases = [
        _case("r::allow", Effect.ALLOW),
        _case("r::deny", Effect.DENY),
        _case("other::deny", Effect.DENY, resource="other"),
    ]
    obs = [
        _undelivered("r::allow"),
        _undelivered("r::deny"),
        _delivered("other::deny", Effect.DENY),
    ]

    health = assess(cases, obs)

    assert health.transport_errors == 3 - 1
    assert health.undelivered_negative == 1


def test_a_resource_on_an_unreachable_target_is_not_reported_twice():
    """An unreachable target denies everything by definition."""
    cases = [
        _case("a::allow", Effect.ALLOW, resource="a"),
        _case("b::deny", Effect.DENY, resource="b"),
    ]
    obs = [_undelivered("a::allow"), _undelivered("b::deny")]

    health = assess(cases, obs)

    assert health.inconclusive
    assert health.untested_resources == []
    assert len(health.reasons) == 1
    assert "unreachable" in health.reasons[0]


def test_a_healthy_run_reports_no_delivery_loss():
    cases = [_case("a", Effect.ALLOW), _case("b", Effect.DENY)]
    obs = [_delivered("a", Effect.ALLOW), _delivered("b", Effect.DENY)]

    health = assess(cases, obs)

    assert health.untested_resources == []
    assert (health.transport_errors, health.undelivered_negative) == (0, 0)


def test_a_skipped_resource_is_not_called_untested():
    """Not sending a request was the point; it is not a delivery failure."""
    cases = [
        _case("r::allow", Effect.ALLOW),
        _case("skip::deny", Effect.DENY, resource="skipped_res"),
    ]
    obs = [_delivered("r::allow", Effect.ALLOW), _skipped("skip::deny")]

    health = assess(cases, obs)

    assert health.untested_resources == []
    assert health.undelivered_negative == 0
