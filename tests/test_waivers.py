"""Tests for waivers: accepting known findings without disabling gating."""
import datetime

import pytest

from overstep.models import Effect, Finding, Observation, Variant, VulnClass
from overstep.waivers import Waiver, WaiverError, apply_waivers, load_waivers


def _finding(test_id="get_user::alice::other", vuln=VulnClass.BOLA) -> Finding:
    return Finding(
        test_id=test_id,
        vuln_class=vuln,
        severity="high",
        resource="get_user",
        subject="alice",
        role="user",
        method="GET",
        path="/users/u2",
        expected=Effect.DENY,
        observed=Effect.ALLOW,
        status=200,
        variant=Variant.OTHER,
        detail="bola",
        evidence=Observation(test_id=test_id, status=200, effect=Effect.ALLOW),
    )


def _future() -> str:
    return (datetime.date.today() + datetime.timedelta(days=30)).isoformat()


def _past() -> str:
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def test_waiver_removes_matching_finding_from_active():
    findings = [_finding()]
    waivers = [Waiver(id="get_user::alice::other", reason="accepted risk", expires=_future())]
    active, waived, warnings = apply_waivers(findings, waivers)
    assert active == []
    assert len(waived) == 1
    assert waived[0].test_id == "get_user::alice::other"
    assert warnings == []


def test_waiver_matches_by_vuln_class_when_given():
    findings = [_finding()]
    # A waiver scoped to a different class must not suppress a BOLA.
    waivers = [Waiver(id="get_user::alice::other", vuln_class="BFLA", reason="x", expires=_future())]
    active, waived, _ = apply_waivers(findings, waivers)
    assert len(active) == 1
    assert waived == []


def test_expired_waiver_does_not_suppress_and_warns():
    findings = [_finding()]
    waivers = [Waiver(id="get_user::alice::other", reason="stale", expires=_past())]
    active, waived, warnings = apply_waivers(findings, waivers)
    assert len(active) == 1        # finding re-surfaces
    assert waived == []
    assert any("expired" in w for w in warnings)


def test_waiver_without_expiry_is_permanent():
    findings = [_finding()]
    waivers = [Waiver(id="get_user::alice::other", reason="by design")]
    active, waived, warnings = apply_waivers(findings, waivers)
    assert active == []
    assert len(waived) == 1


def test_non_matching_waiver_is_left_active():
    findings = [_finding()]
    waivers = [Waiver(id="some::other::case", reason="x", expires=_future())]
    active, waived, _ = apply_waivers(findings, waivers)
    assert len(active) == 1
    assert waived == []


def test_load_waivers_reads_yaml(tmp_path):
    p = tmp_path / "waivers.yaml"
    p.write_text(
        "waivers:\n"
        "  - id: get_user::alice::other\n"
        "    vuln_class: BOLA\n"
        "    reason: accepted for launch\n"
        f"    expires: {_future()}\n"
    )
    waivers = load_waivers(str(p))
    assert len(waivers) == 1
    assert waivers[0].id == "get_user::alice::other"
    assert waivers[0].reason == "accepted for launch"


def test_load_waivers_rejects_entry_without_reason(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("waivers:\n  - id: x::y::z\n")
    with pytest.raises(WaiverError):
        load_waivers(str(p))


def _finding(test_id: str = "get_user::alice::other") -> Finding:
    return Finding(
        test_id=test_id,
        vuln_class=VulnClass.BOLA,
        severity="high",
        resource="get_user",
        subject="alice",
        role="user",
        method="GET",
        path="/users/u2",
        expected=Effect.DENY,
        observed=Effect.ALLOW,
        status=200,
        variant=Variant.OTHER,
        detail="d",
        evidence=Observation(test_id=test_id, status=200, effect=Effect.ALLOW),
    )


def test_a_waiver_that_matches_nothing_is_reported():
    """It is safe and silent, and the silence is the defect.

    The finding it was aimed at stays active and still fails the gate — the safe
    direction — but the two things a non-matching waiver means both need saying.
    Either the id is a typo and the risk somebody signed off on is not actually
    waived, or the finding is fixed and an accepted risk with nothing behind it
    is sitting in version control until someone re-reads it and believes it.
    """
    waiver = Waiver(id="get_user::alice::othr", reason="typo in the id")
    active, waived, warnings = apply_waivers([_finding()], [waiver])

    assert len(active) == 1 and waived == []
    assert any("matched no finding" in w and "othr" in w for w in warnings)


def test_a_waiver_that_matches_is_not_reported():
    waiver = Waiver(id="get_user::alice::other", reason="accepted")
    active, waived, warnings = apply_waivers([_finding()], [waiver])

    assert active == [] and len(waived) == 1
    assert warnings == []


def test_an_expired_waiver_is_not_also_called_unmatched():
    """It found its finding; it just no longer suppresses it.

    Two notes about one entry, one saying it expired and one saying it matched
    nothing, would contradict each other.
    """
    waiver = Waiver(
        id="get_user::alice::other", reason="lapsed", expires=datetime.date(2020, 1, 1)
    )
    active, waived, warnings = apply_waivers([_finding()], [waiver])

    assert len(active) == 1 and waived == []
    assert any("expired" in w for w in warnings)
    assert not any("matched no finding" in w for w in warnings)


def test_unmatched_waivers_stay_quiet_when_the_run_proved_nothing():
    """On an unreachable target no finding exists for any waiver to match.

    Saying each one may be fixed would be the tool asserting something it never
    observed, on top of a verdict that already says the run means nothing.
    """
    waiver = Waiver(id="get_user::alice::other", reason="accepted")
    _, _, warnings = apply_waivers([], [waiver], report_unmatched=False)
    assert warnings == []

    _, _, loud = apply_waivers([], [waiver], report_unmatched=True)
    assert any("matched no finding" in w for w in loud)


def _pipeline_matrix():
    from overstep.matrix import Matrix

    return Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"user_id": "u2"}},
        ],
        resources=[{
            "name": "get_user",
            "request": {"method": "GET", "path": "/users/{id}"},
            "type": "object", "owner": "id", "owner_attr": "user_id",
        }],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )


@pytest.mark.parametrize(
    "delivered, expect_warning",
    [(True, True), (False, False)],
    ids=["a run that happened warns", "a run that proved nothing stays quiet"],
)
def test_the_pipeline_decides_whether_an_unmatched_waiver_is_worth_reporting(
    delivered, expect_warning
):
    """The wiring, not just the rule.

    `apply_waivers` takes the decision as an argument, so it can be unit-tested
    either way and still be wired to a constant. This is the test that fails if
    the pipeline stops asking the health verdict.
    """
    from overstep.pipeline import run_pipeline

    matrix = _pipeline_matrix()

    def executor(base_url, subjects, cases, **kwargs):
        if delivered:
            return [
                Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases
            ]
        # status 0 is what every transport reserves for a delivery failure.
        return [
            Observation(test_id=c.id, status=0, effect=Effect.DENY, error="unreachable")
            for c in cases
        ]

    result = run_pipeline(
        matrix,
        waivers=[Waiver(id="get_user::alice::nope", reason="wrong id")],
        executor=executor,
        authenticator=lambda *a, **k: None,
    )

    assert result.health.inconclusive is not delivered
    unmatched = [w for w in result.warnings if "matched no finding" in w]
    assert bool(unmatched) is expect_warning


def test_two_waivers_sharing_an_id_are_tracked_apart():
    """One test_id really can carry two findings — a vuln and its drift entry —
    so a file can hold two entries with the same id and different scopes.

    Keying the match on the id alone let the entry that matched vouch for the
    mistyped one beside it, which is the exact silence this warning exists to
    remove, one level down.
    """
    waivers = [
        Waiver(id="get_user::alice::other", vuln_class="BOLA", reason="accepted"),
        Waiver(id="get_user::alice::other", vuln_class="BFLA", reason="obsolete scope"),
    ]
    active, waived, warnings = apply_waivers([_finding()], waivers)

    assert active == [] and len(waived) == 1
    unmatched = [w for w in warnings if "matched no finding" in w]
    assert len(unmatched) == 1
    # And the message says which of the two, since the id does not distinguish them.
    assert "BFLA" in unmatched[0]


def test_a_waiver_passed_over_because_another_covered_it_is_not_called_unmatched():
    """It found its finding; it just was not the one that suppressed it."""
    waivers = [
        Waiver(id="get_user::alice::other", reason="first"),
        Waiver(id="get_user::alice::other", reason="second"),
    ]
    active, waived, warnings = apply_waivers([_finding()], waivers)

    assert active == [] and len(waived) == 1
    assert not [w for w in warnings if "matched no finding" in w]


def test_an_expired_waiver_beside_a_live_one_still_suppresses_and_warns():
    """The expired entry matched, so it is warned about as expired and no more;
    the live one behind it still does its job."""
    waivers = [
        Waiver(id="get_user::alice::other", reason="lapsed",
               expires=datetime.date(2020, 1, 1)),
        Waiver(id="get_user::alice::other", reason="current"),
    ]
    active, waived, warnings = apply_waivers([_finding()], waivers)

    assert active == [] and len(waived) == 1
    assert any("expired" in w for w in warnings)
    assert not [w for w in warnings if "matched no finding" in w]
