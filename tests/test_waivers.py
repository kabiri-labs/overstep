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
