"""Tests for the content-aware BOLA oracle.

A BOLA test that comes back ``allow`` on status alone is not proof that data
leaked — the response might be an empty list or a generic page. When a subject
declares a ``marker`` (a string that uniquely identifies *their* data), overstep
looks for the victim's marker in the response and grades the finding's
confidence accordingly.
"""
import httpx
import pytest

from overstep.classifier import classify
from overstep.executor import execute
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, Variant, VulnClass
from overstep.planner import plan


@pytest.fixture
def marked_matrix() -> Matrix:
    return Matrix(
        base_url="http://testserver",
        roles=["user", "admin"],
        subjects=[
            {
                "name": "alice",
                "role": "user",
                "token": "a",
                "attributes": {"user_id": "u1"},
                "marker": "alice@example.com",
            },
            {
                "name": "bob",
                "role": "user",
                "token": "b",
                "attributes": {"user_id": "u2"},
                "marker": "bob@example.com",
            },
        ],
        resources=[
            {
                "name": "get_user",
                "request": {"method": "GET", "path": "/users/{id}"},
                "type": "object",
                "owner_param": "id",
                "owner_attr": "user_id",
            }
        ],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )


def test_planner_attaches_victim_marker_to_other_variant(marked_matrix):
    cases = {c.id: c for c in plan(marked_matrix)}
    alice_other = cases["get_user::alice::other"]
    assert alice_other.variant == Variant.OTHER
    # The OTHER target is bob, so bob's marker is what a leak would expose.
    assert alice_other.expect_markers == ["bob@example.com"]
    # SELF variants carry no victim marker.
    assert cases["get_user::alice::self"].expect_markers == []


def test_confirmed_when_victim_marker_present(marked_matrix):
    cases = plan(marked_matrix)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::other":
            # BOLA slipped through AND the response carries bob's data.
            obs.append(
                Observation(
                    test_id=c.id,
                    status=200,
                    effect=Effect.ALLOW,
                    matched_markers=["bob@example.com"],
                )
            )
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))

    findings = classify(marked_matrix, cases, obs)
    bola = [f for f in findings if f.vuln_class == VulnClass.BOLA]
    assert len(bola) == 1
    assert bola[0].confidence == "confirmed"
    assert bola[0].severity == "high"


def test_suspected_when_marker_configured_but_absent(marked_matrix):
    cases = plan(marked_matrix)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::other":
            # Access was granted on status, but no victim data actually came back.
            obs.append(Observation(test_id=c.id, status=200, effect=Effect.ALLOW, matched_markers=[]))
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))

    findings = classify(marked_matrix, cases, obs)
    bola = [f for f in findings if f.vuln_class == VulnClass.BOLA]
    assert len(bola) == 1
    assert bola[0].confidence == "suspected"
    assert bola[0].severity == "medium"


def test_unverified_when_no_marker_declared(matrix):
    # The shared fixture declares no markers -> status-based, confidence unverified.
    cases = plan(matrix)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::other":
            obs.append(Observation(test_id=c.id, status=200, effect=Effect.ALLOW))
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))

    findings = classify(matrix, cases, obs)
    bola = [f for f in findings if f.vuln_class == VulnClass.BOLA]
    assert len(bola) == 1
    assert bola[0].confidence == "unverified"
    assert bola[0].severity == "high"


def test_executor_records_matched_markers(marked_matrix):
    """The executor scans the real response body for each victim marker."""

    def handler(request: httpx.Request) -> httpx.Response:
        # /users/u2 is bob's object; leak bob's data back to whoever asks.
        if request.url.path == "/users/u2":
            return httpx.Response(200, json={"email": "bob@example.com", "id": "u2"})
        if request.url.path == "/users/u1":
            return httpx.Response(200, json={"email": "alice@example.com", "id": "u1"})
        return httpx.Response(404)

    cases = plan(marked_matrix)
    transport = httpx.MockTransport(handler)

    import asyncio

    async def _run():
        import overstep.executor as ex

        # Patch the client factory to use the mock transport.
        orig = httpx.AsyncClient

        def factory(*args, **kwargs):
            kwargs["transport"] = transport
            return orig(*args, **kwargs)

        ex.httpx.AsyncClient = factory
        try:
            return await execute("http://testserver", marked_matrix.subjects, cases)
        finally:
            ex.httpx.AsyncClient = orig

    observations = asyncio.run(_run())
    by_id = {o.test_id: o for o in observations}
    # alice reaching bob's object sees bob's marker.
    assert by_id["get_user::alice::other"].matched_markers == ["bob@example.com"]
    # alice reaching her own object does not expose a victim marker.
    assert by_id["get_user::alice::self"].matched_markers == []
