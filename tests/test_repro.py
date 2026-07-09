"""Tests for reproduction evidence attached to findings.

Every finding should carry a copy-pasteable ``curl`` command and the request
detail that produced it, with secrets masked so a report can be shared safely.
"""
from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, VulnClass
from overstep.planner import plan
from overstep.repro import mask_headers, to_curl


def _matrix() -> Matrix:
    return Matrix(
        base_url="http://api.test",
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-secret", "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "token": "bob-secret", "attributes": {"user_id": "u2"}},
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


def test_mask_headers_hides_bearer_token():
    masked = mask_headers({"Authorization": "Bearer alice-secret", "X-Api-Key": "abc123"})
    assert masked["Authorization"] == "Bearer ***"
    assert masked["X-Api-Key"] == "***"


def test_mask_headers_keeps_non_secret_headers():
    masked = mask_headers({"Content-Type": "application/json", "X-Tenant": "acme"})
    assert masked["Content-Type"] == "application/json"
    assert masked["X-Tenant"] == "acme"


def test_to_curl_builds_command_with_masked_secret():
    m = _matrix()
    case = {c.id: c for c in plan(m)}["get_user::alice::other"]
    subject = {s.name: s for s in m.subjects}["alice"]
    curl = to_curl("http://api.test", subject, case)
    assert curl.startswith("curl ")
    assert "-X GET" in curl
    assert "http://api.test/users/u2" in curl
    # The real token must never appear in a shareable repro line.
    assert "alice-secret" not in curl
    assert "Bearer ***" in curl


def test_to_curl_includes_json_body_for_write():
    m = _matrix()
    m.resources[0].request.method = "POST"
    m.resources[0].request.body = {"role": "admin"}
    case = {c.id: c for c in plan(m)}["get_user::alice::other"]
    subject = {s.name: s for s in m.subjects}["alice"]
    curl = to_curl("http://api.test", subject, case)
    assert "-X POST" in curl
    assert "--data" in curl
    assert "admin" in curl


def test_finding_carries_curl_and_masked_request():
    m = _matrix()
    cases = plan(m)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::other":
            obs.append(Observation(test_id=c.id, status=200, effect=Effect.ALLOW))
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))

    findings = classify(m, cases, obs)
    bola = [f for f in findings if f.vuln_class == VulnClass.BOLA][0]
    assert bola.curl.startswith("curl ")
    assert "/users/u2" in bola.curl
    assert "alice-secret" not in bola.curl
    # Request detail is captured with the secret masked.
    assert bola.request is not None
    assert bola.request["method"] == "GET"
    assert "alice-secret" not in str(bola.request)
