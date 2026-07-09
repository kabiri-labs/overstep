"""Tests for BOPLA (property-level) checks and cross-method probing."""
from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, ResourceType, Variant, VulnClass
from overstep.planner import plan


def _matrix(**resource_extra) -> Matrix:
    resource = {
        "name": "get_user",
        "request": {"method": "GET", "path": "/users/{id}"},
        "type": "object",
        "owner_param": "id",
        "owner_attr": "user_id",
    }
    resource.update(resource_extra)
    return Matrix(
        base_url="http://api.test",
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"user_id": "u2"}},
        ],
        resources=[resource],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )


# --- cross-method probing ---------------------------------------------------


def test_probe_methods_generate_extra_negative_cases():
    m = _matrix(probe_methods=["PUT", "DELETE"])
    cases = {c.id: c for c in plan(m)}
    # alice reaching bob's object with a method she was never granted.
    assert "get_user::alice::other::PUT" in cases
    assert "get_user::alice::other::DELETE" in cases
    put = cases["get_user::alice::other::PUT"]
    assert put.method == "PUT"
    assert put.expected == Effect.DENY
    assert put.path == "/users/u2"


def test_probe_method_that_succeeds_is_a_finding():
    m = _matrix(probe_methods=["DELETE"])
    cases = plan(m)
    obs = []
    for c in cases:
        # The DELETE probe wrongly succeeds; everything else behaves.
        if c.id == "get_user::alice::other::DELETE":
            obs.append(Observation(test_id=c.id, status=200, effect=Effect.ALLOW))
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))
    findings = classify(m, cases, obs)
    hit = [f for f in findings if f.test_id == "get_user::alice::other::DELETE"]
    assert len(hit) == 1
    assert hit[0].vuln_class == VulnClass.BOLA  # object + other variant


# --- BOPLA (forbidden fields) -----------------------------------------------


def test_forbidden_field_present_in_allowed_response_is_bopla():
    m = _matrix(forbidden_fields=["is_admin", "password_hash"])
    cases = plan(m)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::self":
            # An allowed read that leaks a field the caller must not see.
            obs.append(
                Observation(
                    test_id=c.id,
                    status=200,
                    effect=Effect.ALLOW,
                    body_snippet='{"id": "u1", "is_admin": false}',
                )
            )
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))
    findings = classify(m, cases, obs)
    bopla = [f for f in findings if f.vuln_class == VulnClass.BOPLA]
    assert len(bopla) == 1
    assert bopla[0].test_id == "get_user::alice::self"
    assert "is_admin" in bopla[0].detail


def test_no_bopla_when_forbidden_field_absent():
    m = _matrix(forbidden_fields=["is_admin"])
    cases = plan(m)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::self":
            obs.append(
                Observation(test_id=c.id, status=200, effect=Effect.ALLOW, body_snippet='{"id": "u1"}')
            )
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))
    findings = classify(m, cases, obs)
    assert [f for f in findings if f.vuln_class == VulnClass.BOPLA] == []


def test_bopla_only_checks_nested_keys_not_substrings():
    # "admin" as a value must not trip a forbidden key check for "is_admin".
    m = _matrix(forbidden_fields=["is_admin"])
    cases = plan(m)
    obs = []
    for c in cases:
        if c.id == "get_user::alice::self":
            obs.append(
                Observation(
                    test_id=c.id,
                    status=200,
                    effect=Effect.ALLOW,
                    body_snippet='{"role": "is_admin_ish", "note": "is_admin appears in text"}',
                )
            )
        else:
            eff = Effect.ALLOW if c.expected == Effect.ALLOW else Effect.DENY
            obs.append(Observation(test_id=c.id, status=200 if eff == Effect.ALLOW else 403, effect=eff))
    findings = classify(m, cases, obs)
    # No JSON *key* named is_admin -> no BOPLA.
    assert [f for f in findings if f.vuln_class == VulnClass.BOPLA] == []
