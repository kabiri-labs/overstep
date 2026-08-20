"""Tests for reproduction evidence attached to findings.

Every finding should carry a copy-pasteable ``curl`` command and the request
detail that produced it, with secrets masked so a report can be shared safely.
"""
import os
import shlex

from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, Subject, VulnClass
from overstep.planner import plan
from overstep.repro import credential_values, mask_headers, redact, to_curl


def _matrix() -> Matrix:
    return Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
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
                "owner": "id",
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
    # ...but a named variable must, so the command is more than decoration.
    assert "Bearer $OVERSTEP_TOKEN_ALICE" in curl


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


def test_the_repro_actually_runs_once_the_variable_is_exported(monkeypatch):
    """The point of a named placeholder over `***`: exporting one variable turns
    the shared line back into the exact request that produced the finding."""
    m = _matrix()
    case = {c.id: c for c in plan(m)}["get_user::alice::other"]
    subject = {s.name: s for s in m.subjects}["alice"]

    # shlex.split parsing at all proves the quoting is well-formed shell.
    argv = shlex.split(to_curl("http://api.test", subject, case))
    monkeypatch.setenv("OVERSTEP_TOKEN_ALICE", "alice-secret")

    expanded = [os.path.expandvars(arg) for arg in argv]

    assert "Authorization: Bearer alice-secret" in expanded


def test_each_subject_gets_its_own_variable():
    """Two subjects must not share a variable, or the repro for one would
    authenticate as the other."""
    m = _matrix()
    cases = {c.id: c for c in plan(m)}
    subjects = {s.name: s for s in m.subjects}

    alice = to_curl("http://api.test", subjects["alice"], cases["get_user::alice::other"])
    bob = to_curl("http://api.test", subjects["bob"], cases["get_user::bob::other"])

    assert "$OVERSTEP_TOKEN_ALICE" in alice
    assert "$OVERSTEP_TOKEN_BOB" in bob


def test_a_non_bearer_secret_header_gets_its_own_variable():
    masked = mask_headers({"X-Api-Key": "abc123", "Cookie": "session=xyz"}, "alice")

    assert masked["X-Api-Key"] == "$OVERSTEP_X_API_KEY_ALICE"
    assert masked["Cookie"] == "$OVERSTEP_COOKIE_ALICE"
    assert "abc123" not in str(masked) and "xyz" not in str(masked)


def test_mask_headers_without_a_subject_still_redacts():
    """The redaction-only contract is unchanged for callers that want it."""
    masked = mask_headers({"Authorization": "Bearer alice-secret"})

    assert masked["Authorization"] == "Bearer ***"


def test_a_subject_name_with_punctuation_makes_a_valid_variable():
    masked = mask_headers({"Authorization": "Bearer t"}, "svc-a.eu")

    assert masked["Authorization"] == "Bearer $OVERSTEP_TOKEN_SVC_A_EU"


# --- credentials in a response the target wrote -----------------------------


def test_credential_values_collects_what_a_run_holds():
    subjects = [
        Subject(name="alice", role="user", token="alice-supersecret"),
        Subject(name="bob", role="user", headers={"X-API-Key": "bob-key-value"}),
        Subject(name="carol", role="user", headers={"Authorization": "Bearer carol-tok"}),
    ]
    values = credential_values(subjects)
    assert "alice-supersecret" in values
    assert "bob-key-value" in values
    # Both spellings: a body may echo the header or just the credential.
    assert "Bearer carol-tok" in values and "carol-tok" in values


def test_credential_values_ignores_a_value_too_short_to_be_a_secret():
    """Replacing every "a" in a body would destroy the evidence it protects."""
    assert credential_values([Subject(name="t", role="user", token="a")]) == set()


def test_redact_replaces_longest_first():
    text = "tok=abc123 short=abc"
    assert redact(text, {"abc", "abc123"}) == "tok=*** short=***"


def test_a_reflected_credential_does_not_reach_a_finding():
    """The request's credentials are masked; the response's were not.

    Some endpoints reflect what they were given — a debug route, a session
    endpoint, an error echoing the header it could not parse — and the evidence
    a finding carries is that response verbatim. A token used to travel into
    findings.json beside a curl line that had replaced the same value with a
    shell variable.
    """
    matrix = Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-supersecret",
             "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "token": "bob-supersecret",
             "attributes": {"user_id": "u2"}},
        ],
        resources=[{
            "name": "get_user",
            "request": {"method": "GET", "path": "/users/{id}"},
            "type": "object", "owner": "id", "owner_attr": "user_id",
        }],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )
    cases = plan(matrix)
    body = '{"id":"u2","session_token":"alice-supersecret"}'
    obs = [
        Observation(
            test_id=c.id,
            status=200 if c.expected == Effect.ALLOW else 200,
            effect=Effect.ALLOW,
            body_snippet=body,
            full_body=body,
        )
        for c in cases
    ]

    findings = classify(matrix, cases, obs)
    assert findings, "the fixture must produce something to inspect"
    for f in findings:
        assert "supersecret" not in f.evidence.body_snippet
        assert "supersecret" not in f.evidence.full_body
        assert "supersecret" not in (f.curl or "")
        assert "supersecret" not in f.model_dump_json()
    # And what is left is still the response, not a hole where it was.
    assert '"id":"u2"' in findings[0].evidence.body_snippet


def test_redaction_does_not_disturb_classification():
    """The classifier reads what the target sent; only the copy written out changes."""
    matrix = Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "token": "alice-supersecret",
                   "attributes": {"user_id": "u1"}}],
        resources=[{
            "name": "get_user",
            "request": {"method": "GET", "path": "/users/{id}"},
            "type": "object", "owner": "id", "owner_attr": "user_id",
            "forbidden_fields": ["alice-supersecret"],
        }],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )
    cases = plan(matrix)
    # The forbidden key *is* the credential, so a redact-first order would hide it.
    body = '{"id":"u1","alice-supersecret":"x"}'
    obs = [
        Observation(test_id=c.id, status=200, effect=Effect.ALLOW,
                    body_snippet=body, full_body=body)
        for c in cases
    ]
    bopla = [f for f in classify(matrix, cases, obs) if f.vuln_class == VulnClass.BOPLA]
    assert len(bopla) == 1
    assert bopla[0].leaked_fields == ["alice-supersecret"]
