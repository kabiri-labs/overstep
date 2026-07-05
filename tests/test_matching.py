"""Tests for the configurable response matcher."""
from overstep.matching import evaluate, status_matches
from overstep.models import Effect, ResponseMatcher


def test_status_matches_exact_range_and_class():
    assert status_matches([200, 201], 200) is True
    assert status_matches([200, 201], 204) is False
    assert status_matches(["200-299"], 250) is True
    assert status_matches(["200-299"], 300) is False
    assert status_matches(["2xx"], 299) is True
    assert status_matches(["2xx"], 301) is False


def test_default_matcher_is_status_based():
    m = ResponseMatcher()
    assert evaluate(m, 200) == Effect.ALLOW
    assert evaluate(m, 204) == Effect.ALLOW
    assert evaluate(m, 403) == Effect.DENY
    assert evaluate(m, 404) == Effect.DENY


def test_redirect_defaults_to_deny_but_is_configurable():
    assert evaluate(ResponseMatcher(), 302) == Effect.DENY
    assert evaluate(ResponseMatcher(treat_redirect_as="allow"), 302) == Effect.ALLOW
    # "status" makes 3xx fall through to allow_status (not listed) -> deny
    assert evaluate(ResponseMatcher(treat_redirect_as="status"), 302) == Effect.DENY


def test_deny_body_regex_overrides_a_2xx():
    # 200 with an error body (soft error / masked failure) -> deny.
    m = ResponseMatcher(deny_body_regex="access denied|not authorized")
    assert evaluate(m, 200, '{"error": "access denied"}') == Effect.DENY
    assert evaluate(m, 200, '{"ok": true}') == Effect.ALLOW


def test_allow_body_regex_can_rescue_a_non_2xx():
    m = ResponseMatcher(allow_status=[200], allow_body_regex='"status"\\s*:\\s*"ok"')
    assert evaluate(m, 202, '{"status": "ok"}') == Effect.ALLOW


def test_deny_body_beats_allow_body():
    m = ResponseMatcher(allow_body_regex="ok", deny_body_regex="error")
    assert evaluate(m, 200, "ok but error") == Effect.DENY


def test_body_regex_is_case_insensitive_and_multiline():
    m = ResponseMatcher(deny_body_regex="forbidden")
    assert evaluate(m, 200, "line1\nFORBIDDEN\nline3") == Effect.DENY


def test_custom_allow_status_list():
    m = ResponseMatcher(allow_status=["2xx", 418])
    assert evaluate(m, 418) == Effect.ALLOW
    assert evaluate(m, 500) == Effect.DENY


def test_planner_resolves_matcher_precedence():
    from overstep.matrix import Matrix
    from overstep.planner import plan

    matrix = Matrix(
        access=ResponseMatcher(deny_body_regex="global-deny"),
        subjects=[{"name": "s", "role": "user", "token": "t"}],
        resources=[
            {"name": "a", "request": {"method": "GET", "path": "/a"}, "type": "function"},
            {
                "name": "b",
                "request": {"method": "GET", "path": "/b"},
                "type": "function",
                "access": {"allow_status": ["2xx"], "treat_redirect_as": "allow"},
            },
        ],
        policy={"a": {"allow": [{"role": "user"}]}, "b": {"allow": [{"role": "user"}]}},
    )
    by_resource = {c.resource: c for c in plan(matrix)}
    # 'a' inherits the matrix-level matcher; 'b' uses its own override.
    assert by_resource["a"].matcher.deny_body_regex == "global-deny"
    assert by_resource["b"].matcher.treat_redirect_as == "allow"
    assert by_resource["b"].matcher.deny_body_regex is None
