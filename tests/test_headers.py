"""Tests for custom header handling through planning and execution."""
from overstep.executor import build_headers
from overstep.models import (
    Effect,
    ResourceType,
    Subject,
    TestCase,
    Variant,
)
from overstep.planner import plan


def _case(**overrides) -> TestCase:
    base = dict(
        id="r::s::na",
        resource="r",
        subject="s",
        role="user",
        method="GET",
        path_template="/x",
        path="/x",
        variant=Variant.NA,
        expected=Effect.ALLOW,
        resource_type=ResourceType.FUNCTION,
    )
    base.update(overrides)
    return TestCase(**base)


def test_token_becomes_bearer_by_default():
    subject = Subject(name="s", token="abc")
    assert build_headers(subject, _case()) == {"Authorization": "Bearer abc"}


def test_resource_headers_are_sent():
    subject = Subject(name="s", token="abc")
    case = _case(headers={"X-Api-Version": "2"})
    headers = build_headers(subject, case)
    assert headers["X-Api-Version"] == "2"
    assert headers["Authorization"] == "Bearer abc"


def test_subject_headers_override_resource_headers():
    subject = Subject(name="s", token="abc", headers={"X-Tenant": "t1"})
    case = _case(headers={"X-Tenant": "default", "Accept": "application/json"})
    headers = build_headers(subject, case)
    assert headers["X-Tenant"] == "t1"          # subject wins
    assert headers["Accept"] == "application/json"


def test_custom_auth_scheme_is_not_clobbered_by_token():
    # A subject using a non-bearer scheme sets Authorization explicitly and no token.
    subject = Subject(name="s", token=None, headers={"Authorization": "Token xyz"})
    assert build_headers(subject, _case())["Authorization"] == "Token xyz"


def test_explicit_authorization_beats_token():
    subject = Subject(name="s", token="abc", headers={"Authorization": "Token xyz"})
    assert build_headers(subject, _case())["Authorization"] == "Token xyz"


def test_subject_token_overrides_a_resource_level_authorization():
    """A credential on the resource belongs to no identity, so it must not stand in.

    Letting it survive sends it for every subject: each one's own token is
    dropped, every request authenticates as the same caller, and a matrix written
    to tell callers apart tests one caller under several names — silently, since
    the requests still succeed.
    """
    subject = Subject(name="alice", token="alice-token")
    case = _case(headers={"Authorization": "Bearer shared-key", "X-Api-Version": "2"})
    headers = build_headers(subject, case)
    assert headers["Authorization"] == "Bearer alice-token"
    assert headers["X-Api-Version"] == "2"        # other resource headers still sent


def test_two_subjects_do_not_collapse_into_one_identity():
    """The consequence, stated as the property that matters."""
    case = _case(headers={"Authorization": "Bearer shared-key"})
    alice = build_headers(Subject(name="alice", token="a"), case)
    bob = build_headers(Subject(name="bob", token="b"), case)
    assert alice["Authorization"] != bob["Authorization"]


def test_a_resource_authorization_is_kept_when_the_subject_has_no_token():
    """Nothing to replace it with, and it may be the only way in."""
    subject = Subject(name="anon", token=None)
    case = _case(headers={"Authorization": "Bearer shared-key"})
    assert build_headers(subject, case)["Authorization"] == "Bearer shared-key"


def test_a_differently_cased_resource_authorization_is_still_replaced():
    subject = Subject(name="alice", token="alice-token")
    headers = build_headers(subject, _case(headers={"authorization": "Bearer shared-key"}))
    assert [v for k, v in headers.items() if k.lower() == "authorization"] == [
        "Bearer alice-token"
    ]


def test_api_key_header_without_token():
    subject = Subject(name="s", token=None, headers={"X-API-Key": "k"})
    headers = build_headers(subject, _case())
    assert headers == {"X-API-Key": "k"}        # no Authorization added


def test_planner_carries_resource_headers_into_cases():
    from overstep.matrix import Matrix

    matrix = Matrix(
        subjects=[{"name": "s", "role": "user", "token": "t"}],
        resources=[
            {
                "name": "r",
                "request": {"method": "GET", "path": "/x", "headers": {"X-Api-Version": "2"}},
                "type": "function",
            }
        ],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    case = plan(matrix)[0]
    assert case.headers == {"X-Api-Version": "2"}
