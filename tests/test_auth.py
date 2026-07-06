"""Tests for dynamic authentication (token acquisition)."""
import json
from urllib.parse import parse_qs

import httpx
import pytest

from overstep.auth import AuthError, authenticate, extract_token
from overstep.auth import _render
from overstep.matrix import Matrix


# --- pure helpers -----------------------------------------------------------

def test_extract_token_dotted_path():
    assert extract_token("$.access_token", {"access_token": "abc"}) == "abc"
    assert extract_token("$.data.token", {"data": {"token": "xyz"}}) == "xyz"
    assert extract_token("$.items[0].t", {"items": [{"t": "first"}]}) == "first"
    assert extract_token("$.missing", {"access_token": "abc"}) is None


def test_render_substitutes_double_brace():
    assert _render({"u": "{{U}}", "p": "{{P}}"}, {"U": "alice", "P": "pw"}) == {
        "u": "alice",
        "p": "pw",
    }


# --- login flows via a mock transport (no network) --------------------------

def _mock_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/auth/login":
            body = json.loads(request.content)
            return httpx.Response(200, json={"access_token": "tok-" + body["username"]})
        if path == "/oauth/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert form["grant_type"] == "client_credentials"
            assert form["client_id"] == "cid"
            return httpx.Response(200, json={"access_token": "cc-token"})
        if path == "/bad":
            return httpx.Response(401, json={"error": "nope"})
        if path == "/notoken":
            return httpx.Response(200, json={"nothing": "here"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _client():
    return httpx.Client(transport=_mock_transport(), base_url="http://test")


def test_http_login_sets_bearer_per_subject():
    matrix = Matrix(
        base_url="http://test",
        auth={
            "providers": [
                {
                    "name": "login",
                    "type": "http",
                    "request": {
                        "method": "POST",
                        "path": "/auth/login",
                        "body": {"username": "{{U}}", "password": "{{P}}"},
                    },
                }
            ]
        },
        subjects=[
            {"name": "alice", "role": "user", "auth": {"provider": "login", "vars": {"U": "alice", "P": "pw"}}},
            {"name": "bob", "role": "user", "auth": {"provider": "login", "vars": {"U": "bob", "P": "pw"}}},
        ],
        resources=[],
    )
    with _client() as client:
        authenticate(matrix, base_url="http://test", client=client)

    assert matrix.subjects[0].headers["Authorization"] == "Bearer tok-alice"
    assert matrix.subjects[1].headers["Authorization"] == "Bearer tok-bob"


def test_oauth2_client_credentials_flow():
    matrix = Matrix(
        base_url="http://test",
        auth={
            "providers": [
                {
                    "name": "cc",
                    "type": "oauth2_client_credentials",
                    "token_url": "/oauth/token",
                    "client_id": "cid",
                    "client_secret": "csecret",
                }
            ]
        },
        subjects=[{"name": "svc", "role": "admin", "auth": {"provider": "cc"}}],
        resources=[],
    )
    with _client() as client:
        authenticate(matrix, base_url="http://test", client=client)
    assert matrix.subjects[0].headers["Authorization"] == "Bearer cc-token"


def test_custom_token_header_and_format():
    matrix = Matrix(
        base_url="http://test",
        auth={
            "providers": [
                {
                    "name": "login",
                    "type": "http",
                    "request": {"method": "POST", "path": "/auth/login",
                                "body": {"username": "{{U}}", "password": "x"}},
                    "token_header": "X-Auth-Token",
                    "token_format": "{token}",
                }
            ]
        },
        subjects=[{"name": "alice", "role": "user", "auth": {"provider": "login", "vars": {"U": "alice"}}}],
        resources=[],
    )
    with _client() as client:
        authenticate(matrix, base_url="http://test", client=client)
    assert matrix.subjects[0].headers["X-Auth-Token"] == "tok-alice"
    assert "Authorization" not in matrix.subjects[0].headers


def test_login_failure_raises():
    matrix = Matrix(
        base_url="http://test",
        auth={"providers": [{"name": "p", "type": "http",
                             "request": {"method": "GET", "path": "/bad"}}]},
        subjects=[{"name": "a", "role": "user", "auth": {"provider": "p"}}],
        resources=[],
    )
    with _client() as client, pytest.raises(AuthError):
        authenticate(matrix, base_url="http://test", client=client)


def test_missing_token_in_response_raises():
    matrix = Matrix(
        base_url="http://test",
        auth={"providers": [{"name": "p", "type": "http",
                             "request": {"method": "GET", "path": "/notoken"}}]},
        subjects=[{"name": "a", "role": "user", "auth": {"provider": "p"}}],
        resources=[],
    )
    with _client() as client, pytest.raises(AuthError):
        authenticate(matrix, base_url="http://test", client=client)


def test_no_providers_is_a_noop():
    matrix = Matrix(base_url="http://test", subjects=[{"name": "a", "role": "user", "token": "static"}], resources=[])
    authenticate(matrix, base_url="http://test")  # must not touch the network
    assert matrix.subjects[0].headers == {}


def test_validate_flags_unknown_provider():
    matrix = Matrix(
        subjects=[{"name": "a", "role": "user", "auth": {"provider": "ghost"}}],
        resources=[],
    )
    assert any("unknown auth provider 'ghost'" in p for p in matrix.validate_refs())
