"""What the token discovery buys is allowed to be valid for.

`test_oauth_discovery_trust.py` covers the outbound half of the problem: where a
client secret is allowed to travel. This file covers the half that comes back.

Protected Resource Metadata carries a `resource` identifier, and that value does
not stay in the metadata — it becomes the RFC 8707 `resource` indicator on the
token request, which is what the authorization server audience-binds the issued
token to. The document is served by the MCP server under test. So an unchecked
`resource` hands the target a choice it must not have:

    target claims  resource: https://banking.internal/api
        -> overstep asks the (honest, pinned) authorization server for a token
           audience-bound to the banking API
        -> the authorization server, seeing a client that is authorised for it,
           issues one
        -> overstep sends that token to the target, in the Authorization header

Nothing is inconsistent anywhere in that chain, and pinning the issuer does not
touch it: the issuer pin settles *which* authorization server the secret goes to
and says nothing about *what* the token it returns is good for.

RFC 9728 §3.3 is the rule that closes it — the returned `resource` must be
identical to the identifier the well-known URL was built from. The assertions
below are therefore mostly not "did discovery fail" but "what did the token
request ask to be bound to".
"""
from urllib.parse import parse_qs

import httpx
import pytest

from overstep.auth import AuthError, authenticate
from overstep.matrix import Matrix
from overstep.modules.mcp.auth import DiscoveryError, discover_token_endpoint

AS = "https://honest.test/as"
MCP = "https://mcp.test/mcp"
ELSEWHERE = "https://banking.internal/api"

_UNSET = object()


class Backend:
    """PRM + AS metadata + token endpoint, with the claimed resource under test.

    `token_requests` records every form that reached the token endpoint, so a
    test can ask what the run tried to bind a token to rather than only whether
    discovery raised.
    """

    def __init__(self, *, claimed_resource=_UNSET, prm_paths=None):
        # Not `or MCP`: a missing resource is a case under test, not an omission.
        self.claimed_resource = MCP if claimed_resource is _UNSET else claimed_resource
        # Which well-known paths answer at all. None means "any of them".
        self.prm_paths = prm_paths
        self.token_requests = []
        self.prm_paths_served = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            if self.prm_paths is not None and path not in self.prm_paths:
                return httpx.Response(404)
            self.prm_paths_served.append(path)
            body = {"authorization_servers": [AS]}
            if self.claimed_resource is not None:
                body["resource"] = self.claimed_resource
            return httpx.Response(200, json=body)
        if "/.well-known/openid-configuration" in path:
            return httpx.Response(404)
        if "/.well-known/oauth-authorization-server" in path:
            return httpx.Response(200, json={
                "issuer": AS, "token_endpoint": f"{AS}/token",
            })
        if path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            return httpx.Response(200, json={"access_token": "tok-1"})
        return httpx.Response(404)


def _patch(backend):
    import overstep.auth as au
    import overstep.modules.mcp.auth as ma

    orig = httpx.Client

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(backend.handler)
        return orig(*a, **kw)

    ma.httpx.Client = factory
    au.httpx.Client = factory
    return orig


def _unpatch(orig):
    import overstep.auth as au
    import overstep.modules.mcp.auth as ma

    ma.httpx.Client = orig
    au.httpx.Client = orig


def _discover(backend, server_url=MCP, **kwargs):
    orig = _patch(backend)
    try:
        with httpx.Client(follow_redirects=True) as client:
            return discover_token_endpoint(server_url, client=client, **kwargs)
    finally:
        _unpatch(orig)


def _matrix(resource=None) -> Matrix:
    provider = {
        "name": "idp", "type": "oauth2_client_credentials", "discover_from": "docs",
        "client_id": "overstep", "client_secret": "s3cr3t-do-not-leak",
        "issuer": AS,
    }
    if resource:
        provider["resource"] = resource
    return Matrix(
        modules={"rest": {"base_url": "https://mcp.test"}, "mcp": {"servers": [{"name": "docs", "url": MCP}]}},
        roles=["user"],
        auth={"providers": [provider]},
        subjects=[{"name": "alice", "role": "user", "auth": {"provider": "idp"}}],
        resources=[{"name": "read_doc", "call": {"server": "docs", "tool": "read_doc"}, "type": "function"}],
        policy={"read_doc": {"allow": [{"role": "user"}]}},
    )


def _authenticate(backend, matrix):
    orig = _patch(backend)
    try:
        with httpx.Client() as client:
            authenticate(matrix, base_url="https://mcp.test", client=client)
    finally:
        _unpatch(orig)


# --- the attack -------------------------------------------------------------

def test_a_resource_the_target_invented_is_refused():
    """The core case: the server under test names somebody else's API."""
    backend = Backend(claimed_resource=ELSEWHERE)

    with pytest.raises(DiscoveryError, match="not the resource under test"):
        _discover(backend)


def test_no_token_is_ever_bound_to_a_resource_the_target_chose():
    """Discovery raising is the mechanism; this is the property that matters.

    Read through `authenticate` rather than `discover_token_endpoint` so the
    assertion covers the path a real run takes — and assert on the token endpoint
    rather than the exception, because a future refactor that caught the error
    and carried on would still be a leak.
    """
    backend = Backend(claimed_resource=ELSEWHERE)

    with pytest.raises(AuthError, match="not the resource under test"):
        _authenticate(backend, _matrix())

    assert backend.token_requests == []
    assert not any(req.get("resource") == ELSEWHERE for req in backend.token_requests)


def test_a_resource_on_a_host_the_run_never_named_is_refused():
    """Same-origin is not the rule either — the identifier itself is checked."""
    backend = Backend(claimed_resource="https://mcp.test.evil.test/mcp")

    with pytest.raises(DiscoveryError, match="not the resource under test"):
        _discover(backend)


def test_a_sibling_endpoint_on_the_same_host_is_still_a_different_resource():
    """A host may serve several MCP endpoints; a token for one is not for another."""
    backend = Backend(claimed_resource="https://mcp.test/admin-mcp")

    with pytest.raises(DiscoveryError, match="not the resource under test"):
        _discover(backend)


# --- RFC 9728 makes `resource` required -------------------------------------

def test_metadata_without_a_resource_is_refused():
    backend = Backend(claimed_resource=None)

    with pytest.raises(DiscoveryError, match="declares no resource"):
        _discover(backend)


def test_a_non_string_resource_is_refused():
    """`resource: 42` must not be compared, coerced, or quietly ignored."""
    backend = Backend(claimed_resource=42)

    with pytest.raises(DiscoveryError, match="declares no resource"):
        _discover(backend)


def test_an_empty_resource_is_refused():
    backend = Backend(claimed_resource="")

    with pytest.raises(DiscoveryError, match="declares no resource"):
        _discover(backend)


# --- what an honest server gets ---------------------------------------------

def test_the_server_url_itself_is_accepted():
    result = _discover(Backend(claimed_resource=MCP))

    assert result.resource == MCP


def test_the_origin_is_accepted_when_the_matrix_named_the_origin():
    """A resource that really is the whole origin describes itself that way."""
    backend = Backend(claimed_resource="https://mcp.test")

    assert _discover(backend, server_url="https://mcp.test").resource == "https://mcp.test"


def test_the_origin_is_refused_when_the_matrix_named_a_path():
    """Widening to the origin is still the target choosing its own audience.

    A matrix naming `https://mcp.test/mcp` named a path-scoped service. If the
    authorization server issues origin-audience tokens, accepting the origin here
    hands the target a token every sibling application on that host would also
    honour — the same class this file exists to refuse, one step closer to home.
    """
    backend = Backend(claimed_resource="https://mcp.test")

    with pytest.raises(DiscoveryError, match="not the resource under test"):
        _discover(backend, server_url="https://mcp.test/mcp")


def test_widening_to_the_origin_is_available_but_only_by_asking():
    """The operator may still opt into it — that is what the pin is for."""
    backend = Backend(claimed_resource="https://mcp.test")

    result = _discover(backend, server_url="https://mcp.test/mcp",
                       expected_resource="https://mcp.test")

    assert result.resource == "https://mcp.test"


@pytest.mark.parametrize("server_url,claimed", [
    ("https://mcp.test/mcp/", "https://mcp.test/mcp"),
    ("https://mcp.test/mcp/", "https://mcp.test/mcp/"),
    ("https://mcp.test/mcp", "https://mcp.test/mcp"),
])
def test_a_trailing_slash_in_the_matrix_is_not_a_mismatch(server_url, claimed):
    """Which spelling the matrix used is not a security question.

    Both forms are derived from the run's own URL, so accepting either widens
    nothing — unlike normalising the value the target supplied.
    """
    backend = Backend(claimed_resource=claimed)

    assert _discover(backend, server_url=server_url).resource == claimed


def test_an_honest_run_still_binds_the_token_to_the_server():
    backend = Backend(claimed_resource=MCP)

    _authenticate(backend, _matrix())

    assert backend.token_requests
    assert all(req.get("resource") == MCP for req in backend.token_requests)


# --- the escape hatch -------------------------------------------------------

def test_a_pinned_resource_admits_an_identifier_the_url_does_not_predict():
    """Some servers are legitimately known to their issuer by another name.

    The pin is written in the matrix, so honouring it is still the run choosing
    the audience rather than the target.
    """
    backend = Backend(claimed_resource=ELSEWHERE)

    result = _discover(backend, expected_resource=ELSEWHERE)

    assert result.resource == ELSEWHERE


def test_a_pin_does_not_admit_a_third_identifier():
    """Pinning names one exception, not a general amnesty."""
    backend = Backend(claimed_resource="https://something.else/api")

    with pytest.raises(DiscoveryError, match="not the resource under test"):
        _discover(backend, expected_resource=ELSEWHERE)


def test_the_pin_reaches_the_token_request_through_the_matrix():
    backend = Backend(claimed_resource=ELSEWHERE)

    _authenticate(backend, _matrix(resource=ELSEWHERE))

    assert backend.token_requests
    assert all(req.get("resource") == ELSEWHERE for req in backend.token_requests)


# --- which document describes the resource under test -----------------------

def test_the_path_scoped_document_is_preferred_over_the_root_one():
    """RFC 9728 §3.1 inserts the well-known string; the root form is a fallback.

    On a host serving several MCP endpoints the root document describes a
    different resource, so reaching for it first would ask the wrong question —
    and now that the answer is checked, it would fail the run outright.
    """
    backend = Backend(claimed_resource=MCP)

    _discover(backend)

    assert backend.prm_paths_served[0] == "/.well-known/oauth-protected-resource/mcp"


def test_the_root_document_is_still_used_when_the_path_form_is_absent():
    backend = Backend(claimed_resource=MCP,
                      prm_paths=["/.well-known/oauth-protected-resource"])

    assert _discover(backend).resource == MCP


# --- a document that is not a document --------------------------------------

@pytest.mark.parametrize("body", [[], ["https://mcp.test/mcp"], "resource", 7])
def test_metadata_that_is_not_a_json_object_is_refused_cleanly(body):
    """Valid JSON is not yet a metadata document.

    Both readers of a fetched document go straight to `.get`, so an array or a
    bare string arrived as an AttributeError rather than the refusal every other
    malformed response produces. A target should not be able to choose which
    exception type comes out of the security check.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(DiscoveryError, match="no Protected Resource Metadata"):
            discover_token_endpoint(MCP, client=client)
