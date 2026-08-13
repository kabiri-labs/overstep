"""Where an authorization server's metadata actually lives.

RFC 8414 §3.1 *inserts* the well-known string between host and path rather than
appending it. An issuer identifying a tenant at `https://auth.example.com/tenant1`
is therefore described at
`https://auth.example.com/.well-known/oauth-authorization-server/tenant1`, not at
`https://auth.example.com/tenant1/.well-known/oauth-authorization-server`.

OpenID Connect Discovery appends instead, and RFC 8414 §5 keeps that form for
interoperability. So a path-bearing issuer has three legal addresses and the MCP
authorization spec requires clients to try all three, in a fixed order.

overstep built exactly one of them — the OIDC appended form — and paired it with
an appended OAuth suffix that no specification defines. That combination works
against the identity providers whose OIDC document answers the appended form
(Keycloak's `/realms/x`, Entra's `/{tenant}/v2.0`), which is why it went
unnoticed, and finds nothing at all for a plain OAuth authorization server
serving a tenant under a path.

Adding addresses cannot widen trust here, which is what makes this safe to fix
rather than a tradeoff: `_validate_issuer` refuses any document that does not
claim the identifier the URL was built from, so a new candidate is a new place to
be told "no", not a new thing to believe.
"""
import httpx
import pytest

from overstep.mcp_auth import (
    DiscoveryError,
    _as_metadata_candidates,
    discover_token_endpoint,
)

MCP = "https://mcp.test/mcp"


# --- the addresses themselves -----------------------------------------------

def test_a_path_bearing_issuer_gets_the_three_the_spec_requires():
    assert _as_metadata_candidates("https://auth.example.com/tenant1") == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_a_path_less_issuer_gets_the_two_the_spec_requires():
    assert _as_metadata_candidates("https://auth.example.com") == [
        "https://auth.example.com/.well-known/oauth-authorization-server",
        "https://auth.example.com/.well-known/openid-configuration",
    ]


def test_the_url_no_specification_defines_is_gone():
    """Appending the OAuth suffix to a path-bearing issuer names nothing."""
    urls = _as_metadata_candidates("https://auth.example.com/tenant1")

    assert "https://auth.example.com/tenant1/.well-known/oauth-authorization-server" not in urls


@pytest.mark.parametrize("issuer", [
    "https://auth.example.com/tenant1",
    "https://auth.example.com/tenant1/",
])
def test_a_trailing_slash_on_the_issuer_does_not_change_the_addresses(issuer):
    """`/tenant1/` and `/tenant1` name the same tenant; a doubled slash names nothing."""
    assert _as_metadata_candidates(issuer) == _as_metadata_candidates(
        "https://auth.example.com/tenant1"
    )


def test_a_multi_segment_path_is_inserted_whole():
    """Entra spells its issuer `/{tenant}/v2.0`; the whole path moves, not the last bit."""
    urls = _as_metadata_candidates("https://login.example.com/contoso/v2.0")

    assert urls[0] == (
        "https://login.example.com/.well-known/oauth-authorization-server/contoso/v2.0"
    )
    assert urls[-1] == "https://login.example.com/contoso/v2.0/.well-known/openid-configuration"


def test_a_path_less_issuer_is_unchanged_from_before():
    """The common case must not move — this is a fix for tenants, not for everyone."""
    for issuer in ("https://auth.example.com", "https://auth.example.com/"):
        assert _as_metadata_candidates(issuer) == [
            "https://auth.example.com/.well-known/oauth-authorization-server",
            "https://auth.example.com/.well-known/openid-configuration",
        ]


# --- against servers shaped like the real ones ------------------------------

class Tenant:
    """A multi-tenant authorization server that answers at exactly one address.

    `serves` is the whole point: each instance models one real deployment style,
    and discovery has to find the document without being told which.
    """

    def __init__(self, serves: str, issuer: str = "https://auth.test/tenant1"):
        self.serves = serves
        self.issuer = issuer
        self.paths_tried = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json={
                "resource": MCP, "authorization_servers": [self.issuer],
            })
        if ".well-known" in path:
            self.paths_tried.append(path)
            if path == self.serves:
                return httpx.Response(200, json={
                    "issuer": self.issuer,
                    "token_endpoint": "https://auth.test/tenant1/token",
                })
            return httpx.Response(404)
        return httpx.Response(404)


def _discover(server, **kwargs):
    with httpx.Client(transport=httpx.MockTransport(server.handler),
                      follow_redirects=True) as client:
        return discover_token_endpoint(MCP, client=client, **kwargs)


def test_a_plain_oauth_tenant_is_found_at_the_inserted_path():
    """The case that previously found nothing at all."""
    server = Tenant("/.well-known/oauth-authorization-server/tenant1")

    result = _discover(server)

    assert result.token_endpoint == "https://auth.test/tenant1/token"


def test_an_oidc_tenant_serving_the_inserted_path_is_found():
    server = Tenant("/.well-known/openid-configuration/tenant1")

    assert _discover(server).token_endpoint == "https://auth.test/tenant1/token"


def test_a_keycloak_shaped_tenant_still_works():
    """The appended OIDC form is the one that worked before; it must keep working.

    This is the regression that matters — Keycloak and Entra answer here, so most
    real multi-tenant discovery went through this address.
    """
    server = Tenant("/tenant1/.well-known/openid-configuration")

    assert _discover(server).token_endpoint == "https://auth.test/tenant1/token"


def test_the_oauth_document_wins_when_a_server_offers_several():
    """Priority order is part of the requirement, not an implementation detail."""
    class Both(Tenant):
        def handler(self, request):
            path = request.url.path
            if path.startswith("/.well-known/oauth-protected-resource"):
                return httpx.Response(200, json={
                    "resource": MCP, "authorization_servers": [self.issuer]})
            if ".well-known" in path:
                self.paths_tried.append(path)
                endpoint = ("https://auth.test/oauth-token"
                            if "oauth-authorization-server" in path
                            else "https://auth.test/oidc-token")
                return httpx.Response(200, json={
                    "issuer": self.issuer, "token_endpoint": endpoint})
            return httpx.Response(404)

    server = Both("unused")

    assert _discover(server).token_endpoint == "https://auth.test/oauth-token"
    assert server.paths_tried == ["/.well-known/oauth-authorization-server/tenant1"]


def test_the_new_addresses_are_not_a_way_past_the_issuer_check():
    """A document at the inserted path is checked exactly like any other."""
    server = Tenant("/.well-known/oauth-authorization-server/tenant1")
    server.issuer = "https://auth.test/tenant1"

    class Liar(Tenant):
        def handler(self, request):
            path = request.url.path
            if path.startswith("/.well-known/oauth-protected-resource"):
                return httpx.Response(200, json={
                    "resource": MCP, "authorization_servers": [self.issuer]})
            if path == self.serves:
                return httpx.Response(200, json={
                    "issuer": "https://somewhere.else/tenant1",
                    "token_endpoint": "https://somewhere.else/token"})
            return httpx.Response(404)

    liar = Liar("/.well-known/oauth-authorization-server/tenant1")

    with pytest.raises(DiscoveryError, match="claims issuer"):
        _discover(liar)


def test_a_tenant_nobody_serves_is_still_a_failure():
    """Three addresses tried and none answering is not a reason to invent one."""
    server = Tenant("/nowhere")

    with pytest.raises(DiscoveryError, match="no Authorization Server Metadata"):
        _discover(server)

    assert server.paths_tried == [
        "/.well-known/oauth-authorization-server/tenant1",
        "/.well-known/openid-configuration/tenant1",
        "/tenant1/.well-known/openid-configuration",
    ]
