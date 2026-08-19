"""Where discovery is allowed to send a client secret.

OAuth discovery for MCP starts at the server under test and ends at a token
endpoint. That is a strange shape for a security tool: the host it trusts least
gets to name the authorization server, which names the URL that overstep then
POSTs `client_secret` — or, on the password grant, a real username and password —
to. Every hop is target-supplied, so every hop is checked.

Two different attacks live here and they need different answers:

* **Substitution** — an authorization server that answers at its own well-known
  URL while claiming to be somebody else's issuer. RFC 8414 §3.3 catches this,
  and the spec's own worked example is exactly it.
* **Redirection** — a hostile MCP server that names an authorization server it
  owns outright, self-consistently. No amount of metadata checking catches that,
  because nothing is inconsistent: the only thing that stops it is the operator
  saying in advance which issuer their credentials belong to.

The tests below pin both answers, and the residual case in between.
"""
import httpx
import pytest

from overstep.auth import AuthError, authenticate
from overstep.matrix import Matrix
from overstep.mcp_auth import DiscoveryError, discover_token_endpoint, require_https

HONEST = "https://honest.test/as"
ATTACKER = "https://attacker.test/as"
MCP = "https://mcp.test/mcp"

_UNSET = object()


class Backend:
    """A configurable PRM + AS metadata + token endpoint.

    `token_requests` records every form that reached *any* token endpoint, which
    is what the leak assertions read: the question is never "did discovery fail"
    but "did the secret move".
    """

    def __init__(self, *, authorization_servers=None, claimed_issuer=_UNSET,
                 token_endpoint=None, redirect_metadata_to=None):
        self.authorization_servers = authorization_servers or [HONEST]
        # Not `or HONEST`: an empty issuer is a case under test, not an omission.
        self.claimed_issuer = HONEST if claimed_issuer is _UNSET else claimed_issuer
        self.token_endpoint = token_endpoint or f"{HONEST}/token"
        self.redirect_metadata_to = redirect_metadata_to
        self.token_requests = []
        self.hosts_asked_for_tokens = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json={
                "resource": MCP, "authorization_servers": self.authorization_servers,
            })
        if "/.well-known/openid-configuration" in path:
            return httpx.Response(404)
        if "/.well-known/oauth-authorization-server" in path:
            # Redirect once, from the host that was asked for — redirecting the
            # destination too would just be a loop httpx reports as a transport
            # error, and the check under test would never be reached.
            if self.redirect_metadata_to and request.url.host == "honest.test":
                return httpx.Response(302, headers={"Location": self.redirect_metadata_to})
            return httpx.Response(200, json={
                "issuer": self.claimed_issuer, "token_endpoint": self.token_endpoint,
            })
        if path.endswith("/token") or path.endswith("/steal"):
            from urllib.parse import parse_qs
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            self.hosts_asked_for_tokens.append(request.url.host)
            return httpx.Response(200, json={"access_token": "tok-1"})
        return httpx.Response(404)


def _patch(backend):
    import overstep.auth as au
    import overstep.mcp_auth as ma

    orig = httpx.Client

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(backend.handler)
        return orig(*a, **kw)

    ma.httpx.Client = factory
    au.httpx.Client = factory
    return orig


def _unpatch(orig):
    import overstep.auth as au
    import overstep.mcp_auth as ma

    ma.httpx.Client = orig
    au.httpx.Client = orig


def _discover(backend, **kwargs):
    orig = _patch(backend)
    try:
        # follow_redirects matches how auth.py builds the real client, which is
        # what makes the cross-origin redirect case reachable at all.
        with httpx.Client(follow_redirects=True) as client:
            return discover_token_endpoint(MCP, client=client, **kwargs)
    finally:
        _unpatch(orig)


def _matrix(issuer=None) -> Matrix:
    provider = {
        "name": "idp", "type": "oauth2_client_credentials", "discover_from": "docs",
        "client_id": "overstep", "client_secret": "s3cr3t-do-not-leak",
    }
    if issuer:
        provider["issuer"] = issuer
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


# --- substitution: the spec's own worked example ----------------------------

def test_metadata_claiming_another_issuer_is_refused():
    """`attacker.test` serving a document that says `issuer: honest.test`."""
    backend = Backend(authorization_servers=[ATTACKER], claimed_issuer=HONEST,
                      token_endpoint=f"{ATTACKER}/steal")

    with pytest.raises(DiscoveryError, match="claims issuer"):
        _discover(backend)

    assert backend.token_requests == []


def test_metadata_without_an_issuer_is_refused():
    """Nothing to compare is not the same as nothing to check."""
    backend = Backend(authorization_servers=[ATTACKER], claimed_issuer="")

    with pytest.raises(DiscoveryError, match="declares no issuer"):
        _discover(backend)


def test_a_matching_issuer_is_accepted():
    result = _discover(Backend())

    assert result.issuer == HONEST
    assert result.token_endpoint == f"{HONEST}/token"


def test_a_trailing_slash_on_the_pinned_identifier_is_not_a_mismatch():
    """The only normalisation allowed is the one this module itself performs."""
    backend = Backend(authorization_servers=[f"{HONEST}/"], claimed_issuer=HONEST)

    assert _discover(backend).issuer == f"{HONEST}/"


# --- transport --------------------------------------------------------------

def test_a_plaintext_authorization_server_is_refused():
    backend = Backend(authorization_servers=["http://attacker.test/as"])

    with pytest.raises(DiscoveryError, match="not HTTPS"):
        _discover(backend)

    assert backend.token_requests == []


def test_a_plaintext_token_endpoint_is_refused():
    """The issuer can be honest and the endpoint it names still be plaintext."""
    backend = Backend(token_endpoint="http://honest.test/as/token")

    with pytest.raises(DiscoveryError, match="not HTTPS"):
        _discover(backend)


def test_loopback_stays_usable_for_local_development():
    local = "http://127.0.0.1:9000/as"
    backend = Backend(authorization_servers=[local], claimed_issuer=local,
                      token_endpoint=f"{local}/token")

    assert _discover(backend).token_endpoint == f"{local}/token"


def test_disabling_tls_verification_still_allows_a_plaintext_rig():
    """The documented escape hatch keeps working, and only when asked for."""
    backend = Backend(authorization_servers=["http://rig.test/as"],
                      claimed_issuer="http://rig.test/as",
                      token_endpoint="http://rig.test/as/token")

    assert _discover(backend, allow_plaintext=True).issuer == "http://rig.test/as"


def test_require_https_accepts_https_and_loopback_only():
    require_https("https://a.test/x", "endpoint")
    require_https("http://localhost:1/x", "endpoint")
    with pytest.raises(DiscoveryError):
        require_https("http://a.test/x", "endpoint")


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "127.255.255.254", "[::1]"])
def test_the_whole_loopback_range_counts_as_local(host):
    """Isolating local test services on 127.0.0.2 is ordinary, and still local."""
    require_https(f"http://{host}:9000/as", "authorization server")


@pytest.mark.parametrize("host", ["10.0.0.1", "169.254.1.1", "example.com"])
def test_a_non_loopback_address_is_not_exempt(host):
    with pytest.raises(DiscoveryError):
        require_https(f"http://{host}/as", "authorization server")


@pytest.mark.parametrize("issuer", [
    "https://Honest.Test/as",        # httpx lowercases the host it reports
    "https://honest.test:443/as",    # and drops the default port
])
def test_a_differently_spelled_origin_is_not_a_redirect(issuer):
    """A false 'redirected' here would break discovery against a valid server.

    httpx canonicalises the URL it reports, so the response for an unredirected
    request comes back spelled differently than it was asked for. Origins are
    compared as scheme/host/port for that reason — a security check that refuses
    correct deployments is one people switch off.
    """
    backend = Backend(authorization_servers=[issuer], claimed_issuer=issuer,
                      token_endpoint=f"{issuer}/token")

    assert _discover(backend).issuer == issuer


# --- redirects --------------------------------------------------------------

def test_metadata_redirected_to_another_origin_is_refused():
    backend = Backend(authorization_servers=[HONEST],
                      redirect_metadata_to="https://attacker.test/as/.well-known/oauth-authorization-server")

    with pytest.raises(DiscoveryError, match="redirected to another origin"):
        _discover(backend)

    assert backend.token_requests == []


# --- redirection: only a pinned issuer answers this one ---------------------

def test_a_pinned_issuer_refuses_an_authorization_server_it_did_not_register_with():
    backend = Backend(authorization_servers=[ATTACKER], claimed_issuer=ATTACKER,
                      token_endpoint=f"{ATTACKER}/steal")

    with pytest.raises(DiscoveryError, match="pinned issuer"):
        _discover(backend, expected_issuer=HONEST)

    assert backend.token_requests == []


def test_a_pinned_issuer_is_selected_even_when_it_is_not_listed_first():
    backend = Backend(authorization_servers=[ATTACKER, HONEST])

    assert _discover(backend, expected_issuer=HONEST).issuer == HONEST


# --- the leak, end to end ---------------------------------------------------

def test_a_hostile_server_cannot_harvest_the_client_secret():
    """The whole point: a self-consistent attacker AS is still refused when pinned.

    Nothing in the metadata is inconsistent here — the attacker answers at its own
    well-known URL and honestly names itself — so no amount of document checking
    would catch it. What stops the secret is the operator having said which issuer
    these credentials belong to.
    """
    backend = Backend(authorization_servers=[ATTACKER], claimed_issuer=ATTACKER,
                      token_endpoint=f"{ATTACKER}/steal")

    with pytest.raises(AuthError, match="pinned issuer"):
        _authenticate(backend, _matrix(issuer=HONEST))

    assert backend.token_requests == []
    assert "attacker.test" not in backend.hosts_asked_for_tokens


def test_an_unpinned_provider_that_sends_a_secret_is_flagged_by_validate():
    """The residual risk is opt-out, so it has to be visible rather than silent.

    Metadata validation cannot catch an authorization server the target owns and
    names honestly — nothing about it is inconsistent. Only a pinned issuer
    refuses that, and a matrix without one runs while testing less safely than it
    appears to, which is precisely what a warning means here.
    """
    from overstep.matrix import Severity

    problems = _matrix().diagnose()
    warnings = [p for p in problems if p.severity is Severity.WARNING]

    assert any("pins no issuer" in p.message for p in warnings)
    # A warning, not an error: existing matrices keep running.
    assert not [p for p in problems if p.severity is Severity.ERROR]


def test_pinning_the_issuer_clears_the_warning():
    from overstep.matrix import Severity

    problems = _matrix(issuer=HONEST).diagnose()

    assert not [p for p in problems if p.severity is Severity.WARNING]


def test_a_provider_without_a_secret_is_not_warned_about():
    """Nothing to leak, nothing to warn about."""
    from overstep.matrix import Severity

    matrix = _matrix()
    matrix.auth.providers[0].client_secret = None
    problems = matrix.diagnose()

    assert not [p for p in problems if "pins no issuer" in p.message
                and p.severity is Severity.WARNING]


def test_the_secret_reaches_the_registered_issuer_and_only_it():
    backend = Backend(authorization_servers=[HONEST])
    matrix = _matrix(issuer=HONEST)

    _authenticate(backend, matrix)

    assert backend.hosts_asked_for_tokens == ["honest.test"]
    assert backend.token_requests[0]["client_secret"] == "s3cr3t-do-not-leak"
    assert matrix.subjects[0].headers["Authorization"] == "Bearer tok-1"
