"""MCP OAuth 2.1 discovery: find where to authenticate for an MCP server.

The MCP authorization spec builds on OAuth 2.1. Rather than hardcoding a token
endpoint, a client discovers it from the server:

1. **Protected Resource Metadata** (RFC 9728) at
   ``<origin>/.well-known/oauth-protected-resource`` — lists the
   ``authorization_servers`` and the canonical ``resource`` identifier.
2. **Authorization Server Metadata** (RFC 8414, or OIDC discovery) at
   ``<issuer>/.well-known/oauth-authorization-server`` — gives the
   ``token_endpoint`` (and ``registration_endpoint``).

overstep then obtains a token with the usual machine grants (client-credentials or
password), including the ``resource`` indicator (RFC 8707) so the token is
audience-bound. The interactive authorization-code flow is out of scope — an
automated security tool has no browser.

**Discovery is attacker-directed by construction.** The chain starts at the MCP
server under test — which is the one host in the picture that should be assumed
hostile — and that server names the authorization server, which names the token
endpoint, which is where overstep sends ``client_secret`` (and, on the password
grant, a real username and password). Every hop is therefore checked before it is
used:

* the authorization server must be reached over HTTPS;
* its metadata's ``issuer`` must be identical to the identifier used to build the
  well-known URL, per RFC 8414 §3.3 — the spec's own example is a document served
  from ``attacker.example`` claiming ``"issuer": "https://honest.example"``;
* a redirect must not move a metadata fetch to another origin;
* and the token endpoint must be HTTPS too.

A provider may additionally pin ``issuer:``, which is the direct expression of the
rule that client credentials belong to the authorization server that minted them
and must not be presented to another one.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx


class DiscoveryError(RuntimeError):
    """Raised when an MCP server's OAuth metadata cannot be discovered."""


@dataclass(frozen=True)
class DiscoveryResult:
    token_endpoint: str
    resource: str
    issuer: str
    registration_endpoint: Optional[str] = None


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _prm_candidates(server_url: str) -> List[str]:
    origin = _origin(server_url)
    path = urlsplit(server_url).path.rstrip("/")
    urls = [f"{origin}/.well-known/oauth-protected-resource"]
    # RFC 9728 also allows the resource path appended after the well-known suffix.
    if path:
        urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    return urls


def _as_metadata_candidates(issuer: str) -> List[str]:
    base = issuer.rstrip("/")
    return [
        f"{base}/.well-known/oauth-authorization-server",
        f"{base}/.well-known/openid-configuration",
    ]


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _is_loopback(url: str) -> bool:
    """Does this URL address the local machine?

    The whole of ``127.0.0.0/8`` is loopback, not just ``127.0.0.1`` — isolating
    local test services on ``127.0.0.2`` is ordinary — so the address is asked
    rather than matched against a list. A name other than ``localhost`` is not
    resolved: what it points at today is not a decision to make here.
    """
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _origin_key(url: str) -> tuple:
    """A URL's origin as scheme, host and effective port (RFC 6454).

    Compared this way rather than as raw text because httpx canonicalises the
    URL it reports — lowercasing the host, dropping a default port — so
    ``https://Example.com`` comes back spelled differently than it was asked for
    even when nothing was redirected, and a textual comparison would call that a
    cross-origin hop.

    This normalisation is deliberately *not* the one refused in
    :func:`_validate_issuer`. An origin is a network location, and comparing two
    of them is supposed to see through spelling; an issuer is an identifier, and
    normalising it is how two different ones are talked into looking alike.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    port = parts.port or _DEFAULT_PORTS.get(scheme)
    return scheme, (parts.hostname or "").lower(), port


def require_https(url: str, what: str, *, allow_plaintext: bool = False) -> None:
    """OAuth endpoints must be HTTPS; this is where credentials are about to go.

    The MCP authorization spec makes it a flat requirement — "all authorization
    server endpoints MUST be served over HTTPS" — and the reason is immediate
    here: the next thing to travel to this URL is a client secret. Two exemptions,
    both explicit rather than accidental. Loopback is how local development and
    the bundled demos work, and it does not leave the machine. And a run that has
    already turned TLS verification off has made a deliberate choice about
    transport security that it would be strange to override on this one hop.
    """
    if urlsplit(url).scheme == "https" or _is_loopback(url) or allow_plaintext:
        return
    raise DiscoveryError(
        f"{what} '{url}' is not HTTPS — credentials would travel in the clear. "
        f"Use https, a loopback address, or --insecure if this is a test rig."
    )


def _get_json(client: httpx.Client, urls: List[str]) -> Optional[Tuple[str, dict]]:
    """The first candidate that answers with JSON, and the URL that answered.

    The URL comes back because the caller has to know which identifier the
    document is claiming to describe. A redirect that lands on another origin is
    refused outright: metadata fetched from somewhere else is exactly the
    substitution the issuer check below exists to catch, and following it first
    would only give the attacker a second name to satisfy.
    """
    for url in urls:
        try:
            resp = client.get(url)
        except httpx.HTTPError:
            continue
        if _origin_key(str(resp.url)) != _origin_key(url):
            raise DiscoveryError(
                f"metadata request for '{url}' was redirected to another origin "
                f"('{resp.url}') — refusing to trust it"
            )
        if resp.status_code < 400:
            try:
                return url, resp.json()
            except ValueError:
                continue
    return None


def _select_issuer(
    auth_servers: List[str], expected: Optional[str], server_url: str
) -> str:
    """Which authorization server to use, and whether we are allowed to use it.

    ``expected`` is the issuer the provider's credentials were registered with.
    Client identifiers are unique to the authorization server that issued them,
    so a discovery that lands somewhere else is not a fallback to take quietly —
    it is the moment a secret would be handed to a stranger. When it is pinned,
    only that issuer is acceptable; when it is not, the first listed one is used
    exactly as before.
    """
    if expected is None:
        return auth_servers[0]
    for candidate in auth_servers:
        if candidate == expected:
            return candidate
    listed = ", ".join(auth_servers)
    raise DiscoveryError(
        f"'{server_url}' names authorization server(s) [{listed}], none of which is the "
        f"pinned issuer '{expected}' — client credentials belong to the issuer that "
        f"registered them and are not sent elsewhere"
    )


def _validate_issuer(meta: dict, issuer: str, source_url: str) -> None:
    """RFC 8414 §3.3: the document must claim the identifier we asked for.

    Without this the whole chain is decorative — anyone able to answer at the
    well-known URL could name any ``token_endpoint`` they liked. Compared as
    strings, with no normalisation beyond the trailing slash this module itself
    removes when building the URL: normalising an attacker-supplied value is how
    two different identifiers are talked into looking like one.
    """
    claimed = meta.get("issuer")
    if not isinstance(claimed, str) or not claimed:
        raise DiscoveryError(
            f"authorization server metadata at '{source_url}' declares no issuer, so it "
            f"cannot be checked against '{issuer}' (RFC 8414 section 3.3)"
        )
    if claimed not in (issuer, issuer.rstrip("/")):
        raise DiscoveryError(
            f"authorization server metadata at '{source_url}' claims issuer '{claimed}' "
            f"but was requested for '{issuer}' — refusing to use it (RFC 8414 section 3.3)"
        )


def discover_token_endpoint(
    server_url: str,
    *,
    client: Optional[httpx.Client] = None,
    verify: bool = True,
    timeout: float = 15.0,
    expected_issuer: Optional[str] = None,
    allow_plaintext: bool = False,
) -> DiscoveryResult:
    """Resolve an MCP server's token endpoint + resource via PRM and AS metadata.

    Every value used here is supplied by the target, so each is checked before it
    is acted on; see the module docstring for the shape of the attack this closes.
    """
    owns = client is None
    client = client or httpx.Client(timeout=timeout, verify=verify, follow_redirects=True)
    try:
        found = _get_json(client, _prm_candidates(server_url))
        if not found:
            raise DiscoveryError(
                f"no Protected Resource Metadata for '{server_url}' "
                f"(RFC 9728 /.well-known/oauth-protected-resource)"
            )
        _, prm = found
        auth_servers = [s for s in (prm.get("authorization_servers") or []) if isinstance(s, str)]
        if not auth_servers:
            raise DiscoveryError(f"PRM for '{server_url}' lists no authorization_servers")
        resource = prm.get("resource") or server_url
        issuer = _select_issuer(auth_servers, expected_issuer, server_url)
        require_https(issuer, "authorization server", allow_plaintext=allow_plaintext)

        found = _get_json(client, _as_metadata_candidates(issuer))
        if not found:
            raise DiscoveryError(f"no Authorization Server Metadata at issuer '{issuer}'")
        source_url, meta = found
        _validate_issuer(meta, issuer, source_url)

        token_endpoint = meta.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise DiscoveryError(f"issuer '{issuer}' metadata has no token_endpoint")
        require_https(token_endpoint, "token endpoint", allow_plaintext=allow_plaintext)

        return DiscoveryResult(
            token_endpoint=token_endpoint,
            resource=resource,
            issuer=issuer,
            registration_endpoint=meta.get("registration_endpoint"),
        )
    finally:
        if owns:
            client.close()
