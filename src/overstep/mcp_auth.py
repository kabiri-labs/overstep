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
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
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


def _get_json(client: httpx.Client, urls: List[str]) -> Optional[dict]:
    for url in urls:
        try:
            resp = client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code < 400:
            try:
                return resp.json()
            except ValueError:
                continue
    return None


def discover_token_endpoint(
    server_url: str,
    *,
    client: Optional[httpx.Client] = None,
    verify: bool = True,
    timeout: float = 15.0,
) -> DiscoveryResult:
    """Resolve an MCP server's token endpoint + resource via PRM and AS metadata."""
    owns = client is None
    client = client or httpx.Client(timeout=timeout, verify=verify, follow_redirects=True)
    try:
        prm = _get_json(client, _prm_candidates(server_url))
        if not prm:
            raise DiscoveryError(
                f"no Protected Resource Metadata for '{server_url}' "
                f"(RFC 9728 /.well-known/oauth-protected-resource)"
            )
        auth_servers = prm.get("authorization_servers") or []
        if not auth_servers:
            raise DiscoveryError(f"PRM for '{server_url}' lists no authorization_servers")
        resource = prm.get("resource") or server_url
        issuer = auth_servers[0]

        meta = _get_json(client, _as_metadata_candidates(issuer))
        if not meta:
            raise DiscoveryError(f"no Authorization Server Metadata at issuer '{issuer}'")
        token_endpoint = meta.get("token_endpoint")
        if not token_endpoint:
            raise DiscoveryError(f"issuer '{issuer}' metadata has no token_endpoint")

        return DiscoveryResult(
            token_endpoint=token_endpoint,
            resource=resource,
            issuer=issuer,
            registration_endpoint=meta.get("registration_endpoint"),
        )
    finally:
        if owns:
            client.close()
