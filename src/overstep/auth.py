"""Dynamic authentication: obtain subject tokens before a run.

Real APIs don't accept a JWT pasted into a config file — it expires, and it
shouldn't be committed anyway. A subject instead points at an auth provider and
supplies its credentials via ``auth.vars``; before the run we perform the login,
extract the token and set it on the subject as a header. Everything here happens
once, up front, over a short-lived synchronous client kept separate from the
async test executor.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from overstep.jsonpath import extract
from overstep.matrix import Matrix
from overstep.models import AuthProvider, Subject
from overstep.templating import render


class AuthError(RuntimeError):
    """Raised when a subject's login fails or no token can be extracted."""


def extract_token(path: str, data: Any) -> Optional[str]:
    """Pull a token string out of a JSON response by a dotted path."""
    value = extract(path, data)
    return value if value is None or isinstance(value, str) else str(value)


def _login_call(provider: AuthProvider, variables: Dict[str, str], base_url: Optional[str]):
    """Build (method, url, kwargs) for a provider's login request."""
    provider_base = provider.base_url or base_url or ""

    if provider.type == "http":
        if provider.request is None:
            raise AuthError(f"auth provider '{provider.name}' (http) needs a request")
        req = provider.request
        url = urljoin(_slash(provider_base), req.path.lstrip("/"))
        kwargs: Dict[str, Any] = {
            "params": render(req.query, variables) or None,
            "json": render(req.body, variables),
            "headers": render(req.headers, variables) or None,
        }
        return req.method, url, kwargs

    # OAuth2 token endpoints: standard form-encoded body.
    if not provider.token_url:
        raise AuthError(f"auth provider '{provider.name}' needs a token_url")
    url = urljoin(_slash(provider_base), provider.token_url.lstrip("/"))
    form: Dict[str, str] = {}
    if provider.type == "oauth2_client_credentials":
        form["grant_type"] = "client_credentials"
    elif provider.type == "oauth2_password":
        form["grant_type"] = "password"
        form["username"] = render(provider.username or "", variables)
        form["password"] = render(provider.password or "", variables)
    for key in ("client_id", "client_secret", "scope"):
        val = render(getattr(provider, key) or "", variables)
        if val:
            form[key] = val
    return "POST", url, {"data": form}


def _slash(base: str) -> str:
    return base if base.endswith("/") else base + "/"


def _obtain_token(
    client: httpx.Client,
    provider: AuthProvider,
    variables: Dict[str, str],
    base_url: Optional[str],
) -> str:
    method, url, kwargs = _login_call(provider, variables, base_url)
    try:
        resp = client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise AuthError(f"login via provider '{provider.name}' failed: {exc}") from exc

    if resp.status_code >= 400:
        raise AuthError(
            f"login via provider '{provider.name}' returned {resp.status_code}"
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise AuthError(
            f"login via provider '{provider.name}' did not return JSON"
        ) from exc

    token = extract_token(provider.token_path, payload)
    if not token:
        raise AuthError(
            f"provider '{provider.name}' response had no token at "
            f"'{provider.token_path}'"
        )
    return token


def authenticate(
    matrix: Matrix,
    *,
    base_url: Optional[str] = None,
    verify_tls: bool = True,
    client: Optional[httpx.Client] = None,
) -> None:
    """Resolve every subject that has an ``auth`` block, in place.

    A no-op when the matrix declares no providers, so runs without dynamic auth
    pay nothing and stay offline.
    """
    providers: Dict[str, AuthProvider] = {p.name: p for p in matrix.auth.providers}
    subjects_with_auth: List[Subject] = [s for s in matrix.subjects if s.auth]
    if not providers or not subjects_with_auth:
        return

    owns_client = client is None
    client = client or httpx.Client(timeout=15.0, verify=verify_tls, follow_redirects=True)
    try:
        for subject in subjects_with_auth:
            provider = providers.get(subject.auth.provider)
            if provider is None:
                raise AuthError(
                    f"subject '{subject.name}' references unknown auth provider "
                    f"'{subject.auth.provider}'"
                )
            token = _obtain_token(client, provider, subject.auth.vars, base_url)
            header_value = provider.token_format.format(token=token)
            subject.headers = {**subject.headers, provider.token_header: header_value}
    finally:
        if owns_client:
            client.close()
