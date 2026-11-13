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

import base64
import json

import httpx

from overstep import netopts

from overstep.jsonpath import extract
from overstep.matrix import Matrix
from overstep.discovery import Discovered, DiscoveryFailed
from overstep.discovery import resolve as resolve_discovery
from overstep.models import SECRET_HEADERS, AuthProvider, Subject
from overstep.templating import render


class AuthError(RuntimeError):
    """Raised when a subject's login fails or no token can be extracted.

    ``defect`` carries a :class:`~overstep.discovery.MetadataDefect` when the
    login never happened because discovery refused a document the target served,
    together with the subject whose authentication was in progress. The run
    still stops — a credential must not be handed to a host that failed the
    check — but the caller can now say in a report why it stopped.
    """

    def __init__(self, message: str, *, defect=None, subject=None):
        super().__init__(message)
        self.defect = defect
        self.subject = subject


def extract_token(path: str, data: Any) -> Optional[str]:
    """Pull a token string out of a JSON response by a dotted path."""
    value = extract(path, data)
    return value if value is None or isinstance(value, str) else str(value)


# RFC 8693 section 2.1 and the registry in section 7.1.
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _login_call(
    provider: AuthProvider,
    variables: Dict[str, str],
    base_url: Optional[str],
    *,
    token_url: Optional[str] = None,
    resource: Optional[str] = None,
    subject_token: Optional[str] = None,
    scope: Optional[str] = None,
):
    """Build (method, url, kwargs) for a provider's login request.

    ``token_url`` / ``resource`` override the provider's own values — used when the
    token endpoint was discovered from an MCP server (RFC 9728/8414) and the token
    must carry a resource indicator (RFC 8707).
    """
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
    effective_token_url = token_url or provider.token_url
    if not effective_token_url:
        raise AuthError(f"auth provider '{provider.name}' needs a token_url or discover_from")
    # A discovered endpoint is absolute; only join a relative one against the base.
    url = effective_token_url if "://" in effective_token_url else urljoin(_slash(provider_base), effective_token_url.lstrip("/"))
    form: Dict[str, str] = {}
    if provider.type == "oauth2_client_credentials":
        form["grant_type"] = "client_credentials"
    elif provider.type == "oauth2_password":
        form["grant_type"] = "password"
        form["username"] = render(provider.username or "", variables)
        form["password"] = render(provider.password or "", variables)
    elif provider.type == "oauth2_token_exchange":
        if not subject_token:
            raise AuthError(
                f"auth provider '{provider.name}' is a token exchange and needs a "
                f"subject_token; it is only reachable through a 'delegation:' entry"
            )
        form["grant_type"] = TOKEN_EXCHANGE_GRANT
        form["subject_token"] = subject_token
        form["subject_token_type"] = ACCESS_TOKEN_TYPE
        # Deliberately no `actor_token`, and therefore deliberately no
        # `actor_token_type`: RFC 8693 section 2.1 makes the type REQUIRED when
        # the token is present and says it MUST NOT be included otherwise.
    for key in ("client_id", "client_secret", "scope"):
        val = render(getattr(provider, key) or "", variables)
        if val:
            form[key] = val
    if scope:
        # A delegation's own requested scope wins over the provider's, because
        # the provider is shared and the chain is what is being tested.
        form["scope"] = scope
    effective_resource = resource or provider.resource
    if effective_resource:
        form["resource"] = effective_resource       # RFC 8707 resource indicator
    return "POST", url, {"data": form}


def _slash(base: str) -> str:
    return base if base.endswith("/") else base + "/"


def _obtain_token(
    client: httpx.Client,
    provider: AuthProvider,
    variables: Dict[str, str],
    base_url: Optional[str],
    *,
    token_url: Optional[str] = None,
    resource: Optional[str] = None,
) -> str:
    method, url, kwargs = _login_call(
        provider, variables, base_url, token_url=token_url, resource=resource
    )
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


def _bearer_value(subject: Subject) -> Optional[str]:
    """The credential this subject presents, as a bare value.

    `token:` is only one of the two places one lives: a provider writes what it
    obtained into `headers` under its own header name, formatted. Either way the
    scheme word is stripped, because what a token exchange wants as its
    `subject_token` is the credential and not the presentation.
    """
    if subject.token:
        return subject.token
    for key, value in subject.headers.items():
        if key.lower() in SECRET_HEADERS and value:
            scheme, _, rest = value.partition(" ")
            return rest if rest and scheme.isalpha() else value
    return None


def _act_claim_present(token: str) -> bool:
    """Whether a JWT's payload carries an RFC 8693 `act` claim.

    This reads the claim; it does not verify anything. There is no signature
    check here and there must not be one implied: the result is evidence for a
    low-severity attribution note and never decides an access finding. A token
    that is not a JWT, or whose payload will not decode, answers False — the
    claim cannot be read, which for this purpose is the same as absent, and the
    note it feeds is opt-in.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw)
    except (ValueError, TypeError):
        return False
    return isinstance(claims, dict) and "act" in claims


def _exchange_for_actor(
    client: httpx.Client,
    matrix: Matrix,
    chain,
    provider: AuthProvider,
    base_url: Optional[str],
) -> None:
    """Mint the actor's credential from the delegator's, and record what came back.

    Three things are recorded on the chain, and the first is the one that makes
    this worth doing rather than trusting the request. RFC 8693 section 2.2.1
    requires the response to carry `scope` whenever the issued scope differs
    from the requested one — so an absent `scope` means the request was honoured
    and a present one is the authorization server saying what it actually
    granted. The run reasons from that, not from what the matrix asked for.
    """
    by_name = {s.name: s for s in matrix.subjects}
    delegator, actor = by_name.get(chain.delegator), by_name.get(chain.actor)
    if delegator is None or actor is None:
        return  # `validate` reports it; nothing here should guess

    subject_token = _bearer_value(delegator)
    if not subject_token:
        raise AuthError(
            f"delegation '{chain.name}' needs a credential for delegator "
            f"'{chain.delegator}' to exchange, and that subject has none"
        )

    requested = " ".join(chain.grant.scopes)
    method, url, kwargs = _login_call(
        provider, {}, base_url,
        subject_token=subject_token, scope=requested or None,
    )
    try:
        resp = client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise AuthError(f"delegation '{chain.name}' exchange failed: {exc}") from exc
    if resp.status_code >= 400:
        raise AuthError(
            f"delegation '{chain.name}' exchange returned {resp.status_code}"
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise AuthError(
            f"delegation '{chain.name}' exchange did not return JSON"
        ) from exc

    token = extract_token(provider.token_path, payload)
    if not token:
        raise AuthError(
            f"delegation '{chain.name}' exchange response had no token at "
            f"'{provider.token_path}'"
        )

    granted = payload.get("scope")
    if isinstance(granted, str) and granted:
        chain._granted_scopes = granted.split()
        chain._scope_was_declined = chain._granted_scopes != chain.grant.scopes
    else:
        # Absent means identical to what was requested (RFC 8693 section 2.2.1).
        chain._granted_scopes = list(chain.grant.scopes)
        chain._scope_was_declined = False
    chain._actor_claim_present = _act_claim_present(token)

    actor.token = token


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
    # A delegation needs the client too, even in a matrix whose subjects all
    # carry static tokens: the exchange is a request of its own.
    if not providers or not (subjects_with_auth or matrix.modules.mcp.delegation):
        return

    discovery_cache: Dict[str, Discovered] = {}

    owns_client = client is None
    client = client or httpx.Client(
        verify=verify_tls, follow_redirects=True, **netopts.client_kwargs()
    )
    try:
        for subject in subjects_with_auth:
            provider = providers.get(subject.auth.provider)
            if provider is None:
                raise AuthError(
                    f"subject '{subject.name}' references unknown auth provider "
                    f"'{subject.auth.provider}'"
                )

            token_url: Optional[str] = None
            resource: Optional[str] = None
            if provider.discover_from:
                if provider.name not in discovery_cache:
                    try:
                        discovery_cache[provider.name] = resolve_discovery(
                            matrix, provider, client=client, verify_tls=verify_tls
                        )
                    except DiscoveryFailed as exc:
                        raise AuthError(
                            str(exc), defect=exc.defect, subject=subject
                        ) from exc
                disc = discovery_cache[provider.name]
                token_url = disc.token_endpoint
                resource = provider.resource or disc.resource

            token = _obtain_token(
                client, provider, subject.auth.vars, base_url,
                token_url=token_url, resource=resource,
            )
            header_value = provider.token_format.format(token=token)
            subject.headers = {**subject.headers, provider.token_header: header_value}

        # After every subject, because a delegation exchanges a credential one
        # of them is now holding.
        for chain in matrix.modules.mcp.delegation:
            provider = providers.get(chain.grant.provider)
            if provider is None:
                raise AuthError(
                    f"delegation '{chain.name}' references unknown auth provider "
                    f"'{chain.grant.provider}'"
                )
            _exchange_for_actor(client, matrix, chain, provider, base_url)
    finally:
        if owns_client:
            client.close()
