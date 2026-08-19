"""Resolving where a subject should authenticate, when the matrix does not say.

An auth provider may set `discover_from` instead of a `token_url`, naming
something that knows where its own authorization server lives. Working out what
that means — reading Protected Resource Metadata, checking the issuer, deciding
what the token should be audience-bound to — is knowledge about a particular
surface, and `overstep.auth` had it inline: it imported the MCP discovery module
and looked the reference up in the MCP server list.

That made a shared piece of machinery, which every subject with credentials goes
through, unable to exist without the MCP module. The seam is the same one the
transports use: a surface registers a resolver, and the core asks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


class DiscoveryFailed(RuntimeError):
    """A resolver recognised the reference and could not complete it.

    Distinct from returning ``None``, which means "not mine". The difference
    decides whether the next resolver is asked or the run stops: a metadata
    document that fails its issuer check is an error to surface, not a reason to
    let something else guess.
    """


@dataclass(frozen=True)
class Discovered:
    """Where to get a token, and what it will be bound to."""

    token_endpoint: str
    resource: Optional[str] = None


# (matrix, provider, client, verify_tls) -> Discovered | None
ResolverFn = Callable[..., Optional[Discovered]]

_RESOLVERS: Dict[str, ResolverFn] = {}


def register(name: str, resolver: ResolverFn) -> None:
    """Register (or replace) a discovery resolver under a surface's name."""
    _RESOLVERS[name] = resolver


def resolver_names() -> List[str]:
    return list(_RESOLVERS)


def resolve(matrix, provider, *, client, verify_tls: bool) -> Discovered:
    """Ask each registered resolver until one recognises the reference.

    Raises `DiscoveryFailed` when none does, because a provider that named
    something nothing can resolve is a matrix that cannot authenticate — quietly
    falling through to "no token endpoint" would surface much later as an
    unexplained rejection of every request the subject makes.
    """
    for resolver in _RESOLVERS.values():
        found = resolver(matrix, provider, client=client, verify_tls=verify_tls)
        if found is not None:
            return found
    known = ", ".join(sorted(_RESOLVERS)) or "none registered"
    raise DiscoveryFailed(
        f"provider '{provider.name}' discover_from '{provider.discover_from}' "
        f"is not something any surface can resolve (resolvers: {known})"
    )
