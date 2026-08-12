"""What each MCP revision requires on the wire.

Two shapes of protocol are in the field, and they differ in the one place a
test tool cannot paper over: how a request establishes who is asking and under
which rules.

**Stateful revisions** (through ``2025-11-25``) open with an ``initialize``
exchange, finish it with ``notifications/initialized``, and may carry an
``Mcp-Session-Id`` for everything after. Protocol version, client identity and
capabilities are agreed once, at the top.

**Stateless revisions** (from ``2026-07-28``) retired all three. Each request
stands alone: it repeats the protocol version and client capabilities in its
own ``params._meta``, and Streamable HTTP additionally requires ``Mcp-Method``
and ``Mcp-Name`` headers so gateways can route and meter without parsing the
body. The header and the body must agree — a server whose ``MCP-Protocol-Version``
does not match the ``_meta`` copy must answer ``400`` with ``HeaderMismatch``.

Both shapes are collected here rather than in the transport, because three
callers speak this wire — the run transport, the scaffolding loader, and the
synchronous fixture client — and a revision handled in only two of them is a
tool that runs but cannot be set up.

An unknown version is deliberately *not* guessed at. It is neither set, so the
caller treats it as a protocol it cannot drive and says so, rather than sending
a legacy handshake at a server that retired it and reading the refusals as
authorization denials.
"""
from __future__ import annotations

import base64
from typing import Any, Dict, Mapping, Optional

# Revisions built on the initialize/initialized lifecycle, with an optional
# server-issued session id carried on subsequent requests.
LEGACY_PROTOCOL_VERSIONS = frozenset({
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
})

# Revisions with no handshake and no protocol-level session: every request
# carries its own metadata and routing headers.
STATELESS_PROTOCOL_VERSIONS = frozenset({"2026-07-28"})

SUPPORTED_PROTOCOL_VERSIONS = LEGACY_PROTOCOL_VERSIONS | STATELESS_PROTOCOL_VERSIONS

# Unchanged on purpose. Adopting a revision is a decision about the target, not
# about the tool: a matrix written against a stateful server must keep working
# untouched, so the newer wire is opt-in via `protocol_version` on the server.
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

# Kept as it has always been spelled, so a stateful server sees the same client
# it saw before this module existed.
CLIENT_INFO: Dict[str, str] = {"name": "overstep", "version": "1"}

# Headers a stateless request derives from what it is sending, and which a
# matrix therefore cannot supply: the revision requires each to agree with the
# body, so a value set anywhere else can only disagree with it.
PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
RESERVED_HEADERS = (PROTOCOL_VERSION_HEADER, "Mcp-Method", "Mcp-Name")

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"

# The errors a stateless server returns for a request it will not accept as a
# request. Both are defined to arrive under `400`, and neither is a statement
# about the caller's authorization.
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022

# Which param `Mcp-Name` repeats, per method. Methods absent from this map take
# no name header — `tools/list` names nothing, and sending an empty one would be
# a malformed request rather than an unnamed one.
_NAME_SOURCE: Dict[str, str] = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}


def is_stateless(protocol_version: str) -> bool:
    """Does this revision send each request on its own, with no handshake?

    Membership rather than a date comparison: a version this build has never
    heard of is not assumed to resemble the newest one it knows.
    """
    return protocol_version in STATELESS_PROTOCOL_VERSIONS


def is_supported(protocol_version: str) -> bool:
    """Can either code path here actually drive this revision?"""
    return protocol_version in SUPPORTED_PROTOCOL_VERSIONS


def request_meta(protocol_version: str) -> Dict[str, Any]:
    """The ``params._meta`` a stateless request must carry.

    ``protocolVersion`` and ``clientCapabilities`` are required by the schema;
    ``clientInfo`` is a SHOULD, and is sent because a server that logs who called
    is exactly the server an authorization test wants to be legible to. The
    capabilities are empty and truthfully so: overstep calls tools and reads
    resources, and offers the server nothing to call back into.
    """
    return {
        META_PROTOCOL_VERSION: protocol_version,
        META_CLIENT_INFO: dict(CLIENT_INFO),
        META_CLIENT_CAPABILITIES: {},
    }


def _header_safe(value: str) -> bool:
    """Is every character printable US-ASCII, and therefore safe in a header?"""
    return all(" " <= char <= "~" for char in value)


def header_value(value: str) -> str:
    """A tool name or resource URI, encoded for a header if it has to be.

    The spec only *recommends* that names stay header-safe, so the value here is
    attacker-adjacent input: it comes from the target's own catalogue by way of
    the matrix. Anything outside printable ASCII travels in the base64 sentinel
    form the spec defines, which also means a name carrying a newline cannot
    smuggle a second header into the request.
    """
    if _header_safe(value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def routing_headers(method: str, params: Optional[Mapping[str, Any]] = None) -> Dict[str, str]:
    """``Mcp-Method`` and, where the method names something, ``Mcp-Name``.

    Both are required for compliance on Streamable HTTP. The name is read from
    the params actually being sent rather than passed separately, so the header
    cannot drift from the body it is supposed to mirror — which is the one thing
    a server is entitled to reject the request for.
    """
    headers = {"Mcp-Method": method}
    source = _NAME_SOURCE.get(method)
    if source and params:
        value = params.get(source)
        if isinstance(value, str) and value:
            headers["Mcp-Name"] = header_value(value)
    return headers
