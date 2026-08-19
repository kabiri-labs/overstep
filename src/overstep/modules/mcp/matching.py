"""Turn an MCP tool-call result into an allow/deny decision.

Unlike HTTP, MCP has no 403 of its own. A ``tools/call`` either returns a
JSON-RPC ``error`` object, or a ``result`` that may carry ``isError: true`` with
an error message in its content, or a normal result with the tool's output. This
module interprets that per an :class:`~overstep.models.McpMatcher`, mirroring the
HTTP :mod:`overstep.modules.rest.matching` interpreter so the classifier can stay
transport-agnostic.

Over Streamable HTTP there *is* a status code underneath, and authorization
failures are expected to use it: the MCP authorization spec has an unauthorized
request answered with ``401`` and a ``WWW-Authenticate`` header pointing at the
resource metadata. Nothing says the body must then be a JSON-RPC message, and in
practice it often isn't — an empty body, or a framework's own ``{"detail": ...}``
error. That response has no in-band deny signal, so the status is consulted too;
otherwise the safest servers, the ones that reject before dispatching, would be
the ones read as having granted access.
"""
from __future__ import annotations

import base64
import re
from typing import Any, List, Optional

from overstep.statuses import status_matches
from overstep.models import Effect, McpMatcher


def content_text(content: Any) -> str:
    """Flatten an MCP result ``content`` array into searchable text.

    Each content block is typically ``{"type": "text", "text": "..."}``; other
    block types are serialised loosely so markers/regex can still match.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts: List[str] = []
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    parts.append(block["text"])
                else:
                    parts.append(str(block))
            else:
                parts.append(str(block))
    else:
        parts.append(str(content))
    return "\n".join(parts)


def _entries(contents: Any) -> List[Any]:
    if contents is None:
        return []
    return contents if isinstance(contents, list) else [contents]


def contents_text(contents: Any) -> str:
    """Flatten a ``resources/read`` result into the body it returned.

    Each entry is ``{"uri": ..., "text": ...}`` or the same with a base64
    ``blob``. This is the payload channel: what the marker oracle searches, what
    a ``deny_content_regex`` is matched against, and what the BOPLA check parses
    looking for forbidden property keys.

    That last one is why the entry's URI is *not* folded in here. BOPLA reads the
    body as JSON, and a URI on the line above turns a perfectly good JSON
    document into something that does not parse — so prepending it would silently
    switch off forbidden-field detection for every resource read that returns
    JSON, which is most of them. The URI is evidence in its own right and is
    carried separately, by :func:`contents_uris`.

    A blob is decoded when it decodes as UTF-8, since a text document served
    base64 still carries its owner's marker; one that doesn't is left out rather
    than contributing noise a regex could match by accident.
    """
    if isinstance(contents, str):
        return contents

    parts: List[str] = []
    for entry in _entries(contents):
        if not isinstance(entry, dict):
            parts.append(str(entry))
            continue
        if isinstance(entry.get("text"), str):
            parts.append(entry["text"])
        elif isinstance(entry.get("blob"), str):
            try:
                parts.append(base64.b64decode(entry["blob"], validate=True).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                pass
    return "\n".join(parts)


def contents_uris(contents: Any) -> List[str]:
    """The URIs a ``resources/read`` result answered with.

    Kept apart from the body so each can be read as what it is. A read that comes
    back naming the victim's URI reached the victim's object whatever the body
    turned out to hold, so this is searched for markers alongside the payload —
    but never mixed into it, since the body has a parser of its own to satisfy.
    """
    return [
        entry["uri"]
        for entry in _entries(contents)
        if isinstance(entry, dict) and isinstance(entry.get("uri"), str)
    ]


def _search(pattern: Optional[str], text: str) -> bool:
    return bool(pattern) and re.search(pattern, text or "", re.IGNORECASE | re.DOTALL) is not None


def evaluate_mcp(
    matcher: McpMatcher,
    *,
    jsonrpc_error: Optional[dict],
    is_error: bool,
    text: str = "",
    status: Optional[int] = None,
) -> Effect:
    """Decide allow/deny for one MCP tool-call result under ``matcher``.

    ``status`` is the HTTP status of a Streamable HTTP response, or ``None`` for
    stdio, where there is no such thing. It matters because an authorization
    failure on the HTTP leg — the ``401`` the MCP authorization spec asks for —
    can arrive with an empty or non-JSON-RPC body, which carries no in-band deny
    signal at all. Falling through to the "the tool ran" default there would read
    a correct denial as access granted, so the status is consulted before it.
    """
    # Explicit content signals win, deny beats allow so an error marker fails safe.
    if _search(matcher.deny_content_regex, text):
        return Effect.DENY
    if _search(matcher.allow_content_regex, text):
        return Effect.ALLOW

    if status is not None and status_matches(matcher.deny_status, status):
        return Effect.DENY

    if jsonrpc_error is not None and matcher.jsonrpc_error_is_deny:
        return Effect.DENY
    if is_error and matcher.is_error_is_deny:
        return Effect.DENY

    # The tool ran and returned a result without an error signal -> access granted.
    return Effect.ALLOW
