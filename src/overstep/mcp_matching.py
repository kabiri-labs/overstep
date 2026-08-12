"""Turn an MCP tool-call result into an allow/deny decision.

Unlike HTTP, MCP has no 403 of its own. A ``tools/call`` either returns a
JSON-RPC ``error`` object, or a ``result`` that may carry ``isError: true`` with
an error message in its content, or a normal result with the tool's output. This
module interprets that per an :class:`~overstep.models.McpMatcher`, mirroring the
HTTP :mod:`overstep.matching` interpreter so the classifier can stay
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

import re
from typing import Any, List, Optional

from overstep.matching import status_matches
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
