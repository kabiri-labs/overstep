"""Turn an MCP tool-call result into an allow/deny decision.

Unlike HTTP, MCP has no status code and no 403. A ``tools/call`` either returns a
JSON-RPC ``error`` object, or a ``result`` that may carry ``isError: true`` with
an error message in its content, or a normal result with the tool's output. This
module interprets that per an :class:`~overstep.models.McpMatcher`, mirroring the
HTTP :mod:`overstep.matching` interpreter so the classifier can stay
transport-agnostic.
"""
from __future__ import annotations

import re
from typing import Any, List, Optional

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
) -> Effect:
    """Decide allow/deny for one MCP tool-call result under ``matcher``."""
    # Explicit content signals win, deny beats allow so an error marker fails safe.
    if _search(matcher.deny_content_regex, text):
        return Effect.DENY
    if _search(matcher.allow_content_regex, text):
        return Effect.ALLOW

    if jsonrpc_error is not None and matcher.jsonrpc_error_is_deny:
        return Effect.DENY
    if is_error and matcher.is_error_is_deny:
        return Effect.DENY

    # The tool ran and returned a result without an error signal -> access granted.
    return Effect.ALLOW
