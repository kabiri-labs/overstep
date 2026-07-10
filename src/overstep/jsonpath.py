"""A minimal dotted-path extractor over decoded JSON (a tiny JSONPath subset).

Supports object keys and list indices: ``$.data.items[0].id``. Enough to pull a
token out of a login response or an object id out of a "create" response,
without pulling in a full JSONPath dependency.
"""
from __future__ import annotations

import re
from typing import Any


def extract(path: str, data: Any) -> Any:
    node = data
    for segment in re.findall(r"\w+", path):
        if isinstance(node, list):
            try:
                node = node[int(segment)]
            except (ValueError, IndexError):
                return None
        elif isinstance(node, dict):
            node = node.get(segment)
        else:
            return None
    return node


def set_at(data: Any, path: str, value: Any) -> Any:
    """Set ``value`` at a dotted/indexed path, creating containers as needed.

    Mirrors :func:`extract`'s subset (object keys and list indices, e.g.
    ``$.order.id`` or ``$.items[0].id``). Missing intermediate containers are
    created — a dict, or a list when the next segment is numeric — so an object id
    can be written into a nested body that the template didn't spell out in full.
    Returns the (possibly newly created) root so callers can capture it when the
    body started as ``None``.
    """
    segments = re.findall(r"\w+", path)
    if not segments:
        return data

    def _is_index(seg: str) -> bool:
        return seg.isdigit()

    if data is None:
        data = [] if _is_index(segments[0]) else {}

    node = data
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        next_is_index = (not last) and _is_index(segments[i + 1])

        if _is_index(seg) and isinstance(node, list):
            idx = int(seg)
            while len(node) <= idx:
                node.append(None)
            if last:
                node[idx] = value
            else:
                if not isinstance(node[idx], (dict, list)):
                    node[idx] = [] if next_is_index else {}
                node = node[idx]
        elif isinstance(node, dict):
            if last:
                node[seg] = value
            else:
                child = node.get(seg)
                if not isinstance(child, (dict, list)):
                    child = [] if next_is_index else {}
                    node[seg] = child
                node = child
        else:
            # Can't descend into a scalar; give up rather than corrupt the body.
            break
    return data
