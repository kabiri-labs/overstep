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
