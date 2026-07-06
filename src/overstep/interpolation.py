"""Environment-variable interpolation for matrix files.

Secrets — tokens, client secrets, passwords — must never live in a committed
matrix. Any ``${VAR}`` in the YAML is replaced from the process environment when
the matrix is loaded; ``${VAR:-default}`` supplies a fallback. Per-subject auth
inputs use a *different* ``{{var}}`` syntax that is resolved later, once per
subject, at login time — so it is deliberately left untouched here.
"""
from __future__ import annotations

import os
import re
from typing import Any, List, Mapping, Optional

# ${NAME} or ${NAME:-default}
_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class InterpolationError(ValueError):
    """Raised when a referenced environment variable is missing."""


def interpolate(obj: Any, env: Optional[Mapping[str, str]] = None) -> Any:
    """Recursively replace ``${VAR}`` in every string within ``obj``.

    Raises :class:`InterpolationError` listing every variable that had no value
    and no default, so a misconfigured pipeline fails loudly instead of sending
    the literal string ``${TOKEN}`` as a credential.
    """
    environ = os.environ if env is None else env
    missing: List[str] = []

    def _string(value: str) -> str:
        def _replace(match: "re.Match[str]") -> str:
            name, default = match.group(1), match.group(2)
            if name in environ:
                return environ[name]
            if default is not None:
                return default
            missing.append(name)
            return match.group(0)

        return _PATTERN.sub(_replace, value)

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            return _string(node)
        if isinstance(node, dict):
            return {key: _walk(val) for key, val in node.items()}
        if isinstance(node, list):
            return [_walk(val) for val in node]
        return node

    result = _walk(obj)
    if missing:
        joined = ", ".join(sorted(set(missing)))
        raise InterpolationError(f"missing environment variable(s): {joined}")
    return result
