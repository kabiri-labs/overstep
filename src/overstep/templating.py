"""Runtime ``{{var}}`` placeholder substitution.

Distinct from :mod:`overstep.interpolation`, which resolves ``${ENV}`` once when
the matrix is loaded. ``{{...}}`` placeholders are resolved *later* and against a
*scoped* set of variables: a subject's ``auth.vars`` at login time, or the
captures accumulated by setup steps. Keeping the two syntaxes separate is what
lets secrets come from the environment while per-subject/runtime values are
threaded through without ever landing in the committed file.
"""
from __future__ import annotations

from typing import Any, Dict


def render(value: Any, variables: Dict[str, str]) -> Any:
    """Replace every ``{{name}}`` in ``value`` (recursively) from ``variables``."""
    if isinstance(value, str):
        for key, val in variables.items():
            value = value.replace("{{%s}}" % key, str(val))
        return value
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    return value
