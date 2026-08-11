"""Find scaffold placeholders that were never filled in.

``overstep scaffold`` writes a matrix with deliberate holes — ``PASTE_..._TOKEN``
where a credential goes, ``REPLACE_ME_1`` where an object identifier goes. They
are suffixed on purpose (see :mod:`overstep.loaders.openapi`) so that two
subjects cannot be filled in with the same value, which would collapse the
cross-owner probe the tool exists to make.

Left in place, they are not a partial configuration but a guaranteed dead run:
every credential is rejected, so every expected-allow test fails and every
expected-deny test "passes" for the wrong reason. :mod:`overstep.health` catches
that afterwards and refuses to call the run clean, which is the safe outcome —
but it can only report that *something* about the credentials or the matrix is
wrong, after a full pass over the network. The placeholders are visible in the
file before any request is sent, and naming the line is the difference between a
diagnosis and a hint.

The scan reads the file rather than the parsed :class:`~overstep.matrix.Matrix`
for two reasons: line numbers only exist in the text, and ``${ENV}``
interpolation has already run by the time a model exists — the user has to edit
the line as written.
"""
from __future__ import annotations

import re
from typing import Any, Iterator, List, Optional, Tuple

import yaml

from overstep.matrix import Problem, Severity

# The markers `scaffold` emits. Anchored to the whole value: a real credential
# is not rejected for containing these letters somewhere inside it, and every
# placeholder the loaders write is the entire value.
_PLACEHOLDER_RE = re.compile(r"^(?:PASTE_[A-Z0-9_]*TOKEN|REPLACE_ME[A-Z0-9_]*)$")

# What to do about it, per marker family. A token needs a credential; an
# identifier needs a real object that the subject actually owns.
_TOKEN_FIX = (
    "replace it with a real credential, or with a ${ENV_VAR} reference so the "
    "secret stays out of the file"
)
_IDENTIFIER_FIX = (
    "replace it with an object this subject really owns — two subjects must end "
    "up with different values, or the cross-owner probe proves nothing"
)


class _MarkedStr(str):
    """A string that remembers the line of the file it was parsed from."""

    __slots__ = ("line",)

    def __new__(cls, value: str, line: int) -> "_MarkedStr":
        marked = super().__new__(cls, value)
        marked.line = line
        return marked


class _LineLoader(yaml.SafeLoader):
    """A safe loader whose strings carry their line number."""


def _construct_marked_str(loader: yaml.Loader, node: yaml.Node) -> _MarkedStr:
    # start_mark is 0-indexed; editors are not.
    return _MarkedStr(loader.construct_scalar(node), node.start_mark.line + 1)


_LineLoader.add_constructor("tag:yaml.org,2002:str", _construct_marked_str)


def _walk(node: Any, path: str) -> Iterator[Tuple[str, str, Optional[int]]]:
    """Yield ``(path, value, line)`` for every string in a parsed document.

    Keys are walked as well as values: a placeholder used as a mapping key —
    an ``objects:`` entry keyed by a subject that was never renamed — is just
    as dead as one used as a value.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(key, str):
                yield child, key, getattr(key, "line", None)
            yield from _walk(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node, getattr(node, "line", None)


def _fix_for(value: str) -> str:
    return _TOKEN_FIX if value.startswith("PASTE_") else _IDENTIFIER_FIX


def scan(path: str) -> List[Problem]:
    """Report every unfilled scaffold placeholder in a matrix file.

    Returns errors — a matrix carrying these cannot produce a meaningful run.
    A file that cannot be read or parsed yields nothing rather than raising:
    both failures are reported, in more detail, by whoever loaded the matrix.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = yaml.load(handle, Loader=_LineLoader)
    except (OSError, yaml.YAMLError):
        return []

    problems: List[Problem] = []
    for location, value, line in _walk(document, ""):
        if _PLACEHOLDER_RE.match(value):
            problems.append(
                Problem(
                    f"{location} is still the scaffold placeholder '{value}' — "
                    f"{_fix_for(value)}",
                    Severity.ERROR,
                    line,
                )
            )
    # Line order, so the list reads like the file the user is about to edit.
    problems.sort(key=lambda p: (p.line is None, p.line or 0))
    return problems
