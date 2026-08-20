"""Reading a status-code specification, for whichever surface wrote one.

`allow_status` on a REST matcher and `deny_status` on an MCP one accept the same
three spellings — an exact code, an inclusive range, a status class — because
they describe the same thing: what an HTTP status is allowed to mean.

It lived in the REST matcher, which made the MCP matcher import the REST module
to read its own configuration. That is the wrong direction for a dependency
between two peer surfaces, and the fix is not to duplicate the parser but to put
it where neither owns it: an HTTP status is a fact about HTTP, and MCP's
Streamable HTTP transport has an HTTP leg of its own.
"""
from __future__ import annotations

from typing import List, Optional, Tuple, Union

# The range a status code can occupy. Anything outside it is not a status that
# an HTTP server can send, so an entry naming one is a typo rather than an
# exotic choice worth honouring.
MIN_STATUS = 100
MAX_STATUS = 599


def parse_entry(item: Union[int, str]) -> Optional[Tuple[int, int]]:
    """The inclusive ``(low, high)`` an entry denotes, or ``None`` if it is not
    a status specification at all.

    Reading and validating go through this one function on purpose. They used to
    be the same code written once, which meant an entry the matcher could not
    read had no way to be reported: ``"2OO"`` with a letter O, ``"20x"``,
    ``banana`` — each fell through every branch and was skipped in silence. A
    spec of nothing but such entries matches no status, so every response reads
    as *deny* and every negative test passes for the wrong reason. Returning the
    parse instead of a bool lets the loader refuse what the matcher cannot read.
    """
    # bool is an int subclass, and `True` is not a status code.
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        return (item, item) if MIN_STATUS <= item <= MAX_STATUS else None

    token = str(item).strip().lower()
    if len(token) == 3 and token.endswith("xx") and token[0].isdigit():
        base = int(token[0]) * 100
        low, high = base, base + 99
    elif "-" in token:
        left, _, right = token.partition("-")
        if not (left.strip().isdigit() and right.strip().isdigit()):
            return None
        low, high = int(left), int(right)
        if low > high:
            # A reversed range matches nothing at all; it is never intended.
            return None
    elif token.isdigit():
        low = high = int(token)
    else:
        return None

    if low < MIN_STATUS or high > MAX_STATUS:
        return None
    return (low, high)


def invalid_entries(spec: List[Union[int, str]]) -> List[str]:
    """Every entry in ``spec`` that :func:`parse_entry` cannot read."""
    return [repr(item) for item in spec if parse_entry(item) is None]


def status_matches(spec: List[Union[int, str]], status: int) -> bool:
    """Does ``status`` satisfy one of the entries in ``spec``?

    Entries may be an exact code (``200``/``"200"``), an inclusive range
    (``"200-299"``) or a status class (``"2xx"``). An entry that is none of these
    is refused when the matrix loads, so nothing unreadable reaches here.
    """
    for item in spec:
        parsed = parse_entry(item)
        if parsed is not None and parsed[0] <= status <= parsed[1]:
            return True
    return False
