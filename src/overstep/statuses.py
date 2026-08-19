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

from typing import List, Union


def status_matches(spec: List[Union[int, str]], status: int) -> bool:
    """Does ``status`` satisfy one of the entries in ``spec``?

    Entries may be an exact code (``200``/``"200"``), an inclusive range
    (``"200-299"``) or a status class (``"2xx"``).
    """
    for item in spec:
        if isinstance(item, int):
            if status == item:
                return True
            continue
        token = str(item).strip().lower()
        if len(token) == 3 and token.endswith("xx") and token[0].isdigit():
            if status // 100 == int(token[0]):
                return True
        elif "-" in token:
            low, high = token.split("-", 1)
            if low.strip().isdigit() and high.strip().isdigit():
                if int(low) <= status <= int(high):
                    return True
        elif token.isdigit() and status == int(token):
            return True
    return False
