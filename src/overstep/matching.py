"""Turn a raw HTTP response into an allow/deny decision.

A bare status check is often wrong in the real world — success redirects,
``200`` with an error body, ``403`` masked as ``404``. :class:`ResponseMatcher`
(in overstep.models) captures the intended signal declaratively; this module is
the interpreter for it. Keeping the logic here, separate from the model, means
both the executor and tests can call it directly.
"""
from __future__ import annotations

import re
from typing import List, Optional, Union

from overstep.models import Effect, ResponseMatcher


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


def _search(pattern: Optional[str], body: str) -> bool:
    return bool(pattern) and re.search(pattern, body or "", re.IGNORECASE | re.DOTALL) is not None


def evaluate(matcher: ResponseMatcher, status: int, body: str = "") -> Effect:
    """Decide allow/deny for one response under ``matcher``."""
    # Body signals win over status: this is exactly the 200-with-error-body and
    # masked-404 case. Deny beats allow so an error marker always fails safe.
    if _search(matcher.deny_body_regex, body):
        return Effect.DENY
    if _search(matcher.allow_body_regex, body):
        return Effect.ALLOW

    if 300 <= status < 400 and matcher.treat_redirect_as != "status":
        return Effect.ALLOW if matcher.treat_redirect_as == "allow" else Effect.DENY

    return Effect.ALLOW if status_matches(matcher.allow_status, status) else Effect.DENY
