"""Build a copy-pasteable reproduction for a finding.

A finding is only actionable if a developer can re-run it. This module turns a
test case + subject into a ``curl`` command and a structured request record.

Credentials never appear in either: a secret is replaced by a **shell variable
named after the subject it belongs to**, so the output stays safe to paste into
a ticket or a shared dashboard *and* the command still runs once that one
variable is exported. A bare ``***`` achieves the first half only — it makes the
"copy-pasteable repro" a command that answers 401.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, Iterable, Optional, Set
from urllib.parse import urlencode, urljoin

from overstep.models import SECRET_HEADERS as _SECRET_HEADERS
from overstep.models import Observation, Subject, TestCase, drop_header

_MASK = "***"

# Shell variables this module emits in place of credentials.
_VAR_PREFIX = "OVERSTEP"
_VAR_RE = re.compile(r"\$" + _VAR_PREFIX + r"_[A-Z0-9_]+")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper() or "VALUE"


def credential_var(header: str, subject_name: str) -> str:
    """Name the shell variable that carries one subject's credential.

    ``Authorization`` is spelled ``TOKEN`` because that is what it holds and what
    the reader is looking for; other secret headers keep their own name so two
    credentials on one subject never collide.
    """
    kind = "TOKEN" if header.lower() == "authorization" else _slug(header)
    return f"{_VAR_PREFIX}_{kind}_{_slug(subject_name)}"


def mask_headers(headers: Dict[str, str], subject_name: Optional[str] = None) -> Dict[str, str]:
    """Replace secret header values so nothing confidential is written out.

    With a ``subject_name`` the replacement is an expandable shell variable and
    the result is runnable; without one it falls back to a bare mask, which is
    what a caller that only wants redaction gets.
    """
    masked: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() not in _SECRET_HEADERS:
            masked[key] = value
            continue
        secret = f"${credential_var(key, subject_name)}" if subject_name else _MASK
        # Keep a leading scheme word (e.g. "Bearer") so the shape stays obvious.
        parts = value.split(" ", 1)
        masked[key] = f"{parts[0]} {secret}" if len(parts) == 2 and parts[0].isalpha() else secret
    return masked


# A credential shorter than this is not redacted from a response body. Nothing
# that short is a secret worth protecting, and replacing every occurrence of a
# one- or two-character string would shred the evidence it was meant to keep
# safe — a token of "a" would turn a JSON body into punctuation.
_MIN_REDACTABLE = 4


def credential_values(
    subjects: Iterable[Subject], cases: Iterable[TestCase] = ()
) -> Set[str]:
    """Every credential this run holds, for finding them in text it did not write.

    A request's credentials are masked where they are built. A *response* is
    written by the target, and some endpoints reflect what they were given — a
    debug route, a session endpoint, an error that echoes the header it could not
    parse. The evidence a finding carries is that response verbatim, so the
    credential has to be recognised in it, and that means knowing the values.

    Both the raw value and its scheme-stripped tail are collected: a body may
    echo ``Bearer abc123`` or just ``abc123``, and only the second is what a
    ``token:`` in the matrix actually says.
    """
    values: Set[str] = set()

    def add(value: Optional[str]) -> None:
        if not value:
            return
        values.add(value)
        # "Bearer abc123" also hides abc123, which is what the matrix declared.
        scheme, _, rest = value.partition(" ")
        if rest and scheme.isalpha():
            values.add(rest)

    for subject in subjects:
        add(subject.token)
        for key, value in subject.headers.items():
            if key.lower() in _SECRET_HEADERS:
                add(value)
    for case in cases:
        for key, value in case.headers.items():
            if key.lower() in _SECRET_HEADERS:
                add(value)
        # An MCP case carries its credentials on the invocation, not on the case:
        # the server's own headers, the handshake identity when it differs, and
        # for stdio the environment the process is launched with.
        inv = case.mcp
        if inv is None:
            continue
        for headers in (inv.headers, inv.handshake_headers or {}):
            for key, value in headers.items():
                if key.lower() in _SECRET_HEADERS:
                    add(value)
        for key, value in inv.env.items():
            if any(word in key.upper() for word in ("TOKEN", "SECRET", "KEY", "PASSWORD")):
                add(value)

    return {v for v in values if len(v) >= _MIN_REDACTABLE}


def redact(text: str, secrets: Iterable[str]) -> str:
    """Replace every known credential wherever it appears in ``text``.

    Longest first, so a token that contains another one does not leave the
    shorter half behind.
    """
    if not text:
        return text
    for secret in sorted(secrets, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, _MASK)
    return text


def sanitize_evidence(
    obs: Observation, secrets: Iterable[str], body_limit: Optional[int] = None
) -> Observation:
    """The observation as a report may carry it: no credentials, bounded body.

    Every field a target writes is covered, not just the body. A response header
    can echo the credential that was sent (``X-Echo-Token``, a ``Set-Cookie``
    built from the bearer) and an error string can quote the header it failed to
    parse — and the JSON reporter serializes the whole observation, so redacting
    the body alone left the same secret two keys away from where it was removed.

    A secret-looking header is *not* masked wholesale, only where its value is a
    credential this run holds. A ``Set-Cookie`` the target minted itself is
    evidence — the session-hijack finding is about exactly that — and blanking it
    would cost the finding its proof to protect something that was never ours.

    Returns the observation unchanged when there was nothing to do, so an
    already-sanitized one costs a comparison. Applying this twice is the same as
    applying it once.
    """
    secrets = list(secrets)
    body = redact(obs.full_body, secrets)
    if body_limit is not None and len(body) > body_limit:
        body = f"{body[:body_limit]}\n… truncated at {body_limit} bytes"
    update = {
        "full_body": body,
        "body_snippet": redact(obs.body_snippet, secrets),
        "error": redact(obs.error, secrets) if obs.error else obs.error,
        "headers": {k: redact(v, secrets) for k, v in obs.headers.items()},
    }
    if all(getattr(obs, field) == value for field, value in update.items()):
        return obs
    return obs.model_copy(update=update)


def _escape_for_double_quotes(text: str) -> str:
    for char in ("\\", '"', "`", "$"):
        text = text.replace(char, "\\" + char)
    return text


def _shell_arg(text: str) -> str:
    """Quote for the shell, leaving any credential variable expandable.

    ``shlex.quote`` uses single quotes, which would stop the variable from
    expanding and defeat the point of emitting one — so a value that carries one
    is double-quoted instead, with everything else escaped.
    """
    if not _VAR_RE.search(text):
        return shlex.quote(text)
    out: list = []
    cursor = 0
    for match in _VAR_RE.finditer(text):
        out.append(_escape_for_double_quotes(text[cursor:match.start()]))
        out.append(match.group(0))
        cursor = match.end()
    out.append(_escape_for_double_quotes(text[cursor:]))
    return '"' + "".join(out) + '"'


def _full_url(base_url: str, path: str, query: Dict[str, Any]) -> str:
    url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path.lstrip("/"))
    if query:
        url = f"{url}?{urlencode({k: str(v) for k, v in query.items()})}"
    return url






def _mask_env(env: Dict[str, str], subject: Subject, runnable: bool = True) -> Dict[str, str]:
    """Replace identity/secret values in a stdio server's environment.

    Same bargain as the headers: a named variable keeps the secret out of the
    report while leaving the repro executable.
    """
    masked: Dict[str, str] = {}
    for key, value in env.items():
        secret = (
            value == subject.token
            or any(w in key.upper() for w in ("TOKEN", "SECRET", "KEY", "PASSWORD"))
        )
        if not secret:
            masked[key] = value
        elif runnable:
            masked[key] = f"${credential_var(key, subject.name)}"
        else:
            masked[key] = _MASK
    return masked



def _capability(case: TestCase, name: str):
    """The transport's implementation of one rendering capability.

    Imported inside the call rather than at module scope: each surface's
    renderer imports the masking helpers from here, so a module-level import of
    the registry — which pulls those renderers in — would be a cycle. By the
    time a finding is being rendered, everything has loaded.
    """
    from overstep.transports import capability

    return capability(case.transport, name)


def request_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """A structured, secret-masked description of the request that was sent."""
    build = _capability(case, "build_record")
    if build is None:
        # A transport that registered only delivery. Say what is known rather
        # than raising in the middle of writing a report.
        return {"method": case.method, "transport": case.transport}
    return build(base_url, subject, case)


def to_curl(base_url: str, subject: Subject, case: TestCase) -> str:
    """Render the request as a command with credentials masked.

    What that command *is* belongs to the surface — a curl over HTTP, a process
    with an environment over stdio, two steps for a session-binding finding —
    so the surface renders it and this only asks.
    """
    build = _capability(case, "build_repro")
    if build is None:
        return f"# no repro available for transport '{case.transport}'"
    return build(base_url, subject, case)
