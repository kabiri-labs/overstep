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
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urljoin

from overstep.executor import build_headers
from overstep.models import Subject, TestCase

# Header names whose value is a secret and must be redacted in any shared output.
_SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}
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


def _mcp_headers(case: TestCase, subject: Subject) -> Dict[str, str]:
    inv = case.mcp
    headers: Dict[str, str] = dict(inv.headers) if inv else {}
    headers.update(subject.headers)
    if subject.token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {subject.token}"
    return headers


def _mcp_payload(case: TestCase) -> Dict[str, Any]:
    inv = case.mcp
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": inv.tool if inv else case.path, "arguments": inv.arguments if inv else {}},
    }


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


def request_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """A structured, secret-masked description of the request that was sent."""
    if case.mcp is not None and case.mcp.kind == "stdio":
        return {
            "method": "tools/call",
            "transport": "stdio",
            "command": case.mcp.command,
            "env": _mask_env(case.mcp.env, subject),
            "tool": case.mcp.tool,
            "arguments": case.mcp.arguments,
        }
    if case.mcp is not None:
        return {
            "method": "tools/call",
            "url": case.mcp.url,
            "tool": case.mcp.tool,
            "arguments": case.mcp.arguments,
            "headers": mask_headers(_mcp_headers(case, subject), subject.name),
        }
    record = {
        "method": case.method,
        "url": _full_url(base_url, case.path, case.query),
        "headers": mask_headers(build_headers(subject, case), subject.name),
        "body": case.body,
    }
    if case.form:
        record["form"] = case.form
    return record


def to_curl(base_url: str, subject: Subject, case: TestCase) -> str:
    """Render the request as a ``curl`` command with masked credentials.

    For a stdio MCP call there is no curl; we render a shell repro that sets the
    identity environment and pipes the tools/call into the server process.
    """
    if case.mcp is not None and case.mcp.kind == "stdio":
        env = " ".join(f"{k}={_shell_arg(v)}" for k, v in _mask_env(case.mcp.env, subject).items())
        cmd = " ".join(shlex.quote(c) for c in case.mcp.command)
        call = json.dumps(_mcp_payload(case))
        prefix = f"{env} " if env else ""
        return f"{prefix}{cmd}  # then send JSON-RPC: {call}"

    if case.mcp is not None:
        parts = ["curl", "-sS", "-X", "POST"]
        headers = mask_headers(_mcp_headers(case, subject), subject.name)
        headers.setdefault("Content-Type", "application/json")
        for key, value in headers.items():
            parts += ["-H", _shell_arg(f"{key}: {value}")]
        parts += ["--data", shlex.quote(json.dumps(_mcp_payload(case)))]
        parts.append(shlex.quote(case.mcp.url))
        return " ".join(parts)

    parts = ["curl", "-sS", "-X", case.method]
    for key, value in mask_headers(build_headers(subject, case), subject.name).items():
        parts += ["-H", _shell_arg(f"{key}: {value}")]
    if case.form:
        for key, value in case.form.items():
            parts += ["--data-urlencode", shlex.quote(f"{key}={value}")]
    elif case.body is not None:
        payload = case.body if isinstance(case.body, str) else json.dumps(case.body)
        parts += ["--data", shlex.quote(payload)]
        if not any(p.lower().startswith("content-type") for p in parts):
            parts += ["-H", shlex.quote("Content-Type: application/json")]
    parts.append(shlex.quote(_full_url(base_url, case.path, case.query)))
    return " ".join(parts)
