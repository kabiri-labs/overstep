"""Build a copy-pasteable reproduction for a finding.

A finding is only actionable if a developer can re-run it. This module turns a
test case + subject into a ``curl`` command and a structured request record,
with credentials masked so the output is safe to paste into a report, a ticket
or a shared dashboard.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urljoin

from overstep.executor import build_headers
from overstep.models import Subject, TestCase

# Header names whose value is a secret and must be redacted in any shared output.
_SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}
_MASK = "***"


def mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact secret header values, preserving the scheme prefix where useful."""
    masked: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SECRET_HEADERS:
            # Keep a leading scheme word (e.g. "Bearer") so the shape is clear.
            parts = value.split(" ", 1)
            masked[key] = f"{parts[0]} {_MASK}" if len(parts) == 2 and parts[0].isalpha() else _MASK
        else:
            masked[key] = value
    return masked


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


def request_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """A structured, secret-masked description of the request that was sent."""
    if case.mcp is not None:
        return {
            "method": "tools/call",
            "url": case.mcp.url,
            "tool": case.mcp.tool,
            "arguments": case.mcp.arguments,
            "headers": mask_headers(_mcp_headers(case, subject)),
        }
    return {
        "method": case.method,
        "url": _full_url(base_url, case.path, case.query),
        "headers": mask_headers(build_headers(subject, case)),
        "body": case.body,
    }


def to_curl(base_url: str, subject: Subject, case: TestCase) -> str:
    """Render the request as a ``curl`` command with masked credentials."""
    if case.mcp is not None:
        parts = ["curl", "-sS", "-X", "POST"]
        headers = mask_headers(_mcp_headers(case, subject))
        headers.setdefault("Content-Type", "application/json")
        for key, value in headers.items():
            parts += ["-H", shlex.quote(f"{key}: {value}")]
        parts += ["--data", shlex.quote(json.dumps(_mcp_payload(case)))]
        parts.append(shlex.quote(case.mcp.url))
        return " ".join(parts)

    parts = ["curl", "-sS", "-X", case.method]
    for key, value in mask_headers(build_headers(subject, case)).items():
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if case.body is not None:
        payload = case.body if isinstance(case.body, str) else json.dumps(case.body)
        parts += ["--data", shlex.quote(payload)]
        if not any(p.lower().startswith("content-type") for p in parts):
            parts += ["-H", shlex.quote("Content-Type: application/json")]
    parts.append(shlex.quote(_full_url(base_url, case.path, case.query)))
    return " ".join(parts)
