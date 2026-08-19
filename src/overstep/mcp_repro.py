"""Rendering an MCP request as evidence: a structured record and a repro.

A finding is only actionable if a developer can re-run it, and what "re-run it"
means is a fact about the surface. Over Streamable HTTP it is a curl carrying
the protocol headers; over stdio it is an environment and a process with a
JSON-RPC message piped in; for a session-binding finding it is two steps,
because the defect *is* the pair.

This lived in `overstep.repro`, which meant a core module imported both
surfaces in order to render either kind of command — and imported the MCP
protocol constants to do it. The core now asks the transport, and the transport
answers here. Masking, shell quoting and credential variables stay shared: they
are the same problem whatever the request looks like.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, Optional

from overstep.mcp_protocol import (
    DEFAULT_PROTOCOL_VERSION,
    PROTOCOL_VERSION_HEADER,
    RESERVED_HEADERS,
    is_stateless,
    request_meta,
    routing_headers,
)
from overstep.models import SECRET_HEADERS as _SECRET_HEADERS
from overstep.models import Subject, TestCase, drop_header
from overstep.repro import _VAR_PREFIX, _mask_env, _shell_arg, credential_var, mask_headers


def _mcp_headers(case: TestCase, subject: Subject) -> Dict[str, str]:
    """The headers the executor actually sent — including sending none.

    Mirrors :func:`overstep.transports.mcp.mcp_headers`. An ``anonymous``
    invocation must come out credential-free here too: a repro that quietly adds
    the subject's token would succeed against a server that correctly refuses the
    request the finding is about, which is worse than having no repro at all.
    """
    inv = case.mcp
    headers: Dict[str, str] = dict(inv.headers) if inv else {}
    if inv is not None and inv.anonymous:
        headers = {k: v for k, v in headers.items() if k.lower() not in _SECRET_HEADERS}
    else:
        headers.update(subject.headers)
        if subject.token and not any(k.lower() == "authorization" for k in subject.headers):
            headers["Authorization"] = f"Bearer {subject.token}"
    if inv is not None:
        # The executor sends the protocol version on every revision, and the
        # routing headers on the stateless one, where both are required for
        # compliance. A repro missing either is a command the server rejects
        # before it ever reaches the authorization the finding is about — a
        # false all-clear pasted into a bug report.
        from overstep.transports.mcp import jsonrpc_params

        for name in RESERVED_HEADERS:
            drop_header(headers, name)
        headers[PROTOCOL_VERSION_HEADER] = inv.protocol_version
        if is_stateless(inv.protocol_version):
            headers.update(routing_headers(inv.method, jsonrpc_params(inv)))
    return headers


def _mcp_handshake_headers(case: TestCase, subject: Subject) -> Dict[str, str]:
    """Headers for the ``initialize`` that opens the session being reused."""
    inv = case.mcp
    headers = dict(inv.headers) if inv else {}
    headers.update(inv.handshake_headers or {} if inv else {})
    headers.setdefault("Content-Type", "application/json")
    return headers


def _initialize_payload(case: TestCase) -> Dict[str, Any]:
    version = case.mcp.protocol_version if case.mcp else DEFAULT_PROTOCOL_VERSION
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "overstep", "version": "1"},
        },
    }


def _mcp_payload(case: TestCase) -> Dict[str, Any]:
    """The JSON-RPC body to paste, matching what the executor actually sent."""
    inv = case.mcp
    if inv is None:
        return {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": case.path, "arguments": {}},
        }
    from overstep.transports.mcp import jsonrpc_request

    return jsonrpc_request(inv, request_id=1)


def _curl(headers: Dict[str, str], payload: Dict[str, Any], url: str, *, head: bool = False) -> str:
    parts = ["curl", "-sS"]
    if head:
        parts += ["-D", "-", "-o", "/dev/null"]
    parts += ["-X", "POST"]
    for key, value in headers.items():
        parts += ["-H", _shell_arg(f"{key}: {value}")]
    parts += ["--data", shlex.quote(json.dumps(payload))]
    parts.append(shlex.quote(url))
    return " ".join(parts)

def _session_repro(subject: Subject, case: TestCase) -> str:
    """Two steps, because the defect only exists across both.

    A single command cannot show this one. The finding is that a session opened
    by one identity is honoured for a request carrying no credential, so the
    repro has to open the session as that identity, keep the id the server
    issued, and then send the request without the credential. Collapsing it into
    one authenticated call — which is what the generic MCP repro produced — is a
    command that succeeds against a correctly secured server and demonstrates
    nothing.
    """
    url = case.mcp.url
    handshake = mask_headers(_mcp_handshake_headers(case, subject), subject.name)
    anonymous = mask_headers(_mcp_headers(case, subject), subject.name)
    # Named with the module's own prefix so `_shell_arg` double-quotes it and the
    # shell expands it. A name outside that convention gets single-quoted like any
    # other literal, and step 2 sends the characters `$SESSION` to the server.
    anonymous["Mcp-Session-Id"] = f"${_VAR_PREFIX}_SESSION"

    open_session = _curl(handshake, _initialize_payload(case), url, head=True)
    extract = "tr -d '\\r' | awk 'tolower($1) == \"mcp-session-id:\" { print $2 }'"
    return (
        f"# 1. open a session as {subject.name} and keep the id the server issues\n"
        f"{_VAR_PREFIX}_SESSION=$({open_session} | {extract})\n"
        f"# 2. the same request carrying that session id and no credential at all\n"
        f"{_curl(anonymous, _mcp_payload(case), url)}"
    )


def build_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """The masked, structured description of what was sent."""
    inv = case.mcp
    if inv is not None and inv.kind == "stdio":
        return {
            "method": inv.method,
            "transport": "stdio",
            "command": inv.command,
            "env": _mask_env(inv.env, subject),
            "tool": inv.tool,
            "arguments": inv.arguments,
            # A stdio resource read has no tool or arguments; without this the
            # evidence would not say which resource was actually read.
            "uri": inv.uri,
        }
    record: Dict[str, Any] = {
        "method": inv.method,
        "url": inv.url,
        "tool": inv.tool,
        "arguments": inv.arguments,
        "uri": inv.uri,
        "headers": mask_headers(_mcp_headers(case, subject), subject.name),
    }
    if inv.handshake_headers:
        # The request above carries no credential; this is what opened the
        # session it rides on, and the pair is the finding.
        record["handshake"] = {
            "method": "initialize",
            "headers": mask_headers(_mcp_handshake_headers(case, subject), subject.name),
        }
    return record


def build_repro(base_url: str, subject: Subject, case: TestCase) -> str:
    """The command that re-runs it, in whichever shape this connection takes."""
    inv = case.mcp
    if inv is not None and inv.kind == "stdio":
        env = " ".join(f"{k}={_shell_arg(v)}" for k, v in _mask_env(inv.env, subject).items())
        cmd = " ".join(shlex.quote(c) for c in inv.command)
        call = json.dumps(_mcp_payload(case))
        prefix = f"{env} " if env else ""
        return f"{prefix}{cmd}  # then send JSON-RPC: {call}"

    if inv.handshake_headers:
        return _session_repro(subject, case)

    parts = ["curl", "-sS", "-X", "POST"]
    headers = mask_headers(_mcp_headers(case, subject), subject.name)
    headers.setdefault("Content-Type", "application/json")
    for key, value in headers.items():
        parts += ["-H", _shell_arg(f"{key}: {value}")]
    parts += ["--data", shlex.quote(json.dumps(_mcp_payload(case)))]
    parts.append(shlex.quote(inv.url))
    return " ".join(parts)
