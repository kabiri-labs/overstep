"""A small *synchronous* MCP client used by setup/teardown fixtures.

The main run executes tool-calls asynchronously (see overstep.transports.mcp), but
setup and teardown run once, sequentially, before/after the suite — so a blocking
client is simpler here. Supports both server kinds: Streamable HTTP (httpx) and
stdio (a subprocess speaking newline-delimited JSON-RPC). Given a server and the
acting subject, it performs ``initialize`` then one ``tools/call`` and returns the
parsed JSON-RPC message.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, Optional

import httpx

from overstep.mcp_protocol import CLIENT_INFO, is_stateless, request_meta, routing_headers
from overstep.models import McpServer, Subject, drop_header
from overstep.transports.mcp import _parse_message


def _http_call(
    server: McpServer, subject: Optional[Subject], tool: str, arguments: Dict[str, Any],
    *, timeout: float, verify: bool,
) -> dict:
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": server.protocol_version,
    }
    headers.update(server.headers)
    if subject:
        # Same precedence as the run transport: the subject's identity replaces
        # the server's in every spelling, and the token yields only to an
        # Authorization the subject set itself.
        subject_auth = any(k.lower() == "authorization" for k in subject.headers)
        if subject.token or subject_auth:
            drop_header(headers, "Authorization")
        headers.update(subject.headers)
        if subject.token and not subject_auth:
            headers["Authorization"] = f"Bearer {subject.token}"

    params: Dict[str, Any] = {"name": tool, "arguments": arguments}
    stateless = is_stateless(server.protocol_version)
    if stateless:
        params["_meta"] = request_meta(server.protocol_version)
        headers.update(routing_headers("tools/call", params))

    with httpx.Client(timeout=timeout, verify=verify) as client:
        if not stateless:
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": server.protocol_version, "capabilities": {},
                               "clientInfo": dict(CLIENT_INFO)}}
            try:
                resp = client.post(server.url, json=init, headers=headers)
                session = resp.headers.get("mcp-session-id")
                if session:
                    headers["Mcp-Session-Id"] = session
            except httpx.HTTPError:
                pass
        resp = client.post(
            server.url,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params},
            headers=headers,
        )
        return _parse_message(resp)


def _stdio_call(
    server: McpServer, subject: Optional[Subject], tool: str, arguments: Dict[str, Any],
    *, timeout: float,
) -> dict:
    env = {**os.environ, **server.env}
    if server.token_env and subject and subject.token is not None:
        env[server.token_env] = subject.token

    proc = subprocess.Popen(
        list(server.command or []),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env, text=True,
    )

    def send(msg: dict) -> None:
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def read_id(want: int) -> dict:
        while True:
            line = proc.stdout.readline()
            if not line:
                return {}
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if isinstance(m, dict) and m.get("id") == want:
                return m

    params: Dict[str, Any] = {"name": tool, "arguments": arguments}
    if is_stateless(server.protocol_version):
        params["_meta"] = request_meta(server.protocol_version)

    try:
        if not is_stateless(server.protocol_version):
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": server.protocol_version, "capabilities": {},
                             "clientInfo": dict(CLIENT_INFO)}})
            read_id(1)
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params})
        return read_id(2)
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()


def mcp_tool_call(
    server: McpServer,
    subject: Optional[Subject],
    tool: str,
    arguments: Dict[str, Any],
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> dict:
    """Perform one MCP tool-call synchronously; return the JSON-RPC message."""
    if server.kind == "stdio":
        return _stdio_call(server, subject, tool, arguments, timeout=timeout)
    return _http_call(server, subject, tool, arguments, timeout=timeout, verify=verify_tls)
