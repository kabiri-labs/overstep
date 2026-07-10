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

from overstep.models import McpServer, Subject
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
    if subject and subject.token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {subject.token}"

    with httpx.Client(timeout=timeout, verify=verify) as client:
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": server.protocol_version, "capabilities": {},
                           "clientInfo": {"name": "overstep", "version": "1"}}}
        try:
            resp = client.post(server.url, json=init, headers=headers)
            session = resp.headers.get("mcp-session-id")
            if session:
                headers["Mcp-Session-Id"] = session
        except httpx.HTTPError:
            pass
        resp = client.post(
            server.url,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": tool, "arguments": arguments}},
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

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": server.protocol_version, "capabilities": {},
                         "clientInfo": {"name": "overstep", "version": "1"}}})
        read_id(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": tool, "arguments": arguments}})
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
