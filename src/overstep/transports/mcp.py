"""The MCP transport: deliver a test case as an MCP tool-call.

Speaks MCP over Streamable HTTP (JSON-RPC 2.0) with the same httpx client the HTTP
transport uses — no extra dependency. For each case it performs a best-effort
``initialize`` handshake (capturing a session id if the server issues one) and
then a ``tools/call``, turning the result into an allow/deny Observation via
:mod:`overstep.mcp_matching`. Identity comes from the subject exactly as in HTTP:
the subject's bearer token / headers, merged over the server's own headers.

Only the JSON-response and single-event SSE shapes of Streamable HTTP are handled;
that covers the common non-streaming ``tools/call``. A stdio transport (local MCP
servers via the official SDK) is a separate, future transport.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

import httpx

from overstep.mcp_matching import content_text, evaluate_mcp
from overstep.models import Effect, McpInvocation, Observation, Subject, TestCase
from overstep.transports.base import register

_RETRY_STATUSES = frozenset({429, 503})


def mcp_headers(inv: McpInvocation, subject: Subject) -> Dict[str, str]:
    """Assemble request headers: server headers, then subject headers, then a
    bearer derived from the subject's token unless an auth header is already set."""
    headers: Dict[str, str] = {}
    headers.update(inv.headers)
    headers.update(subject.headers)
    if subject.token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {subject.token}"
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json, text/event-stream")
    headers.setdefault("MCP-Protocol-Version", inv.protocol_version)
    return headers


def _parse_message(resp: httpx.Response) -> dict:
    """Return the JSON-RPC message from a JSON or single-event SSE response."""
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                data = line[len("data:"):].strip()
                if data:
                    try:
                        return json.loads(data)
                    except ValueError:
                        continue
        return {}
    try:
        return resp.json()
    except ValueError:
        return {}


async def _initialize(
    client: httpx.AsyncClient, url: str, headers: Dict[str, str], protocol_version: str
) -> Optional[str]:
    """Best-effort MCP initialize; return a session id if the server issues one."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "overstep", "version": "1"},
        },
    }
    try:
        resp = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError:
        return None
    return resp.headers.get("mcp-session-id")


async def _call(
    client: httpx.AsyncClient,
    subject: Subject,
    case: TestCase,
    semaphore: asyncio.Semaphore,
    *,
    read_only: bool,
    max_retries: int,
    backoff_base: float,
) -> Observation:
    inv = case.mcp
    if inv is None:
        return Observation(test_id=case.id, status=0, effect=Effect.DENY, error="no MCP target on case")

    if read_only and inv.mutating:
        return Observation(
            test_id=case.id,
            status=0,
            effect=Effect.DENY,
            skipped=True,
            error=f"skipped mutating tool '{inv.tool}' under --read-only",
        )

    headers = mcp_headers(inv, subject)
    async with semaphore:
        started = time.perf_counter()
        session = await _initialize(client, inv.url, headers, inv.protocol_version)
        if session:
            headers["Mcp-Session-Id"] = session

        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": inv.tool, "arguments": inv.arguments},
        }
        resp = None
        for attempt in range(max_retries + 1):
            try:
                resp = await client.post(inv.url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                elapsed = (time.perf_counter() - started) * 1000
                return Observation(
                    test_id=case.id, status=0, effect=Effect.DENY,
                    latency_ms=round(elapsed, 1), error=str(exc),
                )
            if resp.status_code in _RETRY_STATUSES and attempt < max_retries:
                await asyncio.sleep(backoff_base * (2 ** attempt))
                continue
            break

        elapsed = (time.perf_counter() - started) * 1000
        message = _parse_message(resp)
        error = message.get("error") if isinstance(message, dict) else None
        result = message.get("result") if isinstance(message, dict) else None
        result = result if isinstance(result, dict) else {}
        is_error = bool(result.get("isError"))
        text = content_text(result.get("content"))
        effect = evaluate_mcp(inv.matcher, jsonrpc_error=error, is_error=is_error, text=text)
        matched = [m for m in case.expect_markers if m and m in text]
        return Observation(
            test_id=case.id,
            status=resp.status_code,
            effect=effect,
            latency_ms=round(elapsed, 1),
            headers=dict(resp.headers),
            body_snippet=text[:2048],
            matched_markers=matched,
            error=(error.get("message") if isinstance(error, dict) else None),
        )


async def execute_mcp(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    *,
    concurrency: int = 10,
    timeout: float = 15.0,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
    **_ignored: Any,
) -> List[Observation]:
    """Run every MCP case and return one observation per case. ``base_url`` is
    ignored — each case carries its own MCP endpoint URL."""
    subject_map: Dict[str, Subject] = {s.name: s for s in subjects}
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=timeout, verify=verify_tls, follow_redirects=False) as client:
        tasks = [
            _call(
                client, subject_map[c.subject], c, semaphore,
                read_only=read_only, max_retries=max_retries, backoff_base=backoff_base,
            )
            for c in cases
        ]
        return await asyncio.gather(*tasks)


def run_mcp(base_url: str, subjects: List[Subject], cases: List[TestCase], **kwargs) -> List[Observation]:
    """Synchronous wrapper registered as the ``mcp`` transport."""
    return asyncio.run(execute_mcp(base_url, subjects, cases, **kwargs))


register("mcp", run_mcp)
