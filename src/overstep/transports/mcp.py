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
from typing import Any, Dict, List, NamedTuple, Optional

import httpx

from overstep.mcp_matching import content_text, evaluate_mcp
from overstep.models import (
    Effect,
    McpInvocation,
    Observation,
    SECRET_HEADERS,
    Subject,
    TestCase,
    Variant,
)
from overstep.transports.base import register

_RETRY_STATUSES = frozenset({429, 503})

# Upper bound on tools/list pages followed for one probe. Generous for any real
# catalogue, and a hard stop for a server whose cursor never terminates.
_MAX_LIST_PAGES = 20


def mcp_headers(inv: McpInvocation, subject: Subject) -> Dict[str, str]:
    """Assemble request headers: server headers, then subject headers, then a
    bearer derived from the subject's token unless an auth header is already set.

    The token yields to an ``Authorization`` the *subject* set, which is a
    deliberate choice of auth scheme, but not to one inherited from the server:
    that credential belongs to nobody in particular, and letting it stand would
    authenticate every subject as the same identity and quietly make each of them
    untestable.

    An ``anonymous`` invocation gets none of the identity half — no subject
    headers, no bearer, and no credential inherited from the server either, since
    a probe asking what an unauthenticated request achieves has to actually be
    one.
    """
    headers: Dict[str, str] = {}
    headers.update(inv.headers)
    if inv.anonymous:
        headers = {k: v for k, v in headers.items() if k.lower() not in SECRET_HEADERS}
    else:
        headers.update(subject.headers)
        subject_authorization = any(k.lower() == "authorization" for k in subject.headers)
        if subject.token and not subject_authorization:
            headers["Authorization"] = f"Bearer {subject.token}"
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json, text/event-stream")
    headers.setdefault("MCP-Protocol-Version", inv.protocol_version)
    return headers


def listed_tool_names(inv: McpInvocation, result: Dict[str, Any]) -> List[str]:
    """Tool names from a ``tools/list`` result; empty for any other method."""
    if inv.method != "tools/list":
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    return [t.get("name", "") for t in tools if isinstance(t, dict) and t.get("name")]


def jsonrpc_request(
    inv: McpInvocation, request_id: int = 2, cursor: Optional[str] = None
) -> Dict[str, Any]:
    """The JSON-RPC request body for one invocation.

    ``tools/call`` names a tool and its arguments; every other method overstep
    sends (today, ``tools/list``) names neither, so it goes out with empty params
    rather than a ``name: ""`` the server would have to reject for the wrong
    reason. ``cursor`` continues a paginated listing.
    """
    params: Dict[str, Any] = (
        {"name": inv.tool, "arguments": inv.arguments}
        if inv.method == "tools/call"
        else {}
    )
    if cursor:
        params["cursor"] = cursor
    return {"jsonrpc": "2.0", "id": request_id, "method": inv.method, "params": params}


def result_text(inv: McpInvocation, result: Dict[str, Any]) -> str:
    """The searchable text of a result, for markers and content regexes.

    A ``tools/call`` result carries the tool's output in ``content``. Other
    methods answer with a structured result of their own, which has no content
    array — serialising it keeps one text channel for the oracle instead of a
    second, method-shaped one.
    """
    if inv.method == "tools/call":
        return content_text(result.get("content"))
    return json.dumps(result, ensure_ascii=False, sort_keys=True) if result else ""


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
    """Best-effort MCP initialize; return a session id if the server issues one.

    The lifecycle is not finished until the client sends
    ``notifications/initialized``, and a server is entitled to refuse everything
    that arrives before it. stdio has always sent that notification; over HTTP it
    was missing, so a strict server would reject the request that followed and
    the refusal would be recorded as a denial — a clean-looking result produced
    by our own non-conformance rather than by the server's authorization.
    """
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
    session = resp.headers.get("mcp-session-id")
    if resp.status_code >= 400:
        # The handshake was refused; announcing initialization would be a second
        # request making the same point.
        return session

    notified = dict(headers)
    if session:
        notified["Mcp-Session-Id"] = session
    try:
        await client.post(
            url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=notified
        )
    except httpx.HTTPError:
        pass
    return session


async def _handshake(
    client: httpx.AsyncClient, inv: McpInvocation, subject: Subject, headers: Dict[str, str]
) -> Optional[str]:
    """Open the session for this invocation and return its id, if any.

    Normally the handshake carries the same identity as the request that follows.
    A session probe deliberately splits the two: ``handshake_headers`` merges over
    the request's, so the session is opened as the victim and then used by a
    request that carries nothing.
    """
    if inv.handshake_headers:
        headers = {**headers, **inv.handshake_headers}
    return await _initialize(client, inv.url, headers, inv.protocol_version)


async def _post(
    client: httpx.AsyncClient,
    inv: McpInvocation,
    headers: Dict[str, str],
    *,
    max_retries: int,
    backoff_base: float,
    cursor: Optional[str] = None,
) -> httpx.Response:
    """Send one JSON-RPC request, retrying the statuses worth retrying."""
    payload = jsonrpc_request(inv, cursor=cursor)
    for attempt in range(max_retries + 1):
        resp = await client.post(inv.url, json=payload, headers=headers)
        if resp.status_code in _RETRY_STATUSES and attempt < max_retries:
            await asyncio.sleep(backoff_base * (2 ** attempt))
            continue
        return resp
    return resp


class Reading(NamedTuple):
    """One response, interpreted."""

    effect: Effect
    text: str
    listed: List[str]
    error: Optional[str]
    next_cursor: Optional[str]


def _read(inv: McpInvocation, resp: httpx.Response) -> Reading:
    message = _parse_message(resp)
    error = message.get("error") if isinstance(message, dict) else None
    result = message.get("result") if isinstance(message, dict) else None
    result = result if isinstance(result, dict) else {}
    text = result_text(inv, result)
    effect = evaluate_mcp(
        inv.matcher,
        jsonrpc_error=error,
        is_error=bool(result.get("isError")),
        text=text,
        status=resp.status_code,
    )
    cursor = result.get("nextCursor")
    return Reading(
        effect,
        text,
        listed_tool_names(inv, result),
        error.get("message") if isinstance(error, dict) else None,
        cursor if isinstance(cursor, str) and cursor else None,
    )


async def _read_all_pages(
    client: httpx.AsyncClient,
    inv: McpInvocation,
    headers: Dict[str, str],
    first: Reading,
    *,
    max_retries: int,
    backoff_base: float,
) -> List[str]:
    """Every tool across a paginated listing, starting from the first page.

    Bounded: a server that keeps handing back a cursor — by fault or by design —
    must not be able to hold a run open indefinitely. Stopping early under-reports
    rather than hanging, which is the safer of the two failures for a step that
    only ever adds names to a list.
    """
    listed = list(first.listed)
    cursor = first.next_cursor
    seen = {cursor} if cursor else set()
    for _ in range(_MAX_LIST_PAGES):
        if not cursor:
            break
        try:
            page = _read(
                inv,
                await _post(
                    client, inv, headers, cursor=cursor,
                    max_retries=max_retries, backoff_base=backoff_base,
                ),
            )
        except httpx.HTTPError:
            break
        if page.effect != Effect.ALLOW:
            break
        listed.extend(page.listed)
        cursor = page.next_cursor
        if cursor in seen:  # a server cycling its own cursor
            break
        seen.add(cursor)
    return listed


async def _session_probe(
    client: httpx.AsyncClient,
    subject: Subject,
    case: TestCase,
    inv: McpInvocation,
    *,
    max_retries: int,
    backoff_base: float,
) -> Observation:
    """Is a session id worth a credential?

    The MCP spec says sessions must not be used for authentication, because an
    identifier that travels in a header leaks the way headers leak — proxies,
    logs, referrers — and anyone holding one would become the identity that
    opened it.

    Three exchanges answer that. Open a session as the subject, then send the
    same anonymous request twice: once carrying the session id, once without it.
    The second is the control, and it is what keeps this honest — a server whose
    ``tools/list`` is simply public answers the first request too, and calling
    that session hijacking would be a finding about nothing. Only the difference
    between the two is evidence, so the probe is *allowed* only when the session
    was what made it work.

    A server that issues no session id is stateless and has nothing to hijack;
    the probe is skipped rather than answered, since it never ran.
    """
    started = time.perf_counter()
    headers = mcp_headers(inv, subject)

    def elapsed() -> float:
        return round((time.perf_counter() - started) * 1000, 1)

    try:
        session = await _handshake(client, inv, subject, headers)
        if not session:
            return Observation(
                test_id=case.id, status=0, effect=Effect.DENY, skipped=True,
                latency_ms=elapsed(),
                error="server issued no session id — stateless, so there is no session to reuse",
            )

        with_session = await _post(
            client, inv, {**headers, "Mcp-Session-Id": session},
            max_retries=max_retries, backoff_base=backoff_base,
        )
        ridden = _read(inv, with_session)
        rode_session, text, listed, error = ridden.effect, ridden.text, ridden.listed, ridden.error
        if rode_session == Effect.ALLOW:
            control = _read(
                inv,
                await _post(
                    client, inv, headers,
                    max_retries=max_retries, backoff_base=backoff_base,
                ),
            ).effect
        else:
            # Nothing got through even with the session, so the control cannot
            # change the verdict and is not worth a request.
            control = Effect.DENY
    except httpx.HTTPError as exc:
        return Observation(
            test_id=case.id, status=0, effect=Effect.DENY,
            latency_ms=elapsed(), error=str(exc),
        )

    granted = rode_session == Effect.ALLOW and control == Effect.DENY
    note = None
    if rode_session == Effect.ALLOW and control == Effect.ALLOW:
        note = (
            "the same request succeeded without the session id too, so this "
            "endpoint is open to anyone and the session proves nothing"
        )
    return Observation(
        test_id=case.id,
        status=with_session.status_code,
        effect=Effect.ALLOW if granted else Effect.DENY,
        latency_ms=elapsed(),
        headers=dict(with_session.headers),
        body_snippet=text[:2048],
        listed_tools=listed,
        error=note or error,
    )


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

    if inv.kind == "stdio":
        async with semaphore:
            return await _call_stdio(case, inv)

    if case.variant == Variant.SESSION:
        async with semaphore:
            return await _session_probe(
                client, subject, case, inv,
                max_retries=max_retries, backoff_base=backoff_base,
            )

    headers = mcp_headers(inv, subject)
    async with semaphore:
        started = time.perf_counter()
        session = await _handshake(client, inv, subject, headers)
        if session:
            headers["Mcp-Session-Id"] = session

        try:
            resp = await _post(
                client, inv, headers, max_retries=max_retries, backoff_base=backoff_base
            )
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            return Observation(
                test_id=case.id, status=0, effect=Effect.DENY,
                latency_ms=round(elapsed, 1), error=str(exc),
            )

        elapsed = (time.perf_counter() - started) * 1000
        reading = _read(inv, resp)
        listed = reading.listed
        if inv.paginate and reading.effect == Effect.ALLOW and reading.next_cursor:
            listed = await _read_all_pages(
                client, inv, headers, reading,
                max_retries=max_retries, backoff_base=backoff_base,
            )
        effect, text, error = reading.effect, reading.text, reading.error
        matched = [m for m in case.expect_markers if m and m in text]
        return Observation(
            test_id=case.id,
            status=resp.status_code,
            effect=effect,
            latency_ms=round(elapsed, 1),
            headers=dict(resp.headers),
            body_snippet=text[:2048],
            matched_markers=matched,
            listed_tools=listed,
            error=error,
        )


async def _stdio_tools_call(inv, timeout: float = 15.0) -> dict:
    """Launch a stdio MCP server, do the handshake and one tools/call.

    Returns the parsed JSON-RPC message for the call (id 2), or ``{}`` on failure.
    Identity travels in ``inv.env`` (merged over the current environment).
    """
    import os

    child_env = {**os.environ, **inv.env}
    proc = await asyncio.create_subprocess_exec(
        *inv.command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=child_env,
    )

    async def send(msg: dict) -> None:
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        await proc.stdin.drain()

    async def read_id(want: int) -> dict:
        while True:
            line = await proc.stdout.readline()
            if not line:
                return {}
            try:
                msg = json.loads(line.decode())
            except ValueError:
                continue  # ignore any non-JSON noise on stdout
            if isinstance(msg, dict) and msg.get("id") == want:
                return msg

    async def exchange() -> dict:
        await send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": inv.protocol_version, "capabilities": {},
                       "clientInfo": {"name": "overstep", "version": "1"}},
        })
        await read_id(1)
        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        await send(jsonrpc_request(inv))
        return await read_id(2)

    try:
        return await asyncio.wait_for(exchange(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        return {}
    finally:
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except (asyncio.TimeoutError, Exception):
            try:
                proc.kill()
            except Exception:
                pass


async def _call_stdio(case: TestCase, inv) -> Observation:
    started = time.perf_counter()
    try:
        message = await _stdio_tools_call(inv)
    except Exception as exc:  # launch failure -> denied
        return Observation(test_id=case.id, status=0, effect=Effect.DENY, error=str(exc))

    elapsed = (time.perf_counter() - started) * 1000
    error = message.get("error") if isinstance(message, dict) else None
    result = message.get("result") if isinstance(message, dict) else None
    result = result if isinstance(result, dict) else {}
    is_error = bool(result.get("isError"))
    text = result_text(inv, result)
    # No status is passed: stdio has no HTTP leg, and the synthetic status below
    # is a delivery marker, not something a matcher's deny_status should read.
    effect = evaluate_mcp(inv.matcher, jsonrpc_error=error, is_error=is_error, text=text)
    matched = [m for m in case.expect_markers if m and m in text]
    # No HTTP status for stdio; 200 marks a delivered call, 0 a transport failure.
    status = 200 if message else 0
    return Observation(
        test_id=case.id,
        status=status,
        effect=effect,
        latency_ms=round(elapsed, 1),
        body_snippet=text[:2048],
        matched_markers=matched,
        listed_tools=listed_tool_names(inv, result),
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
