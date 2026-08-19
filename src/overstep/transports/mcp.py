"""The MCP transport: deliver a test case as an MCP tool-call.

Speaks MCP over Streamable HTTP (JSON-RPC 2.0) with the same httpx client the HTTP
transport uses — no extra dependency. For each case it performs a best-effort
``initialize`` handshake (capturing a session id if the server issues one) and
then a ``tools/call``, turning the result into an allow/deny Observation via
:mod:`overstep.mcp_matching`. Identity comes from the subject exactly as in HTTP:
the subject's bearer token / headers, merged over the server's own headers.

That handshake is what pins this transport to a protocol revision (see
``SUPPORTED_PROTOCOL_VERSIONS``). A server that refuses it — because it speaks a
revision where ``initialize`` no longer exists — refuses everything after it too,
at the protocol layer rather than the authorization one, so those refusals are
reported as delivery failures instead of being mistaken for denials.

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

from overstep.mcp_matching import content_text, contents_text, contents_uris, evaluate_mcp
from overstep.mcp_protocol import (
    CLIENT_INFO,
    HEADER_MISMATCH,
    PROTOCOL_VERSION_HEADER,
    RESERVED_HEADERS,
    SUPPORTED_PROTOCOL_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION,
    is_stateless,
    request_meta,
    routing_headers,
)
from overstep.models import (
    drop_header,
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

# Statuses that answer "who are you", not "what protocol is this". A server is
# entitled to demand a credential before it will initialize, and that refusal is
# the run's subject matter — it has to stay on the normal allow/deny path.
_AUTH_STATUSES = frozenset({401, 403})

# JSON-RPC's pre-defined codes for a request the server could not accept *as a
# request*. A server denying authorization does not answer with these: it sets
# ``isError`` on a result, or uses a code of its own — JSON-RPC reserves
# -32000..-32099 for implementation-defined server errors, which is where
# "forbidden" lives. So these four, and only these, distinguish a protocol that
# failed from a policy that refused. ``-32603`` (internal error) is deliberately
# absent: servers reach for it to mean anything at all.
_PROTOCOL_ERROR_CODES = frozenset({-32700, -32600, -32601, -32602})


class _Handshake(NamedTuple):
    """What the initialize exchange established, or why it established nothing.

    ``refusal`` is set only when the handshake this protocol version requires
    could not be completed, and it is a suspicion rather than a verdict: a lax
    server that ignores the lifecycle and answers anyway is perfectly testable,
    so the caller confirms it against the request that follows before treating
    it as a delivery failure.
    """

    session: Optional[str] = None
    refusal: Optional[str] = None


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
        subject_authorization = any(k.lower() == "authorization" for k in subject.headers)
        if subject.token or subject_authorization:
            # The subject brings an identity, so the server's is replaced rather
            # than joined — in every spelling, since two Authorization headers
            # differing only in case both travel and the server chooses.
            drop_header(headers, "Authorization")
        headers.update(subject.headers)
        if subject.token and not subject_authorization:
            headers["Authorization"] = f"Bearer {subject.token}"
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json, text/event-stream")
    headers.setdefault("MCP-Protocol-Version", inv.protocol_version)
    if is_stateless(inv.protocol_version):
        # Derived, not defaulted: a stateless server must reject any request
        # whose headers disagree with its body, so these mirror the params being
        # sent and a matrix cannot set them to something else. Every spelling of
        # each is dropped first — header names are case-insensitive while dict
        # keys are not, so a `mcp-method` from the server's own headers would
        # otherwise travel *alongside* the derived one and the server would see
        # exactly the contradiction these headers exist to prevent.
        derived = {PROTOCOL_VERSION_HEADER: inv.protocol_version}
        derived.update(routing_headers(inv.method, jsonrpc_params(inv)))
        for name in RESERVED_HEADERS:
            drop_header(headers, name)
        headers.update(derived)
    return headers


def listed_tool_names(inv: McpInvocation, result: Dict[str, Any]) -> List[str]:
    """Tool names from a ``tools/list`` result; empty for any other method."""
    if inv.method != "tools/list":
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    return [t.get("name", "") for t in tools if isinstance(t, dict) and t.get("name")]


def jsonrpc_params(inv: McpInvocation, cursor: Optional[str] = None) -> Dict[str, Any]:
    """The ``params`` for one invocation.

    ``tools/call`` names a tool and its arguments; every other method overstep
    sends (today, ``tools/list``) names neither, so it goes out with empty params
    rather than a ``name: ""`` the server would have to reject for the wrong
    reason. ``cursor`` continues a paginated listing.

    On a stateless revision the metadata that used to be agreed once at
    ``initialize`` rides here instead, on every request. It is built in this one
    place because the routing headers are derived from the same dict — the two
    have to agree, and a server is entitled to reject the request when they do
    not.
    """
    if inv.method == "tools/call":
        params: Dict[str, Any] = {"name": inv.tool, "arguments": inv.arguments}
    elif inv.method == "resources/read":
        params = {"uri": inv.uri}
    else:
        params = {}
    if cursor:
        params["cursor"] = cursor
    if is_stateless(inv.protocol_version):
        params["_meta"] = request_meta(inv.protocol_version)
    return params


def jsonrpc_request(
    inv: McpInvocation, request_id: int = 2, cursor: Optional[str] = None
) -> Dict[str, Any]:
    """The JSON-RPC request body for one invocation."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": inv.method,
        "params": jsonrpc_params(inv, cursor),
    }


def result_text(inv: McpInvocation, result: Dict[str, Any]) -> str:
    """The searchable text of a result, for markers and content regexes.

    A ``tools/call`` result carries the tool's output in ``content``. Other
    methods answer with a structured result of their own, which has no content
    array — serialising it keeps one text channel for the oracle instead of a
    second, method-shaped one.
    """
    if inv.method == "tools/call":
        return content_text(result.get("content"))
    if inv.method == "resources/read":
        return contents_text(result.get("contents"))
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


def _unusable_protocol(message: dict, protocol_version: str) -> Optional[str]:
    """Why an initialize *reply* leaves overstep unable to drive this server.

    Two shapes say so. A JSON-RPC error means the method itself was rejected —
    on a server that retired ``initialize`` that arrives as "method not found"
    under a perfectly ordinary 200, so the status alone would miss it. And a
    result negotiating a version this transport does not implement means the
    exchange succeeded into a protocol whose rules are not the ones the requests
    below follow.
    """
    if not isinstance(message, dict):
        return None
    error = message.get("error")
    if isinstance(error, dict):
        detail = error.get("message") or error.get("code")
        return (
            f"the server rejected 'initialize' ({detail}) — overstep is configured for "
            f"MCP {protocol_version}, whose handshake this server does not answer"
        )
    result = message.get("result")
    negotiated = result.get("protocolVersion") if isinstance(result, dict) else None
    if isinstance(negotiated, str) and negotiated not in SUPPORTED_PROTOCOL_VERSIONS:
        return (
            f"the server negotiated MCP {negotiated}, which overstep does not implement "
            f"(it speaks {', '.join(sorted(SUPPORTED_PROTOCOL_VERSIONS))})"
        )
    return None


def _jsonrpc_error(resp: httpx.Response) -> Optional[Dict[str, Any]]:
    """The JSON-RPC error object on a response, if it carries one."""
    message = _parse_message(resp)
    error = message.get("error") if isinstance(message, dict) else None
    return error if isinstance(error, dict) else None


def _stateless_rejection(inv: McpInvocation, resp: httpx.Response) -> Optional[str]:
    """Why a stateless server would not accept this request as a request.

    There is no handshake here to have failed, so the evidence has to come from
    the answer — and the revision defines exactly two errors that mean "not the
    protocol you think": the version is one the server does not implement, and
    the headers disagree with the body. Both are specified to arrive under
    ``400``, and neither says anything about the caller.

    Nothing else is read this way. ``-32601`` in particular is left alone: a
    server answering "method not found" to ``resources/read`` is telling us it
    has no resource surface, which is a true answer to a real question, not a
    protocol it cannot speak.
    """
    if resp.status_code in _AUTH_STATUSES:
        return None
    error = _jsonrpc_error(resp)
    if error is None:
        return None
    code = error.get("code")
    if code == UNSUPPORTED_PROTOCOL_VERSION:
        data = error.get("data")
        offered = data.get("supported") if isinstance(data, dict) else None
        detail = ""
        if isinstance(offered, list) and all(isinstance(v, str) for v in offered) and offered:
            detail = f" — it offers {', '.join(offered)}"
        return (
            f"the server does not implement MCP {inv.protocol_version}{detail}"
        )
    if code == HEADER_MISMATCH:
        return (
            f"the server rejected this request's MCP headers as not matching its body, "
            f"so nothing it says here is about authorization"
        )
    return None


def _protocol_rejection(
    inv: McpInvocation, opened: _Handshake, resp: httpx.Response
) -> Optional[str]:
    """Why the protocol, rather than the policy, refused this request.

    The two revisions leave different evidence. A stateless one is refused in
    the answer alone, by a code the spec reserves for it. A stateful one is
    refused at the handshake — and there both halves have to agree, because a
    handshake overstep could not complete is only fatal once the request built
    on it was rejected too: a lax server that ignores the lifecycle and answers
    anyway is testable, and its answers are real.

    On the stateful path the rejection is read from the status *and* the body,
    because JSON-RPC is entitled to report a malformed request under a perfectly
    ordinary 200. Only the pre-defined codes count there: "any JSON-RPC error"
    would rewrite a lax-but-working server's genuine denials into transport
    failures, losing real findings and condemning a run that was testing exactly
    what it should. And a 401/403 is the server talking about the *caller*,
    which is a genuine authorization signal on either revision.
    """
    if is_stateless(inv.protocol_version):
        return _stateless_rejection(inv, resp)
    if opened.refusal is None:
        return None
    if resp.status_code >= 400:
        return None if resp.status_code in _AUTH_STATUSES else opened.refusal
    error = _jsonrpc_error(resp)
    code = error.get("code") if error else None
    return opened.refusal if code in _PROTOCOL_ERROR_CODES else None


async def _initialize(
    client: httpx.AsyncClient, url: str, headers: Dict[str, str], protocol_version: str
) -> _Handshake:
    """Best-effort MCP initialize; report the session id, or why there is none.

    The lifecycle is not finished until the client sends
    ``notifications/initialized``, and a server is entitled to refuse everything
    that arrives before it. stdio has always sent that notification; over HTTP it
    was missing, so a strict server would reject the request that followed and
    the refusal would be recorded as a denial — a clean-looking result produced
    by our own non-conformance rather than by the server's authorization.

    That trap has a second mouth. A server that retired ``initialize`` outright
    refuses the handshake and then refuses everything built on it, at the
    protocol layer, before authorization is ever consulted. Recorded as denials
    those refusals read as a server that forbids everything — which is the shape
    of a *passing* negative test. So the reason is carried out of here instead,
    for the caller to confirm and report as a delivery failure.
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
        # The connection itself failed. The request that follows fails the same
        # way and reports it with the error string the caller needs, so there is
        # nothing to add here.
        return _Handshake()
    session = resp.headers.get("mcp-session-id")
    if resp.status_code >= 400:
        # The handshake was refused; announcing initialization would be a second
        # request making the same point. A 401/403 is the server asking who is
        # calling, which is the question the run exists to ask — only anything
        # else is evidence that the protocol, not the credential, is the problem.
        if resp.status_code in _AUTH_STATUSES:
            return _Handshake(session)
        return _Handshake(session, (
            f"the server refused 'initialize' with HTTP {resp.status_code} — overstep is "
            f"configured for MCP {protocol_version}, whose handshake this server does not answer"
        ))

    refusal = _unusable_protocol(_parse_message(resp), protocol_version)
    if refusal:
        return _Handshake(session, refusal)

    notified = dict(headers)
    if session:
        notified["Mcp-Session-Id"] = session
    try:
        await client.post(
            url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=notified
        )
    except httpx.HTTPError:
        pass
    return _Handshake(session)


async def _handshake(
    client: httpx.AsyncClient, inv: McpInvocation, subject: Subject, headers: Dict[str, str]
) -> _Handshake:
    """Open the session for this invocation; report its id, or why there is none.

    Normally the handshake carries the same identity as the request that follows.
    A session probe deliberately splits the two: ``handshake_headers`` merges over
    the request's, so the session is opened as the victim and then used by a
    request that carries nothing.
    """
    if is_stateless(inv.protocol_version):
        # There is no handshake to perform and no session to be issued: this
        # revision carries all of it on the request itself. Sending one anyway
        # would be a request the server is right to refuse, and the refusal
        # would then be read as evidence about a protocol that is working.
        return _Handshake()
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
    uris: List[str] = []

    @property
    def marker_haystack(self) -> str:
        """Everything a victim's marker could legitimately turn up in.

        The body plus the URIs the result named — searched together, stored
        apart. Folding the URIs into the body would break the JSON parse the
        BOPLA check depends on.
        """
        return "\n".join([self.text, *self.uris]) if self.uris else self.text


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
        contents_uris(result.get("contents")) if inv.method == "resources/read" else [],
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

    A revision that has no sessions at all is skipped before any request is sent.
    The defect this looks for was removed from the protocol, not fixed in the
    server, so there is nothing here to pass or fail — and a probe reported as
    passing would be credit for a control the target never had to implement.
    """
    started = time.perf_counter()

    def elapsed() -> float:
        return round((time.perf_counter() - started) * 1000, 1)

    if is_stateless(inv.protocol_version):
        return Observation(
            test_id=case.id, status=0, effect=Effect.DENY, skipped=True,
            latency_ms=elapsed(),
            error=(
                f"MCP {inv.protocol_version} has no protocol-level sessions, so "
                f"there is no session binding to test"
            ),
        )

    headers = mcp_headers(inv, subject)

    try:
        opened = await _handshake(client, inv, subject, headers)
        session = opened.session
        if not session:
            # Either way there is no session to ride, so the probe is skipped
            # rather than answered. A protocol the handshake could not open says
            # so precisely; without one, the server is simply stateless.
            why = opened.refusal or (
                "server issued no session id — stateless, so there is no session to reuse"
            )
            return Observation(
                test_id=case.id, status=0, effect=Effect.DENY, skipped=True,
                latency_ms=elapsed(), error=why,
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

    if read_only and case.is_mutating:
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
        opened = await _handshake(client, inv, subject, headers)
        if opened.session:
            headers["Mcp-Session-Id"] = opened.session

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
        refusal = _protocol_rejection(inv, opened, resp)
        if refusal:
            # The request never reached the server's authorization, so it is a
            # delivery failure and not the deny it resembles. Status 0 is what
            # every transport reserves for that, and what stops a target
            # answering nothing but 400 from reading as one that carefully
            # forbids everything.
            return Observation(
                test_id=case.id, status=0, effect=Effect.DENY,
                latency_ms=round(elapsed, 1), error=refusal,
            )
        reading = _read(inv, resp)
        listed = reading.listed
        if inv.paginate and reading.effect == Effect.ALLOW and reading.next_cursor:
            listed = await _read_all_pages(
                client, inv, headers, reading,
                max_retries=max_retries, backoff_base=backoff_base,
            )
        effect, text, error = reading.effect, reading.text, reading.error
        haystack = reading.marker_haystack
        matched = [m for m in case.expect_markers if m and m in haystack]
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
        # stdio went stateless with the rest of the protocol: on those revisions
        # the handshake is gone and the metadata rides on the request itself,
        # which `jsonrpc_request` already puts there.
        if not is_stateless(inv.protocol_version):
            await send({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": inv.protocol_version, "capabilities": {},
                           "clientInfo": dict(CLIENT_INFO)},
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
    # Same split as the HTTP path: a resource read's URIs are searched for markers
    # alongside the body, and kept out of it so BOPLA can still parse it.
    uris = contents_uris(result.get("contents")) if inv.method == "resources/read" else []
    haystack = "\n".join([text, *uris]) if uris else text
    matched = [m for m in case.expect_markers if m and m in haystack]
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


def _register() -> None:
    """Imported at call time: mcp_repro imports this module's protocol helpers."""
    from overstep.discovery import register as register_resolver
    from overstep.mcp_auth import resolve_discovery
    from overstep.mcp_fixtures import run_step
    from overstep.mcp_repro import build_record, build_repro

    register(
        "mcp", run_mcp,
        build_record=build_record,
        build_repro=build_repro,
        run_step=run_step,
    )
    register_resolver("mcp", resolve_discovery)


_register()
