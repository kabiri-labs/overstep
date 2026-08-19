"""Driving a stateless MCP server (2026-07-28) end to end.

The revision retired the ``initialize``/``initialized`` handshake and the
``Mcp-Session-Id`` header, and made every Streamable HTTP request carry its own
protocol version, client capabilities and routing headers. A client that still
opens with a handshake is refused before authorization is ever consulted, so
none of the questions overstep exists to ask can be put to such a server.

The server below *enforces* the revision rather than tolerating it: it rejects
the retired handshake, rejects a request whose headers disagree with its body,
rejects one missing the required ``_meta``, and only then applies a real
authorization policy. A run that comes back conclusive against it, with the
planted defect found and the honest denials intact, is the proof that overstep
speaks this protocol — a tolerant mock would prove only that it sends something.
"""
import base64
import json

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.modules.mcp.protocol import (
    HEADER_MISMATCH,
    LEGACY_PROTOCOL_VERSIONS,
    STATELESS_PROTOCOL_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION,
    header_value,
    is_stateless,
    request_meta,
    routing_headers,
)
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan

STATELESS = "2026-07-28"
LEGACY = "2025-06-18"

# What each token is allowed to reach, as the server actually enforces it.
_TOKENS = {"alice-token": "alice", "bob-token": "bob", "admin-token": "root"}
_ADMINS = {"root"}


def _matrix(probes=None, servers=None, **overrides) -> Matrix:
    data = dict(
        modules={"mcp": {
            "probes": probes or {},
            "servers": servers or [{"name": "docs", "url": "http://docs.test/mcp",
                                    "protocol_version": STATELESS}],
        }},
        roles=["anonymous", "user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token",
             "attributes": {"doc_id": "alice"}},
            {"name": "bob", "role": "user", "token": "bob-token",
             "attributes": {"doc_id": "bob"}},
            {"name": "root", "role": "admin", "token": "admin-token",
             "attributes": {"doc_id": "root"}},
        ],
        resources=[
            {"name": "read_document", "call": {"server": "docs", "tool": "read_document",
                      "arguments": {"doc_id": "${doc_id}"}},
             "type": "object", "owner_arg": "doc_id", "owner_attr": "doc_id"},
            {"name": "reset_tenant", "call": {"server": "docs", "tool": "reset_tenant"}, "type": "function"},
        ],
        policy={
            "read_document": {"allow": [{"role": "user", "scope": "own"},
                                        {"role": "admin"}]},
            "reset_tenant": {"allow": [{"role": "admin"}]},
        },
    )
    data.update(overrides)
    return Matrix(**data)


def _error(body, code, message, status=400, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return httpx.Response(status, json={"jsonrpc": "2.0", "id": body.get("id"), "error": err})


class StrictStatelessServer:
    """A server that holds its callers to the 2026-07-28 wire.

    `bola` plants the defect the run is meant to find: any authenticated caller
    can read any document. Everything else is enforced honestly, so the denials
    in the result are the server's policy and not an artifact of a malformed
    request.
    """

    def __init__(self, *, bola: bool = True):
        self.bola = bola
        self.seen_methods: list = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        method = body.get("method", "")
        self.seen_methods.append(method)
        params = body.get("params") or {}

        # 1. The handshake is gone. So is the session header.
        if method in ("initialize", "notifications/initialized"):
            return _error(body, -32601, f"method not found: {method}", status=400)
        if "Mcp-Session-Id" in request.headers:
            return _error(body, -32600, "sessions were removed in 2026-07-28")

        # 2. Required metadata, and the header must agree with it.
        meta = params.get("_meta") or {}
        declared = meta.get("io.modelcontextprotocol/protocolVersion")
        if declared is None or "io.modelcontextprotocol/clientCapabilities" not in meta:
            return _error(body, -32600, "missing required _meta fields")
        if request.headers.get("MCP-Protocol-Version") != declared:
            return _error(body, HEADER_MISMATCH, "protocol version header/body mismatch")
        if declared != STATELESS:
            return _error(body, UNSUPPORTED_PROTOCOL_VERSION, "unsupported protocol version",
                          data={"supported": [STATELESS], "requested": declared})

        # 3. Routing headers, which must mirror the body.
        if request.headers.get("Mcp-Method") != method:
            return _error(body, HEADER_MISMATCH, "Mcp-Method does not match the body")
        expected_name = params.get("name") if method == "tools/call" else params.get("uri")
        if method in ("tools/call", "resources/read"):
            if request.headers.get("Mcp-Name") != header_value(expected_name or ""):
                return _error(body, HEADER_MISMATCH, "Mcp-Name does not match the body")

        # 4. Only now: authorization.
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        subject = _TOKENS.get(token)
        if method == "tools/list":
            if not subject:
                return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, text="")
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"tools": [{"name": "read_document"}, {"name": "reset_tenant"}]},
            })
        if not subject:
            return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, text="")

        tool = params.get("name")
        if tool == "reset_tenant":
            if subject not in _ADMINS:
                return httpx.Response(200, json={
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "result": {"content": [{"type": "text", "text": "forbidden"}],
                               "isError": True},
                })
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": "tenant reset"}]},
            })

        owner = (params.get("arguments") or {}).get("doc_id")
        if not self.bola and owner != subject and subject not in _ADMINS:
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": "forbidden"}],
                           "isError": True},
            })
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": body.get("id"),
            "result": {"content": [{"type": "text", "text": f"document of {owner}"}]},
        })


def _run(matrix, handler):
    import overstep.modules.mcp.transport as mcpmod

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(matrix)
    finally:
        mcpmod.httpx.AsyncClient = orig


# --- the wire itself --------------------------------------------------------

def test_the_revision_sets_are_disjoint_and_the_default_is_stateful():
    """The opt-in property: adopting the new wire is a choice about the target."""
    from overstep.modules.mcp.protocol import DEFAULT_PROTOCOL_VERSION

    assert not (LEGACY_PROTOCOL_VERSIONS & STATELESS_PROTOCOL_VERSIONS)
    assert DEFAULT_PROTOCOL_VERSION in LEGACY_PROTOCOL_VERSIONS
    assert not is_stateless(DEFAULT_PROTOCOL_VERSION)


def test_2025_11_25_is_a_known_stateful_revision():
    """It has initialize/initialized, so the handshake path drives it."""
    assert "2025-11-25" in LEGACY_PROTOCOL_VERSIONS
    assert not is_stateless("2025-11-25")


def test_an_unknown_revision_is_neither_supported_nor_assumed_stateless():
    from overstep.modules.mcp.protocol import is_supported

    assert not is_supported("2099-01-01")
    assert not is_stateless("2099-01-01")


def test_request_meta_carries_what_the_schema_requires():
    meta = request_meta(STATELESS)
    assert meta["io.modelcontextprotocol/protocolVersion"] == STATELESS
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "overstep"


def test_a_listing_carries_no_name_header():
    """`Mcp-Name` mirrors params.name/uri, and a listing has neither."""
    assert routing_headers("tools/list", {}) == {"Mcp-Method": "tools/list"}


def test_a_read_takes_its_name_from_the_uri():
    headers = routing_headers("resources/read", {"uri": "doc://acme/alice"})
    assert headers == {"Mcp-Method": "resources/read", "Mcp-Name": "doc://acme/alice"}


@pytest.mark.parametrize("name", ["ドキュメント", "tool\r\nX-Injected: 1", "café"])
def test_a_name_outside_ascii_travels_base64(name):
    """Also the header-injection guard: a newline cannot reach the wire raw."""
    encoded = header_value(name)
    assert encoded.startswith("=?base64?") and encoded.endswith("?=")
    assert "\r" not in encoded and "\n" not in encoded
    payload = encoded[len("=?base64?"):-len("?=")]
    assert base64.b64decode(payload).decode("utf-8") == name


def test_a_plain_ascii_name_is_sent_as_is():
    assert header_value("read_document") == "read_document"


# --- end to end -------------------------------------------------------------

def test_a_strict_stateless_server_is_driven_and_its_defect_found():
    server = StrictStatelessServer(bola=True)
    result = _run(_matrix(), server)

    # The run means something: requests landed and the credentials were accepted.
    assert not result.health.inconclusive, result.health.reasons
    assert result.health.positive_allowed > 0
    # No handshake was ever attempted.
    assert "initialize" not in server.seen_methods
    assert "notifications/initialized" not in server.seen_methods
    # And the planted cross-owner read was caught.
    assert any(f.vuln_class == VulnClass.BOLA for f in result.findings)


def test_a_correctly_enforcing_stateless_server_comes_back_clean():
    """The other half: no defect planted, so nothing may be reported."""
    server = StrictStatelessServer(bola=False)
    result = _run(_matrix(), server)

    assert not result.health.inconclusive, result.health.reasons
    assert result.findings == []


def test_the_session_probe_is_not_applicable_and_sends_nothing():
    server = StrictStatelessServer(bola=False)
    matrix = _matrix(probes={"session_binding": True})
    result = _run(matrix, server)

    session_ids = {c.id for c in plan(matrix) if c.variant == Variant.SESSION}
    probes = [o for o in result.observations if o.test_id in session_ids]
    assert probes
    for obs in probes:
        assert obs.skipped
        assert "no protocol-level sessions" in (obs.error or "")


def test_reserved_headers_from_the_matrix_do_not_travel_beside_the_derived_ones():
    """Header names are case-insensitive; dict keys are not.

    A `mcp-method` set in `servers[].headers` would otherwise go out alongside
    the derived `Mcp-Method`, and httpx sends both — which is exactly the
    header/body contradiction these headers exist to prevent.
    """
    from overstep.modules.mcp.transport import mcp_headers

    matrix = _matrix(servers=[{
        "name": "docs", "url": "http://docs.test/mcp", "protocol_version": STATELESS,
        "headers": {"mcp-method": "tools/list", "MCP-NAME": "wrong_tool",
                    "mcp-protocol-version": "2025-06-18"},
    }])
    case = next(c for c in plan(matrix)
                if c.mcp and c.mcp.method == "tools/call" and c.variant != Variant.SESSION)
    subject = next(s for s in matrix.subjects if s.name == case.subject)

    headers = mcp_headers(case.mcp, subject)
    for name in ("mcp-method", "mcp-name", "mcp-protocol-version"):
        spellings = [k for k in headers if k.lower() == name]
        assert len(spellings) == 1, f"{name}: {spellings}"
    assert headers["Mcp-Method"] == "tools/call"
    assert headers["Mcp-Name"] == case.mcp.tool
    assert headers["MCP-Protocol-Version"] == STATELESS


def test_a_matrix_supplied_routing_header_cannot_break_the_run():
    """The same thing end to end, against a server that checks the agreement."""
    matrix = _matrix(servers=[{
        "name": "docs", "url": "http://docs.test/mcp", "protocol_version": STATELESS,
        "headers": {"mcp-method": "tools/list"},
    }])
    result = _run(matrix, StrictStatelessServer(bola=False))

    assert not result.health.inconclusive, result.health.reasons
    assert result.findings == []


def test_a_stateless_repro_carries_the_headers_the_server_requires():
    """A repro the server rejects is a false all-clear pasted into a report."""
    from overstep.repro import request_record, to_curl

    matrix = _matrix()
    case = next(c for c in plan(matrix)
                if c.mcp and c.mcp.method == "tools/call" and c.variant != Variant.SESSION)
    subject = next(s for s in matrix.subjects if s.name == case.subject)

    record = request_record("", subject, case)
    headers = record["headers"]
    assert headers["MCP-Protocol-Version"] == STATELESS
    assert headers["Mcp-Method"] == "tools/call"
    assert headers["Mcp-Name"] == case.mcp.tool
    # And the same values reach the pasteable command.
    command = to_curl("", subject, case)
    assert "MCP-Protocol-Version: 2026-07-28" in command
    assert "Mcp-Method: tools/call" in command


def test_a_stateful_repro_still_declares_its_protocol_version():
    """The executor sends it on every revision, so the repro has to as well."""
    from overstep.repro import request_record

    matrix = _matrix(servers=[{"name": "docs", "url": "http://docs.test/mcp",
                               "protocol_version": LEGACY}])
    case = next(c for c in plan(matrix)
                if c.mcp and c.mcp.method == "tools/call" and c.variant != Variant.SESSION)
    subject = next(s for s in matrix.subjects if s.name == case.subject)

    headers = request_record("", subject, case)["headers"]
    assert headers["MCP-Protocol-Version"] == LEGACY
    # Routing headers belong to the stateless wire only.
    assert "Mcp-Method" not in headers


# --- the reverse mismatch ---------------------------------------------------

def test_a_server_that_does_not_implement_the_version_ends_the_run():
    """Configured stateless, pointed at a server that says no."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        return _error(body, UNSUPPORTED_PROTOCOL_VERSION, "unsupported protocol version",
                      data={"supported": [LEGACY], "requested": STATELESS})

    result = _run(_matrix(), handler)

    assert result.health.inconclusive
    reason = " ".join(result.health.reasons)
    assert STATELESS in reason and LEGACY in reason


def test_a_header_mismatch_ends_the_run_rather_than_reading_as_denial():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        return _error(body, HEADER_MISMATCH, "headers do not match the body")

    result = _run(_matrix(), handler)

    assert result.health.inconclusive
    sent = [o for o in result.observations if not o.skipped]
    assert sent and all(o.status == 0 for o in sent)


def test_an_unauthenticated_stateless_call_is_still_an_authorization_result():
    """401 is about the caller on this revision too, not about the protocol."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, text="")

    result = _run(_matrix(), handler)

    sent = [o for o in result.observations if not o.skipped]
    assert sent and all(o.status == 401 for o in sent)
    assert result.health.transport_errors == 0


def test_a_server_error_is_not_mistaken_for_a_protocol_refusal():
    """-32603 and the server-defined range stay on the allow/deny path."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        return _error(body, -32001, "forbidden: not your document", status=200)

    result = _run(_matrix(), handler)

    sent = [o for o in result.observations if not o.skipped]
    assert all(o.status != 0 for o in sent)
    assert all(o.effect == Effect.DENY for o in sent)
