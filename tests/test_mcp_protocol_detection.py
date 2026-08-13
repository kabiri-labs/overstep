"""Finding out which MCP revision a server speaks, instead of assuming.

A run must be told the revision — a matrix pinned to a version is what makes the
result reproducible next release. But the person writing that matrix should not
have to know the answer in advance, and being wrong is not a quiet failure: the
revisions disagree about whether a request opens with a handshake, carries a
session id, repeats its metadata in `params._meta`, or names itself in routing
headers. Send the wrong shape and the refusals come back looking like the server
denied you.

Scaffolding is the one moment where the server is right there and can be asked.
The material was already on the wire, too: every scaffold ever run sent
`initialize` and read the response for a session id, throwing away the
negotiated `protocolVersion` sitting beside it.

These tests cover the ladder — `server/discover` first, since the stateless
revision requires every server to implement it and it answers with the server's
own list, then legacy `initialize` negotiation — and what the scaffold writes
down at the end of it.
"""
import json

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from overstep.cli import app
from overstep.loaders.mcp import detect_protocol_version
from overstep.matrix import Matrix
from overstep.mcp_protocol import (
    DEFAULT_PROTOCOL_VERSION,
    META_PROTOCOL_VERSION,
    preferred_version,
)

URL = "https://mcp.test/mcp"

_TOOLS = [
    {"name": "get_document",
     "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}}},
    {"name": "list_widgets", "inputSchema": {"type": "object", "properties": {}}},
]

_METHOD_NOT_FOUND = -32601
_UNSUPPORTED_PROTOCOL_VERSION = -32022


class Server:
    """A server that speaks exactly one generation, and records what it was asked.

    `seen` is the point of it: the assertions are about which questions got
    asked, in what order, and with what framing — not only about the answer.
    """

    def __init__(self, *, generation, negotiates=None, supported_versions=None,
                 tools=None):
        # "stateless" answers server/discover and refuses initialize;
        # "legacy" the reverse; "both" answers each, which is how a server
        # mid-migration looks; "mute" answers neither.
        self.generation = generation
        self.negotiates = negotiates or DEFAULT_PROTOCOL_VERSION
        self.supported_versions = supported_versions
        self.tools = _TOOLS if tools is None else tools
        self.seen = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        method = body.get("method")
        self.seen.append({
            "method": method,
            "meta": (body.get("params") or {}).get("_meta"),
            "mcp_method_header": request.headers.get("Mcp-Method"),
            "authorization": request.headers.get("Authorization"),
        })

        def result(payload):
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"), "result": payload})

        def error(code, message):
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": body.get("id"),
                "error": {"code": code, "message": message}})

        if method == "server/discover":
            if self.generation not in ("stateless", "both"):
                return error(_METHOD_NOT_FOUND, "unknown method")
            versions = (self.supported_versions if self.supported_versions is not None
                        else ["2026-07-28"])
            return result({"supportedVersions": versions, "capabilities": {"tools": {}}})

        if method == "initialize":
            if self.generation not in ("legacy", "both"):
                return error(_UNSUPPORTED_PROTOCOL_VERSION, "initialize was retired")
            return result({"protocolVersion": self.negotiates, "capabilities": {}})

        if method == "notifications/initialized":
            return httpx.Response(202)

        if method == "tools/list":
            return result({"tools": self.tools})
        if method == "resources/templates/list":
            return error(_METHOD_NOT_FOUND, "unknown method")

        return error(_METHOD_NOT_FOUND, "unknown method")


def _patch(server):
    import overstep.loaders.mcp as loader

    orig = httpx.Client

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(server.handler)
        return orig(*a, **kw)

    loader.httpx.Client = factory
    return orig


def _unpatch(orig):
    import overstep.loaders.mcp as loader

    loader.httpx.Client = orig


def _detect(server, **kwargs):
    orig = _patch(server)
    try:
        return detect_protocol_version(URL, **kwargs)
    finally:
        _unpatch(orig)


def _scaffold(server, *args):
    orig = _patch(server)
    try:
        return CliRunner().invoke(app, ["scaffold", URL, "--fmt", "mcp", *args])
    finally:
        _unpatch(orig)


# --- picking among what a server offers -------------------------------------

def test_the_newest_supported_revision_wins():
    assert preferred_version(["2024-11-05", "2026-07-28", "2025-06-18"]) == "2026-07-28"


def test_a_revision_overstep_cannot_drive_is_not_chosen():
    assert preferred_version(["2099-01-01", "2025-06-18"]) == "2025-06-18"


def test_a_future_dated_unknown_cannot_sort_its_way_in():
    """Ordering decides preference, never eligibility.

    Membership is filtered first precisely so that a server naming a version
    that sorts highest cannot use that to get itself selected.
    """
    assert preferred_version(["9999-12-31"]) is None


def test_nothing_supported_is_not_the_same_as_nothing_offered():
    assert preferred_version([]) is None


def test_non_strings_among_the_offered_versions_are_ignored():
    assert preferred_version([None, 7, {"v": "2026-07-28"}, "2025-06-18"]) == "2025-06-18"


# --- asking the server ------------------------------------------------------

def test_a_stateless_server_is_detected_from_its_own_list():
    server = Server(generation="stateless")

    assert _detect(server) == "2026-07-28"
    assert server.seen[0]["method"] == "server/discover"


def test_the_discover_probe_is_framed_the_way_the_revision_requires():
    """A stateless request that omitted `_meta` or the routing header would be
    refused by a conformant server, and the refusal would read as "not stateless"."""
    server = Server(generation="stateless")

    _detect(server)

    probe = server.seen[0]
    assert probe["mcp_method_header"] == "server/discover"
    assert probe["meta"][META_PROTOCOL_VERSION] == "2026-07-28"


def test_a_legacy_server_is_detected_from_what_it_negotiated():
    server = Server(generation="legacy", negotiates="2025-03-26")

    assert _detect(server) == "2025-03-26"


def test_a_legacy_server_is_asked_about_discovery_first_and_says_no():
    """The -32601 is an answer, not a failure — it is what rules out the newer wire."""
    server = Server(generation="legacy")

    _detect(server)

    assert [s["method"] for s in server.seen] == ["server/discover", "initialize"]


def test_a_server_that_answers_neither_yields_no_answer():
    assert _detect(Server(generation="mute")) is None


def test_a_server_offering_only_versions_overstep_lacks_still_answered():
    """`supportedVersions` naming nothing usable is still an answer, and is kept.

    Falling through to `initialize` is the right next question — it may yet find
    common ground. But if it finds none, discarding what the server plainly said
    would let the caller record the default and then send a handshake at a server
    that retired it, which is the mismatch this whole area exists to avoid.
    """
    server = Server(generation="stateless", supported_versions=["2099-01-01"])

    assert _detect(server) == "2099-01-01"
    assert [s["method"] for s in server.seen] == ["server/discover", "initialize"]


def test_a_usable_revision_found_late_beats_an_unusable_one_offered_early():
    """The unusable answer is a fallback, not a short circuit."""
    server = Server(generation="both", negotiates="2025-03-26",
                    supported_versions=["2099-01-01"])

    assert _detect(server) == "2025-03-26"
    assert [s["method"] for s in server.seen] == ["server/discover", "initialize"]


def test_an_unusable_offered_revision_reaches_the_matrix():
    """The end-to-end shape of the same thing: recorded, not replaced by the default."""
    server = Server(generation="stateless", supported_versions=["2099-01-01"])

    result = _scaffold(server)

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2099-01-01"


def test_the_token_is_offered_to_a_server_that_requires_one_to_answer():
    server = Server(generation="legacy")

    _detect(server, token="t0ken")

    assert all(s["authorization"] == "Bearer t0ken" for s in server.seen)


# --- what the scaffold writes down ------------------------------------------

def _servers_block(output: str):
    return yaml.safe_load(output)["servers"][0]


def test_a_detected_stateless_revision_reaches_the_matrix():
    result = _scaffold(Server(generation="stateless"))

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2026-07-28"


def test_a_negotiated_legacy_revision_reaches_the_matrix():
    """The value was always on the wire; it was being read for the session id and
    thrown away."""
    result = _scaffold(Server(generation="legacy", negotiates="2025-11-25"))

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2025-11-25"


def test_the_scaffolded_matrix_is_still_valid_with_the_version_in_it():
    result = _scaffold(Server(generation="stateless"))

    matrix = Matrix(**yaml.safe_load(result.stdout))

    assert matrix.validate_refs() == []
    assert matrix.server_map()["mcp"].protocol_version == "2026-07-28"


def test_an_explicit_version_is_used_without_asking_the_server():
    """Someone who knows the answer should not have their matrix decided by a probe."""
    server = Server(generation="legacy", negotiates="2024-11-05")

    result = _scaffold(server, "--protocol-version", "2026-07-28")

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2026-07-28"
    assert "server/discover" not in [s["method"] for s in server.seen]


def test_a_revision_overstep_does_not_implement_is_refused_at_the_flag():
    result = _scaffold(Server(generation="legacy"), "--protocol-version", "2030-01-01")

    assert result.exit_code == 2
    assert "not a revision overstep implements" in result.stdout


def test_a_server_speaking_something_unknown_is_recorded_not_overwritten():
    """Recording it makes the run refuse out loud.

    Substituting the default would send a handshake this server may have retired
    and read the refusals as authorization denials — the fail-open closed in
    0.32.1, reintroduced one layer up.
    """
    server = Server(generation="legacy", negotiates="2099-01-01")

    result = _scaffold(server)

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2099-01-01"


def test_an_undetectable_server_falls_back_and_says_so():
    result = _scaffold(Server(generation="mute"))

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == DEFAULT_PROTOCOL_VERSION


def test_a_saved_listing_records_the_default_rather_than_leaving_it_implicit(tmp_path):
    """There is nobody to ask, but the file should still mean the same thing later."""
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": _TOOLS}))

    result = CliRunner().invoke(app, ["scaffold", str(path), "--fmt", "mcp"])

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == DEFAULT_PROTOCOL_VERSION


def test_a_saved_listing_still_honours_an_explicit_version(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": _TOOLS}))

    result = CliRunner().invoke(
        app, ["scaffold", str(path), "--fmt", "mcp", "--protocol-version", "2026-07-28"])

    assert result.exit_code == 0
    assert _servers_block(result.stdout)["protocol_version"] == "2026-07-28"


def test_the_listing_is_fetched_with_the_revision_that_was_detected():
    """Detecting the revision and then listing with a different one would scaffold
    from a surface the server showed to somebody else."""
    server = Server(generation="stateless")

    _scaffold(server)

    listing = [s for s in server.seen if s["method"] == "tools/list"]
    assert listing
    assert all(s["meta"][META_PROTOCOL_VERSION] == "2026-07-28" for s in listing)
