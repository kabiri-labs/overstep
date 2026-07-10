"""Tests for MCP setup/teardown: seed objects via tool-calls, capture ids."""
import json

import httpx
import pytest

from overstep.fixtures import SetupError, run_setup, run_teardown
from overstep.matrix import Matrix, load_matrix
from overstep.models import VulnClass
from overstep.pipeline import run_pipeline


class _McpBackend:
    """An in-process MCP server with create/read/delete document tools."""

    def __init__(self):
        self.docs = {}
        self.n = 0
        self.deleted = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        subject = {"alice-token": "alice", "bob-token": "bob"}.get(token, "anon")

        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": mid, "result": {}},
                                  headers={"Mcp-Session-Id": "s"})

        def result(text, is_error=False):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": mid,
                                             "result": {"content": [{"type": "text", "text": text}], "isError": is_error}})

        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "create_document":
            self.n += 1
            doc_id = f"d-{self.n}"
            self.docs[doc_id] = {"owner": subject, "email": f"{subject}@corp.example"}
            return result(json.dumps({"id": doc_id}))
        if name == "read_document":                       # BOLA: no ownership check
            doc = self.docs.get(args.get("doc_id"))
            if not doc:
                return result("not found", is_error=True)
            return result(json.dumps({"owner": doc["owner"], "email": doc["email"]}))
        if name == "delete_document":
            self.deleted.append(args.get("doc_id"))
            self.docs.pop(args.get("doc_id"), None)
            return result(json.dumps({"status": "deleted"}))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "x"}})


def _matrix() -> Matrix:
    return Matrix(
        roles=["anonymous", "user", "admin"],
        servers=[{"name": "docs", "url": "http://mcp.test/mcp"}],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token", "marker": "alice@corp.example"},
            {"name": "bob", "role": "user", "token": "bob-token", "marker": "bob@corp.example"},
        ],
        setup=[
            {"name": "alice creates", "as": "alice",
             "call": {"server": "docs", "tool": "create_document", "arguments": {"body": "x"}},
             "extract": {"ALICE_DOC": "$.id"}},
            {"name": "bob creates", "as": "bob",
             "call": {"server": "docs", "tool": "create_document", "arguments": {"body": "y"}},
             "extract": {"BOB_DOC": "$.id"}},
        ],
        teardown=[
            {"as": "alice", "call": {"server": "docs", "tool": "delete_document", "arguments": {"doc_id": "{{ALICE_DOC}}"}}},
            {"as": "bob", "call": {"server": "docs", "tool": "delete_document", "arguments": {"doc_id": "{{BOB_DOC}}"}}},
        ],
        resources=[{
            "name": "read_document", "transport": "mcp",
            "call": {"server": "docs", "tool": "read_document"},
            "type": "object", "owner_arg": "doc_id",
            "objects": {"alice": "{{ALICE_DOC}}", "bob": "{{BOB_DOC}}"},
        }],
        policy={"read_document": {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]}},
    )


def _patch(backend):
    """Route both the sync (setup/teardown) and async (main run) MCP clients to
    the same in-process backend."""
    import overstep.mcp_client as mc
    import overstep.transports.mcp as mcpmod

    orig_sync, orig_async = httpx.Client, httpx.AsyncClient

    def sync_factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(backend.handler)
        return orig_sync(*a, **kw)

    def async_factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(backend.handler)
        return orig_async(*a, **kw)

    mc.httpx.Client = sync_factory
    mcpmod.httpx.AsyncClient = async_factory
    return orig_sync, orig_async


def _unpatch(origs):
    import overstep.mcp_client as mc
    import overstep.transports.mcp as mcpmod

    mc.httpx.Client, mcpmod.httpx.AsyncClient = origs


def test_mcp_setup_captures_tool_result_ids():
    backend = _McpBackend()
    orig = _patch(backend)
    try:
        context = run_setup(_matrix(), base_url="")
    finally:
        _unpatch(orig)
    assert context["ALICE_DOC"] == "d-1"
    assert context["BOB_DOC"] == "d-2"


def test_mcp_setup_raises_on_missing_capture():
    backend = _McpBackend()
    m = _matrix()
    m.setup[0].extract = {"NOPE": "$.does_not_exist"}
    orig = _patch(backend)
    try:
        with pytest.raises(SetupError):
            run_setup(m, base_url="")
    finally:
        _unpatch(orig)


def test_mcp_teardown_deletes_captured_fixtures():
    backend = _McpBackend()
    orig = _patch(backend)
    try:
        warnings = run_teardown(_matrix(), base_url="", context={"ALICE_DOC": "d-1", "BOB_DOC": "d-2"})
    finally:
        _unpatch(orig)
    assert warnings == []
    assert "d-1" in backend.deleted and "d-2" in backend.deleted


def test_end_to_end_setup_seeds_objects_then_finds_bola():
    backend = _McpBackend()
    orig = _patch(backend)
    try:
        result = run_pipeline(_matrix())
    finally:
        _unpatch(orig)

    by_id = {f.test_id: f for f in result.findings}
    bola = by_id.get("read_document::alice::other")
    assert bola is not None
    assert bola.vuln_class == VulnClass.BOLA
    assert bola.confidence == "confirmed"          # read bob's captured doc -> bob marker
    # teardown ran and removed both created documents.
    assert set(backend.deleted) == {"d-1", "d-2"}


def test_example_setup_matrix_validates():
    m = load_matrix("examples/mcp_api/matrix_setup.yaml")
    assert m.validate_refs() == []
