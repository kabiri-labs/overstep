"""Tests for the stdio MCP transport (local server subprocesses)."""
import sys

import pytest

from overstep.matrix import Matrix, load_matrix
from overstep.models import VulnClass
from overstep.pipeline import run_pipeline
from overstep.planner import plan


def _stdio_matrix() -> Matrix:
    return Matrix(
        roles=["anonymous", "user", "admin"],
        servers=[{
            "name": "docs",
            "command": [sys.executable, "examples/mcp_api/stdio_server.py"],
            "token_env": "MCP_TOKEN",
        }],
        subjects=[
            {"name": "alice", "role": "user", "token": "alice-token", "marker": "alice@corp.example", "attributes": {"doc_id": "d-alice"}},
            {"name": "bob", "role": "user", "token": "bob-token", "marker": "bob@corp.example", "attributes": {"doc_id": "d-bob"}},
            {"name": "root", "role": "admin", "token": "admin-token"},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {"name": "read_document", "transport": "mcp",
             "call": {"server": "docs", "tool": "read_document"},
             "type": "object", "owner_arg": "doc_id", "owner_attr": "doc_id"},
            {"name": "list_all_users", "transport": "mcp",
             "call": {"server": "docs", "tool": "list_all_users"}, "type": "function"},
            {"name": "reset_tenant", "transport": "mcp",
             "call": {"server": "docs", "tool": "reset_tenant", "mutating": True}, "type": "function"},
        ],
        policy={
            "read_document": {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]},
            "list_all_users": {"allow": [{"role": "admin"}]},
            "reset_tenant": {"allow": [{"role": "admin"}]},
        },
    )


# --- planning ---------------------------------------------------------------

def test_server_kind_is_stdio_when_command_set():
    m = _stdio_matrix()
    assert m.server_map()["docs"].kind == "stdio"


def test_planner_injects_identity_into_env():
    m = _stdio_matrix()
    cases = {c.id: c for c in plan(m)}
    inv = cases["read_document::alice::self"].mcp
    assert inv.kind == "stdio"
    assert inv.command[-1].endswith("stdio_server.py")
    # alice's token is injected into the env var the server reads for identity.
    assert inv.env["MCP_TOKEN"] == "alice-token"
    assert inv.arguments["doc_id"] == "d-alice"


def test_anon_has_no_token_in_env():
    m = _stdio_matrix()
    cases = {c.id: c for c in plan(m)}
    # anon has no token -> nothing injected, the server sees an anonymous caller.
    inv = cases["list_all_users::anon::na"].mcp
    assert "MCP_TOKEN" not in inv.env


# --- operational end-to-end (real subprocesses) -----------------------------

def test_stdio_end_to_end_finds_bola_and_bfla():
    result = run_pipeline(_stdio_matrix())
    by_id = {f.test_id: f for f in result.findings}

    bola = by_id.get("read_document::alice::other")
    assert bola is not None
    assert bola.vuln_class == VulnClass.BOLA
    assert bola.confidence == "confirmed"          # bob's marker leaked via stdio

    priv = by_id.get("list_all_users::alice::na")
    assert priv is not None
    assert priv.vuln_class == VulnClass.PRIVILEGE_ESCALATION

    # reset_tenant is enforced by the server (reads MCP_TOKEN) -> no finding.
    assert "reset_tenant::alice::na" not in by_id
    assert "reset_tenant::anon::na" not in by_id


def test_stdio_read_only_skips_mutating():
    result = run_pipeline(_stdio_matrix(), read_only=True)
    skipped = [o for o in result.observations if o.test_id.startswith("reset_tenant") and o.skipped]
    assert skipped


def test_stdio_finding_repro_shows_env_and_command():
    result = run_pipeline(_stdio_matrix())
    bola = next(f for f in result.findings if f.test_id == "read_document::alice::other")
    assert "stdio_server.py" in bola.curl
    assert "tools/call" in bola.curl
    assert "alice-token" not in bola.curl          # identity masked
    assert bola.request["transport"] == "stdio"


def test_example_stdio_matrix_loads_and_validates():
    m = load_matrix("examples/mcp_api/matrix_stdio.yaml")
    assert m.validate_refs() == []
