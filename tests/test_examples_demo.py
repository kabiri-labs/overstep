"""The bundled MCP demo, run end to end against its own server.

The README publishes this run's numbers — tests, findings, the class breakdown —
as the first thing a reader sees. Nothing else in the suite pins them, so a
change to the demo server or to the matrix could quietly leave the README
describing a run that no longer happens. That is a documentation bug nobody
notices, so it gets a test.

The point of the demo is that it exercises both halves of the tool: the
per-operation probes (BOLA on a tool argument and on a resource URI, BFLA on an
admin-only tool) *and* the protocol probes that ask about the connection rather
than about any one operation (a session id honoured in place of a credential, a
listing that advertises tools the caller may not invoke).

The server is driven in-process over ASGI, so the test needs no port and no
subprocess.
"""
import importlib.util
import os
from collections import Counter

import httpx
import pytest

from overstep.matrix import load_matrix
from overstep.models import Effect, Variant, VulnClass
from overstep.pipeline import run_pipeline
from overstep.report.base import summarize

# `examples/` is not a package and not installed, and the repository root is on
# `sys.path` only when pytest happens to be invoked as `python -m pytest`. Both
# paths are resolved from this file so the suite runs the same from any working
# directory.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATRIX = os.path.join(_ROOT, "examples", "mcp_api", "matrix.yaml")
_SERVER = os.path.join(_ROOT, "examples", "mcp_api", "server.py")


@pytest.fixture
def demo_app():
    """A fresh server module per test — the demo mutates its own state."""
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location("overstep_demo_mcp_server", _SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def _run(app):
    import overstep.transports.mcp as mcpmod

    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.ASGITransport(app=app)
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(load_matrix(MATRIX))
    finally:
        mcpmod.httpx.AsyncClient = orig


@pytest.fixture
def result(demo_app):
    return _run(demo_app)


def test_the_demo_finds_what_the_readme_says_it_finds(result):
    """The published headline numbers, exactly.

    Change the demo and this fails; the fix is to re-run it and update the README
    rather than to loosen the assertion.
    """
    summary = summarize(result)
    assert summary["total_tests"] == 27
    assert (summary["positive_tests"], summary["negative_tests"]) == (8, 15)
    assert summary["listing_tests"] == 4
    assert (summary["vulnerabilities"], summary["vulnerability_defects"]) == (16, 7)
    assert summary["by_class"] == {
        "BOLA": 4,
        "privilege-escalation": 5,
        "session-hijack": 3,
        "tool-enumeration": 4,
    }


def test_both_protocol_probes_report_against_the_demo(result):
    """The reason the demo server has a session store and an authenticated listing.

    A demo that only showed the per-operation probes would leave the two
    transport-level ones undemonstrated, and they are the part of the tool that
    has no equivalent in an HTTP API scanner.
    """
    by_class = Counter(f.vuln_class for f in result.findings)
    assert by_class[VulnClass.SESSION_HIJACK] > 0
    assert by_class[VulnClass.TOOL_ENUMERATION] > 0


def test_the_session_finding_names_the_identity_whose_session_was_ridden(result):
    """One finding per credentialed subject; the anonymous subject has no session."""
    sessions = [f for f in result.findings if f.vuln_class == VulnClass.SESSION_HIJACK]
    assert sorted(f.subject for f in sessions) == ["alice", "bob", "root"]
    for finding in sessions:
        assert finding.severity == "high"
        # Step 2 must carry the session and nothing else, or it proves nothing.
        step_two = finding.curl.split("# 2.")[1]
        assert "Authorization" not in step_two
        assert "$OVERSTEP_SESSION" in step_two


def test_only_the_admin_tools_are_reported_as_over_advertised(result):
    """The users see the admin half of the catalogue; the admin sees nothing wrong.

    `read_document` is listed to alice and bob too, but they are allowed to invoke
    it — an owner-scoped grant is still permission — so it is not disclosure.
    """
    leaked = {
        (f.subject, f.test_id.rsplit("::", 1)[1])
        for f in result.findings
        if f.vuln_class == VulnClass.TOOL_ENUMERATION
    }
    assert leaked == {
        ("alice", "list_all_users"), ("alice", "reset_tenant"),
        ("bob", "list_all_users"), ("bob", "reset_tenant"),
    }


def test_the_anonymous_caller_is_shown_nothing_to_enumerate(result):
    """Listing needs a credential, so the anonymous probe has nothing to report.

    It still runs — an enumeration probe that cannot list is not a finding of
    over-restriction — and that distinction is what this pins.
    """
    enumerate_cases = [c for c in result.cases if c.variant == Variant.ENUMERATE]
    assert sorted(c.subject for c in enumerate_cases) == ["alice", "anon", "bob", "root"]
    assert not [
        f for f in result.findings
        if f.vuln_class == VulnClass.TOOL_ENUMERATION and f.subject == "anon"
    ]


def test_the_demo_run_is_conclusive(result):
    """Positive controls still pass, so the findings are worth reading.

    Requiring a credential to list is the kind of change that can break every
    authenticated call at once; if it had, the run would report inconclusive
    instead of clean and this is what would say so.
    """
    assert not result.health.inconclusive, result.health.reasons
    assert result.health.positive_allowed == result.health.positive_tests == 8


def test_the_enumeration_probes_are_not_counted_as_positive_controls(result):
    """Fail-open guard: four allow-expected probes that prove no credential works.

    If these were counted, a run whose credentials had all expired could still
    report enough passing controls to look healthy.
    """
    allow_expected = [c for c in result.cases if c.expected == Effect.ALLOW]
    assert len(allow_expected) == 12
    assert sum(1 for c in allow_expected if c.is_positive_control) == 8
