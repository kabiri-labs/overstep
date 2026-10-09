"""The bundled secure MCP demo, run end to end against its own server.

``tests/test_examples_demo.py`` pins the vulnerable MCP demo: a server with holes
is reported as having them. This pins the other direction on the same surface,
which is the claim a gate rests on and the harder one to make honestly.

"Zero vulnerabilities" over MCP is also what an unreachable server, a rejected
credential and an all-skipped suite produce — and, since this release, what a
session probe that could not answer its question produces. So every assertion
below is about the run having been in a position to see a finding: the requests
arrived, the credentials were accepted, the cross-owner probes were generated on
**both** doors, and the two protocol probes actually ran rather than being
skipped.

The last one is also the regression test for the session-binding control. A
well-behaved stateful server must still have its probe *exercised and passed*;
if the new control were too eager it would skip here, and a skipped probe over a
sound server is a question nobody asked.

The server is driven in-process over ASGI, so the test needs no port and no
subprocess.
"""
import importlib.util
import os

import httpx
import pytest

from overstep.matrix import load_matrix
from overstep.models import Effect, Variant
from overstep.pipeline import run_pipeline
from overstep.report.base import summarize

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATRIX = os.path.join(_ROOT, "examples", "secure_mcp", "matrix.yaml")
_SERVER = os.path.join(_ROOT, "examples", "secure_mcp", "server.py")


@pytest.fixture
def demo_app():
    """A fresh server module per test — it keeps a session table."""
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location("overstep_demo_secure_mcp", _SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


@pytest.fixture
def result(demo_app):
    import overstep.modules.mcp.transport as mcpmod

    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.ASGITransport(app=demo_app)
        return orig(*a, **kw)

    mcpmod.httpx.AsyncClient = factory
    try:
        return run_pipeline(load_matrix(MATRIX))
    finally:
        mcpmod.httpx.AsyncClient = orig


def _observations(result, variant):
    wanted = {c.id: c for c in result.cases if c.variant == variant}
    return [(wanted[o.test_id], o) for o in result.observations if o.test_id in wanted]


def test_a_server_that_enforces_its_policy_is_reported_clean(result):
    summary = summarize(result)

    assert summary["vulnerabilities"] == 0
    assert summary["findings"] == 0, [(f.test_id, f.vuln_class.value) for f in result.findings]


def test_the_clean_result_is_conclusive(result):
    """The half that makes the zero mean something."""
    assert not result.health.inconclusive, result.health.reasons
    assert result.health.transport_errors == 0
    assert result.health.positive_tests > 0
    assert result.health.positive_allowed == result.health.positive_tests


def test_the_demo_covers_the_same_surface_as_the_broken_one(result):
    """Same shape, so the two demos differ only in the target's enforcement.

    If this drifts, the secure demo has stopped being the comparison it exists
    to be, and a reader could take its clean result for a narrower suite.
    """
    summary = summarize(result)
    assert summary["total_tests"] == 27
    assert (summary["positive_tests"], summary["negative_tests"]) == (8, 15)
    assert summary["listing_tests"] == 4


def test_both_object_doors_were_probed_across_owners(result):
    """A tool and a resource URI onto the same documents, which is the point.

    The vulnerable demo has the same missing check on both; a matrix that
    declared only the tool would report the resource half clean. A secure demo
    has to prove both were asked.
    """
    assert result.coverage.object_resources == 2
    assert result.coverage.complete, result.coverage.unprobed

    refused = {
        case.resource
        for case, obs in _observations(result, Variant.OTHER)
        if case.expected == Effect.DENY and obs.effect == Effect.DENY and not obs.skipped
    }
    assert refused == {"read_document", "read_doc_resource"}


def test_every_cross_owner_probe_reached_the_server(result):
    """The findings are zero because the server said no, not because nothing was asked."""
    probes = _observations(result, Variant.OTHER)
    assert probes

    for case, obs in probes:
        assert not obs.skipped, f"{case.id} was never sent"
        assert obs.status != 0, f"{case.id} never reached the server"
        assert obs.effect == case.expected, f"{case.id}: expected {case.expected}, got {obs.effect}"


def test_the_session_probe_ran_and_was_refused(result):
    """Exercised and passed, not skipped — the distinction this release added.

    The server issues an ``Mcp-Session-Id`` and then refuses to let it stand in
    for a credential, which is what the MCP spec requires. A probe recorded as
    skipped here would mean overstep could not tell, and a sound server would be
    getting credit for a control nobody checked.
    """
    probes = _observations(result, Variant.SESSION)
    assert probes, "no session probe was planned for a stateful server"

    for case, obs in probes:
        assert not obs.skipped, f"{case.id} was skipped: {obs.error}"
        assert obs.effect == Effect.DENY, "a session id was accepted in place of a credential"
        assert case.expected == Effect.DENY


def test_the_enumeration_probe_ran_and_found_nothing(result):
    """A filtered catalogue and an unfiltered one are indistinguishable without this."""
    probes = _observations(result, Variant.ENUMERATE)
    assert probes, "the matrix asks for tool_enumeration but no probe was planned"

    # A credentialed caller is shown a listing; what it contains is the question.
    listed = [obs for _case, obs in probes if obs.listed_tools]
    assert listed, "no listing came back, so nothing was compared against the policy"
    for obs in listed:
        assert not obs.skipped

    assert not [f for f in result.findings if f.vuln_class.value == "tool-enumeration"]


def test_a_plain_user_is_not_shown_the_admin_tools(result):
    """The behaviour behind the quiet enumeration probe, asserted directly.

    Without this, the probe passing could also mean the listing was empty, or
    that the comparison never happened.
    """
    by_subject = {
        case.subject: obs.listed_tools
        for case, obs in _observations(result, Variant.ENUMERATE)
    }

    assert by_subject["alice"] == ["read_document"]
    assert set(by_subject["root"]) == {"read_document", "list_all_users", "reset_tenant"}
