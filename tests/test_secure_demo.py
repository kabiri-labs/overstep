"""The bundled secure demo, run end to end against its own server.

``tests/test_examples_demo.py`` pins the broken demo: a target with holes is
reported as having them. This pins the other direction, which is the claim a
gate actually rests on — a target that enforces its policy is reported clean,
**and the run can prove it looked**.

Those are two different assertions and only the second is hard. "Zero
vulnerabilities" is also what an unreachable target, a rejected credential and
an all-skipped suite produce, so a test that checked the finding count alone
would pass just as happily against a demo server that never started. Every
assertion below is about the run having been in a position to see a finding:
the requests arrived, the credentials were accepted, and the cross-owner probes
were generated.

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
MATRIX = os.path.join(_ROOT, "examples", "secure_api", "matrix.yaml")
_SERVER = os.path.join(_ROOT, "examples", "secure_api", "server.py")


@pytest.fixture
def demo_app():
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location("overstep_demo_secure_server", _SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


@pytest.fixture
def result(demo_app):
    import overstep.modules.rest.executor as rest

    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.ASGITransport(app=demo_app)
        return orig(*a, **kw)

    rest.httpx.AsyncClient = factory
    try:
        return run_pipeline(load_matrix(MATRIX))
    finally:
        rest.httpx.AsyncClient = orig


def test_a_target_that_enforces_its_policy_is_reported_clean(result):
    summary = summarize(result)

    assert summary["vulnerabilities"] == 0
    assert summary["findings"] == 0, [f.test_id for f in result.findings]


def test_the_clean_result_is_conclusive(result):
    """The half that makes the zero mean something.

    An unreachable target reports zero vulnerabilities too. This asserts the
    run was not that: the requests arrived, and the credentials were accepted.
    """
    assert not result.health.inconclusive, result.health.reasons
    assert result.health.transport_errors == 0
    assert result.health.positive_tests > 0
    assert result.health.positive_allowed == result.health.positive_tests


def test_nothing_was_skipped(result):
    """A full run sends every planned case; the clean result covers all of them."""
    assert result.health.skipped == 0
    assert result.health.skipped_surfaces == []
    assert result.read_only is False


def test_the_cross_owner_probes_were_actually_generated(result):
    """Without these, "no BOLA findings" is the absence of a question, not an answer."""
    assert result.coverage.object_resources > 0
    assert result.coverage.complete, result.coverage.unprobed

    probes = [c for c in result.cases if c.variant == Variant.OTHER and c.expected == Effect.DENY]
    assert probes, "no cross-owner probe was planned, so nothing tested object-level access"


def test_every_negative_probe_was_refused_by_the_target(result):
    """The findings are zero because the target said no, not because nothing was asked."""
    observed = {o.test_id: o for o in result.observations}
    negatives = [c for c in result.cases if c.expected == Effect.DENY]

    assert negatives
    for case in negatives:
        obs = observed[case.id]
        assert not obs.skipped, f"{case.id} was never sent"
        assert obs.status != 0, f"{case.id} never reached the target"
        assert obs.effect == Effect.DENY, f"{case.id} got through with {obs.status}"
