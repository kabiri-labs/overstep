"""A run narrowed to named resources or subjects says so, everywhere it reports.

``--resource`` and ``--subject`` exist to iterate on one endpoint without
sending the whole matrix. The danger is the obvious one: a run of one resource
finds nothing wrong with the others, and a summary that does not say they were
left out is read as a clean result for all of them.
"""
import json

import pytest

from overstep.cli import app
from overstep.models import Effect, Observation
from overstep.pipeline import PipelineError, run_pipeline
from overstep.report.base import summarize
from test_cli_surface import _Demo
from typer.testing import CliRunner


def _healthy(base_url, subjects, cases, **kwargs):
    """A target that enforces the matrix exactly."""
    return [
        Observation(test_id=c.id, status=200 if c.expected == Effect.ALLOW else 403,
                    effect=c.expected)
        for c in cases
    ]


def _recording(sent):
    def executor(base_url, subjects, cases, **kwargs):
        sent.extend(cases)
        return _healthy(base_url, subjects, cases)

    return executor


# --- what is sent ---------------------------------------------------------------


def test_only_the_named_resource_is_sent(matrix):
    sent = []
    result = run_pipeline(matrix, executor=_recording(sent), only_resources=["admin_list"])

    assert sent and {c.resource for c in sent} == {"admin_list"}
    assert [c.id for c in result.cases] == [c.id for c in sent]


def test_a_subject_narrows_by_who_sends_not_by_whose_object(matrix):
    sent = []
    run_pipeline(matrix, executor=_recording(sent), only_subjects=["alice"])

    assert {c.subject for c in sent} == {"alice"}
    # alice's probe at somebody else's object is the point of running her alone.
    assert any(c.victim and c.victim != "alice" for c in sent)


def test_the_two_filters_intersect(matrix):
    sent = []
    run_pipeline(
        matrix, executor=_recording(sent),
        only_resources=["get_user"], only_subjects=["alice", "bob"],
    )

    assert {(c.resource, c.subject) for c in sent} == {("get_user", "alice"), ("get_user", "bob")}


def test_no_filter_is_the_whole_plan_and_not_partial(matrix):
    sent = []
    result = run_pipeline(matrix, executor=_recording(sent))

    assert not result.partial
    assert result.planned_tests == len(sent)
    assert summarize(result)["partial"] is False
    assert summarize(result)["selection"] == {}


# --- what it says about itself ---------------------------------------------------


def test_a_narrowed_run_reports_itself_partial_with_both_counts(matrix):
    full = run_pipeline(matrix, executor=_healthy)
    narrowed = run_pipeline(matrix, executor=_healthy, only_resources=["admin_list"])
    summary = summarize(narrowed)

    assert narrowed.partial
    assert summary["partial"] is True
    assert summary["selection"] == {"resources": ["admin_list"]}
    assert summary["planned_tests"] == len(full.cases)
    assert summary["total_tests"] < summary["planned_tests"]


def test_a_clean_narrowed_run_is_still_not_a_clean_bill_for_the_rest(matrix):
    """The negative: nothing found, and the documents still say it is partial."""
    def leaky(base_url, subjects, cases, **kwargs):
        # Every probe at get_user gets through; admin_list is enforced.
        return [
            Observation(
                test_id=c.id, effect=Effect.ALLOW if c.resource == "get_user" else c.expected,
                status=200 if c.resource == "get_user" or c.expected == Effect.ALLOW else 403,
            )
            for c in cases
        ]

    assert run_pipeline(matrix, executor=leaky).vulnerabilities, "the control: it is broken"
    narrowed = run_pipeline(matrix, executor=leaky, only_resources=["admin_list"])

    assert narrowed.vulnerabilities == []
    assert summarize(narrowed)["partial"] is True


def test_coverage_is_measured_over_what_was_selected(matrix):
    """Left-out object resources are not reported as a gap in the matrix."""
    narrowed = run_pipeline(matrix, executor=_healthy, only_resources=["admin_list"])

    assert narrowed.coverage.unprobed == []
    assert narrowed.coverage.object_resources == 0

    selected = run_pipeline(matrix, executor=_healthy, only_resources=["get_user"])
    assert (selected.coverage.object_resources, selected.coverage.probed) == (1, 1)


# --- refusing a selection that would send less than was asked for ----------------


@pytest.mark.parametrize("kwargs,name", [
    ({"only_resources": ["get_usr"]}, "get_usr"),
    ({"only_subjects": ["alise"]}, "alise"),
    ({"only_resources": ["get_user", "nope"]}, "nope"),
])
def test_an_unknown_name_is_refused_before_anything_happens(matrix, kwargs, name):
    calls = []

    def authenticator(*args, **kw):
        calls.append("auth")

    with pytest.raises(PipelineError) as caught:
        run_pipeline(matrix, executor=_recording(calls), authenticator=authenticator, **kwargs)

    assert name in str(caught.value)
    assert calls == [], "a mistyped name must not cost a login or a request"


def test_a_selection_matching_no_case_is_refused(matrix):
    """Valid names whose intersection is empty: asked of `select` with such a plan.

    The planner gives every subject a case on every resource today, so the
    plan is narrowed by hand to one where the named pair really has none.
    """
    from overstep.pipeline import select
    from overstep.planner import plan

    without_alice = [c for c in plan(matrix) if c.subject != "alice"]
    with pytest.raises(PipelineError) as caught:
        select(matrix, without_alice, ["get_user"], ["alice"])

    assert "matches no test case" in str(caught.value)


# --- through the CLI -------------------------------------------------------------


def test_the_cli_says_partial_before_and_inside_the_summary(tmp_path):
    out = tmp_path / "out"
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(out), "--resource", "get_user")
    flat = " ".join(result.output.split())

    assert "partial run — only resources get_user" in flat
    assert "It says nothing about the rest." in flat
    assert "Partial run" in result.output
    payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["partial"] is True
    assert payload["summary"]["selection"] == {"resources": ["get_user"]}
    assert payload["summary"]["planned_tests"] == 18
    assert {f["resource"] for f in payload["findings"]} == {"get_user"}


def test_the_cli_refuses_an_unknown_resource_as_bad_input(tmp_path):
    out = tmp_path / "out"
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(out), "--resource", "get_usr")

    assert result.exit_code == 2
    assert "get_usr" in result.output
    assert not out.exists()


def test_snapshot_cannot_be_narrowed():
    """A baseline of part of the matrix reports the rest as new on the next run."""
    result = CliRunner().invoke(app, ["snapshot", "m.yaml", "--resource", "x"])

    assert result.exit_code == 2
    assert "No such option" in result.output


# --- --verbose -------------------------------------------------------------------


def test_verbose_prints_one_line_per_request_on_stderr(tmp_path):
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"), "--verbose")

    lines = [l for l in result.stderr.splitlines() if " -> " in l]
    assert len(lines) == 18
    assert any(l.startswith("GET /users/u1  as alice  -> 200 allow  (expected allow") for l in lines)
    assert any("MISMATCH" in l for l in lines), "the demo is broken; its lines say where"
    assert " -> " not in result.stdout, "stdout stays the report, for a pipe"


def test_verbose_never_prints_a_credential(tmp_path):
    with _Demo("rest") as d:
        from overstep.matrix import load_matrix

        tokens = [s.token for s in load_matrix(d.matrix).subjects if s.token]
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"), "--verbose")

    assert tokens, "the control: the demo matrix does carry tokens"
    assert not any(token in result.output for token in tokens)
    assert "Bearer" not in result.output and "Authorization" not in result.output


def test_without_the_flag_nothing_is_traced(tmp_path):
    with _Demo("rest") as d:
        result = d.invoke("run", d.matrix, "--out", str(tmp_path / "out"))

    assert " -> " not in result.output
