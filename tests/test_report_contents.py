"""A report says which run it describes and everything that run tested.

Two things were missing from `findings.json` and `report.html`. Neither said
what had been tested, when, by which version or from which matrix - so a report
passed along in a ticket could not be told from another. And both listed only
what went wrong, so "was this endpoint tested as this subject, and did it pass"
could be answered from `junit.xml` alone.
"""
import json
import re

import pytest

from overstep.models import Effect, Observation
from overstep.pipeline import run_pipeline, write_reports
from overstep.report.base import case_rows, defects, run_info
from overstep.waivers import Waiver

SECRET = "tok-should-never-appear"


def _leaky(base_url, subjects, cases, **kwargs):
    """get_user answers everyone; admin_list is enforced; anon's probe never lands."""
    observations = []
    for c in cases:
        if c.subject == "anon" and c.resource == "admin_list":
            observations.append(Observation(test_id=c.id, status=0, effect=Effect.DENY,
                                            error="connection reset"))
            continue
        allowed = c.resource == "get_user" or c.expected == Effect.ALLOW
        observations.append(Observation(
            test_id=c.id, status=200 if allowed else 403,
            effect=Effect.ALLOW if allowed else Effect.DENY,
            headers={"set-cookie": SECRET}, body_snippet=f"body {SECRET}",
        ))
    return observations


@pytest.fixture
def result(matrix):
    for subject in matrix.subjects:
        if subject.token:
            subject.token = f"{SECRET}-{subject.name}"
    outcome = run_pipeline(matrix, executor=_leaky)
    outcome.source = "matrices/shop.yaml"
    return outcome


@pytest.fixture
def documents(result, tmp_path):
    write_reports(result, str(tmp_path))
    return {
        "json": json.loads((tmp_path / "findings.json").read_text(encoding="utf-8")),
        "html": (tmp_path / "report.html").read_text(encoding="utf-8"),
    }


# --- which run this is ---------------------------------------------------------


def test_the_run_block_names_target_time_version_and_matrix(documents):
    from overstep import __version__

    run = documents["json"]["run"]

    assert run["targets"] == ["http://testserver"]
    assert run["matrix"] == "matrices/shop.yaml"
    assert run["overstep_version"] == __version__
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", run["started_at"])
    assert isinstance(run["duration_s"], float) and run["duration_s"] >= 0
    assert run["read_only"] is False and run["partial"] is False


def test_the_html_header_carries_the_same_facts(documents, result):
    page = documents["html"]

    for fact in ("http://testserver", "matrices/shop.yaml", result.started_at, "full run"):
        assert fact in page


def test_a_read_only_partial_run_says_both_in_the_header(matrix, tmp_path):
    outcome = run_pipeline(matrix, executor=_leaky, read_only=True,
                           only_resources=["get_user"])
    write_reports(outcome, str(tmp_path))
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    run = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))["run"]

    assert "read-only" in page
    assert "partial — only resources get_user" in page
    assert "full run" not in page
    assert run["read_only"] is True and run["partial"] is True
    assert run["selection"] == {"resources": ["get_user"]}


def test_an_mcp_target_is_named_by_url_and_a_stdio_one_by_its_program_only():
    from overstep.matrix import Matrix

    matrix = Matrix(
        modules={"mcp": {"servers": [
            {"name": "docs", "url": "http://mcp.test/mcp"},
            {"name": "local", "command": ["python", "server.py", "--api-key", SECRET]},
        ]}},
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "token": "a"}],
        resources=[
            {"name": "a", "call": {"server": "docs", "tool": "list_docs"}},
            {"name": "b", "call": {"server": "local", "tool": "list_docs"}},
        ],
        policy={"a": {"allow": [{"role": "user"}]}, "b": {"allow": [{"role": "user"}]}},
    )
    outcome = run_pipeline(matrix, executor=lambda b, s, cases, **kw: [
        Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases
    ])
    targets = run_info(outcome)["targets"]

    assert "http://mcp.test/mcp" in targets
    assert "stdio: python" in targets
    assert SECRET not in json.dumps(targets)


# --- everything that was tested ---------------------------------------------------


def test_every_planned_case_is_listed_once_in_plan_order(documents, result):
    listed = [row["test_id"] for row in documents["json"]["cases"]]

    assert listed == [c.id for c in result.cases]


def test_each_case_is_judged(documents):
    by_id = {row["test_id"]: row for row in documents["json"]["cases"]}
    outcomes = {row["outcome"] for row in by_id.values()}

    assert by_id["get_user::alice::self"]["outcome"] == "passed"
    assert by_id["get_user::alice::other"]["outcome"] == "finding"
    assert by_id["admin_list::anon::na"]["outcome"] == "undelivered"
    assert outcomes == {"passed", "finding", "undelivered"}
    passed = by_id["get_user::alice::self"]
    assert (passed["expected"], passed["observed"], passed["status"]) == ("allow", "allow", 200)
    assert (passed["method"], passed["path"]) == ("GET", "/users/u1")


def test_the_finding_rows_agree_with_the_findings(documents):
    marked = {r["test_id"] for r in documents["json"]["cases"] if r["outcome"] == "finding"}

    assert marked == {f["test_id"] for f in documents["json"]["findings"]}


def test_a_waived_and_a_skipped_case_are_told_apart_from_a_passed_one(matrix):
    outcome = run_pipeline(
        matrix,
        executor=lambda b, s, cases, **kw: [
            Observation(test_id=c.id, status=0, effect=Effect.DENY, skipped=True)
            if c.resource == "admin_list" else o
            for c, o in zip(cases, _leaky(b, s, cases))
        ],
        waivers=[Waiver(id="get_user::alice::other", reason="accepted")],
    )
    by_id = {row["test_id"]: row for row in case_rows(outcome)}

    assert by_id["get_user::alice::other"]["outcome"] == "waived"
    assert by_id["admin_list::root::na"]["outcome"] == "skipped"
    assert by_id["admin_list::root::na"]["observed"] is None
    assert by_id["admin_list::root::na"]["status"] is None


def test_the_case_list_carries_no_credential_header_or_body(documents):
    """Passed cases are most of the list; none of them needs the response to be shown."""
    listed = json.dumps(documents["json"]["cases"])

    assert SECRET not in listed
    assert set(documents["json"]["cases"][0]) == {
        "test_id", "resource", "subject", "role", "method", "path", "variant",
        "victim", "expected", "observed", "status", "outcome", "latency_ms",
    }


def test_the_html_lists_every_case_collapsed(documents, result):
    page = documents["html"]

    assert f"<summary>All cases ({len(result.cases)})</summary>" in page
    assert "<details class='all'>" in page and "<details class='all' open" not in page
    section = page.split("<details class='all'>")[1]
    assert section.count("<tr data-resource=") == len(result.cases)
    assert ">passed</span>" in section and ">finding</span>" in section


def test_a_clean_run_still_lists_what_it_tested(matrix, tmp_path):
    outcome = run_pipeline(matrix, executor=lambda b, s, cases, **kw: [
        Observation(test_id=c.id, status=200 if c.expected == Effect.ALLOW else 403,
                    effect=c.expected) for c in cases
    ])
    write_reports(outcome, str(tmp_path))
    page = (tmp_path / "report.html").read_text(encoding="utf-8")

    assert "No findings" in page
    assert f"All cases ({len(outcome.cases)})" in page


# --- the defects table ------------------------------------------------------------


def test_a_defect_is_located_by_its_path_template(result, documents):
    rollup = defects(result.findings, result.cases)
    bola = next(d for d in rollup if d["resource"] == "get_user")

    assert bola["path"] == "/users/{id}"
    assert "<code>GET /users/{id}</code>" in documents["html"]
    assert all("path" in d for d in documents["json"]["defects"])


def test_without_cases_a_defect_falls_back_to_the_path_it_was_seen_on(result):
    bola = next(d for d in defects(result.findings) if d["resource"] == "get_user")

    assert bola["path"].startswith("/users/u")


# --- filtering --------------------------------------------------------------------


def test_the_page_offers_filters_for_what_is_actually_in_it(documents, result):
    page = documents["html"]

    for key in ("class", "resource", "subject"):
        assert f'<select data-filter="{key}">' in page
    for name in {c.resource for c in result.cases} | {c.subject for c in result.cases}:
        assert f'<option value="{name}">' in page
    assert "<script>" in page


def test_rows_carry_the_attributes_the_filters_read(documents):
    page = documents["html"]

    assert 'data-class="BOLA" data-resource="get_user" data-subject="alice"' in page
    # A defect seen by several subjects matches any of them.
    assert re.search(r'data-resource="get_user" data-subject="[a-z]+\|[a-z|]+"', page)


def test_the_page_loads_nothing_from_anywhere(documents):
    page = documents["html"]

    assert "src=" not in page and "href=" not in page and "@import" not in page


def test_a_name_from_the_matrix_cannot_break_out_of_an_attribute(matrix, tmp_path):
    hostile = '"><script>alert(1)</script>'
    matrix.subjects[0].name = hostile
    outcome = run_pipeline(matrix, executor=_leaky)
    write_reports(outcome, str(tmp_path))
    page = (tmp_path / "report.html").read_text(encoding="utf-8")

    assert hostile not in page
    assert "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script>") == 1


# --- a cross-method probe is a case of its own -----------------------------------


def test_a_failed_cross_method_probe_does_not_mark_the_request_it_came_from(matrix):
    """`probe_methods` cases end in `::<METHOD>`, like a derived finding's id.

    Only the PUT gets through here. The GET it was derived from was refused,
    as the matrix expects, and has to stay `passed`.
    """
    matrix.resources[0].probe_methods = ["PUT"]

    def only_put_leaks(base_url, subjects, cases, **kwargs):
        return [
            Observation(test_id=c.id, status=200, effect=Effect.ALLOW)
            if c.method == "PUT" or c.expected == Effect.ALLOW
            else Observation(test_id=c.id, status=403, effect=Effect.DENY)
            for c in cases
        ]

    outcome = run_pipeline(matrix, executor=only_put_leaks)
    by_id = {row["test_id"]: row for row in case_rows(outcome)}

    assert "get_user::alice::other::PUT" in by_id, "the control: the probe is a planned case"
    assert by_id["get_user::alice::other::PUT"]["outcome"] == "finding"
    assert by_id["get_user::alice::other"]["outcome"] == "passed"
    assert {r["test_id"] for r in by_id.values() if r["outcome"] == "finding"} == {
        f.test_id for f in outcome.findings
    }


def test_a_waived_cross_method_probe_does_not_waive_its_parent(matrix):
    matrix.resources[0].probe_methods = ["PUT"]

    def everything_leaks(base_url, subjects, cases, **kwargs):
        return [Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases]

    outcome = run_pipeline(
        matrix, executor=everything_leaks,
        waivers=[Waiver(id="get_user::alice::other::PUT", reason="accepted")],
    )
    by_id = {row["test_id"]: row for row in case_rows(outcome)}

    assert by_id["get_user::alice::other::PUT"]["outcome"] == "waived"
    assert by_id["get_user::alice::other"]["outcome"] == "finding"


def test_a_derived_finding_still_reaches_its_parent_case():
    """The other direction: an id that is not a case is resolved to the one it grew from."""
    from overstep.models import Finding, RunResult, Variant, VulnClass
    from overstep.planner import plan
    from overstep.matrix import Matrix

    m = Matrix(
        modules={"mcp": {"servers": [{"name": "docs", "url": "http://mcp.test/mcp"}]}},
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "token": "a"}],
        resources=[{"name": "list_docs", "call": {"server": "docs", "tool": "list_docs"}}],
        policy={"list_docs": {"allow": [{"role": "user"}]}},
    )
    cases = plan(m)
    parent = cases[0]
    obs = Observation(test_id=parent.id, status=200, effect=Effect.ALLOW)
    derived = Finding(
        test_id=f"{parent.id}::reset_tenant", vuln_class=VulnClass.TOOL_ENUMERATION,
        severity="medium", resource=parent.resource, subject=parent.subject, role=parent.role,
        method=parent.method, path=parent.path, expected=Effect.ALLOW, observed=Effect.ALLOW,
        status=200, variant=Variant.ENUMERATE, detail="d", evidence=obs,
    )
    result = RunResult(base_url="", cases=cases, observations=[obs] * 1, findings=[derived])
    by_id = {row["test_id"]: row for row in case_rows(result)}

    assert by_id[parent.id]["outcome"] == "finding"
