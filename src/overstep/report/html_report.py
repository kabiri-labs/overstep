"""HTML report — a self-contained page for humans.

One file, no network: the styles and the few lines of script that drive the
filters are inline, so the page reads the same from a CI artifact, an email
attachment or a ticket. Every value that came from the matrix or the target is
escaped on its way in, attributes included.
"""
from __future__ import annotations

import html
import os
from typing import Dict, Iterable, List

from overstep.models import Finding, RunResult
from overstep.report.base import case_rows, defects, register, run_info, summarize

_SEVERITY_COLOR = {"high": "#d64545", "medium": "#d98a29", "low": "#3a7bd5"}
_OUTCOME_COLOR = {
    "passed": "#2a8a4a",
    "finding": "#d64545",
    "waived": "#888",
    "skipped": "#d98a29",
    "undelivered": "#d98a29",
}

_STYLE = """
body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #1c1c1c; }
h1 { margin-bottom: 0.2rem; }
.sub { color: #666; margin-top: 0; }
.cards { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1.5rem 0; }
.card { border: 1px solid #e2e2e2; border-radius: 8px; padding: 0.75rem 1rem; min-width: 120px; }
.card .n { font-size: 1.6rem; font-weight: 700; }
.card .l { color: #666; font-size: 0.85rem; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { border-bottom: 1px solid #eee; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #fafafa; }
code { background: #f2f2f2; padding: 0.1rem 0.3rem; border-radius: 4px; }
.badge { color: #fff; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; white-space: nowrap; }
.sev { font-weight: 700; text-transform: uppercase; font-size: 0.7rem; }
details > summary { cursor: pointer; color: #3a7bd5; }
pre { background: #f7f7f7; padding: 0.5rem; overflow-x: auto; border-radius: 4px; }
.empty { color: #2a8a4a; font-weight: 600; }
.conf { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.03em; color: #555; border: 1px solid #ddd; border-radius: 6px; padding: 0.05rem 0.35rem; }
.rlabel { margin: 0.5rem 0 0.15rem; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: #888; }
.run { display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem; margin: 1rem 0; font-size: 0.9rem; }
.run dt { color: #666; }
.run dd { margin: 0; }
.scope { color: #b5651d; font-weight: 600; }
.filters { margin: 1.5rem 0 0; display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.85rem; color: #666; }
.filters select { margin-left: 0.3rem; }
.all > summary { font-size: 1.2rem; font-weight: 700; color: #1c1c1c; margin-top: 2rem; }
"""

# Hides every row that carries a filtered attribute with a different value. A
# row without the attribute is left alone, so a class filter narrows the
# findings without emptying the case list, which has no class to match.
_SCRIPT = """
(function () {
  var selects = document.querySelectorAll('select[data-filter]');
  function apply() {
    var wanted = {};
    selects.forEach(function (s) { if (s.value) wanted[s.dataset.filter] = s.value; });
    document.querySelectorAll('tr[data-resource]').forEach(function (row) {
      var hide = false;
      for (var key in wanted) {
        var have = row.getAttribute('data-' + key);
        if (have !== null && have.split('|').indexOf(wanted[key]) < 0) hide = true;
      }
      row.hidden = hide;
    });
  }
  selects.forEach(function (s) { s.addEventListener('change', apply); });
})();
"""


def _attr(value: object) -> str:
    return html.escape(str(value), quote=True)


def _card(number, label) -> str:
    return f'<div class="card"><div class="n">{number}</div><div class="l">{html.escape(label)}</div></div>'


def _row(f: Finding) -> str:
    color = _SEVERITY_COLOR.get(f.severity, "#888")
    ev = f.evidence
    return (
        f'<tr data-class="{_attr(f.vuln_class.value)}" data-resource="{_attr(f.resource)}" '
        f'data-subject="{_attr(f.subject)}">'
        f'<td><span class="badge" style="background:{color}">{html.escape(f.vuln_class.value)}</span>'
        f'<div class="sev" style="color:{color}">{html.escape(f.severity)}</div></td>'
        f"<td><code>{html.escape(f.method)} {html.escape(f.path)}</code><br>"
        f"<small>{html.escape(f.subject)} · {html.escape(f.role)} · {html.escape(f.variant.value)}</small></td>"
        f"<td>expected <b>{html.escape(f.expected.value)}</b><br>observed <b>{html.escape(f.observed.value)}</b> ({f.status})"
        f'<br><span class="conf">{html.escape(f.confidence)}</span></td>'
        f"<td>{html.escape(f.detail)}"
        "<details><summary>evidence &amp; repro</summary>"
        + (f"<p class='rlabel'>reproduce</p><pre>{html.escape(f.curl)}</pre>" if f.curl else "")
        + f"<p class='rlabel'>response</p><pre>{html.escape(ev.body_snippet[:1200])}</pre>"
        # A property-level finding is the one case where the head of the body is
        # not the proof: the key that leaked can sit anywhere in it. Show the
        # retained body underneath, so the claim in `detail` is checkable without
        # re-running the probe.
        + (
            f"<p class='rlabel'>full response ({len(ev.full_body)} bytes)</p>"
            f"<pre>{html.escape(ev.full_body)}</pre>"
            if ev.full_body and ev.full_body != ev.body_snippet
            else ""
        )
        + "</details></td>"
        "</tr>"
    )


def _defect_row(defect: dict) -> str:
    color = _SEVERITY_COLOR.get(defect["severity"], "#888")
    subjects = ", ".join(defect["subjects"])
    return (
        f'<tr data-class="{_attr(defect["vuln_class"])}" data-resource="{_attr(defect["resource"])}" '
        f'data-subject="{_attr("|".join(defect["subjects"]))}">'
        f"<td><span class='badge' style='background:{color}'>"
        f"{html.escape(defect['vuln_class'])}</span></td>"
        # The path, not the resource's name in the matrix: the name is the
        # author's label, and the person fixing this knows the route.
        f"<td><code>{html.escape(defect['method'])} "
        f"{html.escape(str(defect['path']))}</code><br>"
        f"<small>{html.escape(defect['resource'])}</small></td>"
        f"<td>{html.escape(subjects)}</td>"
        f"<td>{defect['findings']}</td>"
        "</tr>"
    )


def _case_row(row: Dict[str, object]) -> str:
    color = _OUTCOME_COLOR.get(str(row["outcome"]), "#888")
    observed = row["observed"] or "—"
    status = f" ({row['status']})" if row["status"] is not None else ""
    return (
        f'<tr data-resource="{_attr(row["resource"])}" data-subject="{_attr(row["subject"])}">'
        f'<td><span class="badge" style="background:{color}">{html.escape(str(row["outcome"]))}</span></td>'
        f"<td><code>{html.escape(str(row['method']))} {html.escape(str(row['path']))}</code><br>"
        f"<small>{html.escape(str(row['resource']))}</small></td>"
        f"<td>{html.escape(str(row['subject']))} · {html.escape(str(row['role']))}</td>"
        f"<td>{html.escape(str(row['variant']))}</td>"
        f"<td>{html.escape(str(row['expected']))}</td>"
        f"<td>{html.escape(str(observed))}{status}</td>"
        "</tr>"
    )


def _header(info: Dict[str, object]) -> str:
    """Which run this page describes, in the order a reader asks."""
    def entry(label: str, value: str) -> str:
        return f"<dt>{html.escape(label)}</dt><dd>{value}</dd>"

    targets = info["targets"] or ["—"]
    scope: List[str] = []
    if info["read_only"]:
        scope.append("read-only — mutating operations were not sent")
    if info["partial"]:
        selection = info["selection"]
        named = "; ".join(f"{kind} {', '.join(names)}" for kind, names in sorted(selection.items()))
        scope.append(f"partial — only {named}; this page says nothing about the rest")
    duration = f"{info['duration_s']:g} s" if info["duration_s"] is not None else "—"
    return (
        "<dl class='run'>"
        + entry("Target", "<br>".join(f"<code>{html.escape(str(t))}</code>" for t in targets))
        + entry("Started", html.escape(str(info["started_at"] or "—")))
        + entry("Duration", html.escape(duration))
        + entry("Matrix", f"<code>{html.escape(str(info['matrix']))}</code>" if info["matrix"] else "—")
        + entry("overstep", html.escape(str(info["overstep_version"])))
        + entry(
            "Scope",
            "<br>".join(f"<span class='scope'>{html.escape(s)}</span>" for s in scope)
            if scope
            else "full run",
        )
        + "</dl>"
    )


def _select(key: str, label: str, values: Iterable[str]) -> str:
    options = "".join(
        f'<option value="{_attr(v)}">{html.escape(v)}</option>' for v in sorted(set(values))
    )
    return (
        f"<label>{html.escape(label)}"
        f'<select data-filter="{_attr(key)}"><option value="">all</option>{options}</select></label>'
    )


@register("html", "report.html")
def write(result: RunResult, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    s = summarize(result)
    findings = result.findings
    cases = case_rows(result)

    cards = "".join(
        [
            _card(s["total_tests"], "tests run"),
            _card(s["positive_tests"], "positive"),
            _card(s["negative_tests"], "negative"),
            *([_card(s["listing_tests"], "listing")] if s["listing_tests"] else []),
            _card(s["vulnerabilities"], "vulnerabilities"),
            _card(s["defects"], "distinct defects"),
            _card(s["findings"], "total findings"),
        ]
    )

    if findings:
        # The defect table is the work list; the findings table below is the
        # evidence. Reading them the other way round makes one missing check
        # look like a dozen separate problems.
        body = (
            "<h2>Defects</h2>"
            "<p class='sub'>One row per thing to fix. A defect surfaces once per "
            "identity that reaches it — those findings are listed below.</p>"
            "<table><thead><tr><th>Class</th><th>Endpoint</th><th>Seen by</th>"
            "<th>Findings</th></tr></thead><tbody>"
            + "".join(_defect_row(d) for d in defects(findings, result.cases))
            + "</tbody></table>"
            "<h2>Findings</h2>"
            "<table><thead><tr><th>Class</th><th>Endpoint / subject</th>"
            "<th>Decision</th><th>Detail</th></tr></thead><tbody>"
            + "".join(_row(f) for f in findings)
            + "</tbody></table>"
        )
    else:
        body = '<p class="empty">No findings — the API matched the authorization matrix. ✅</p>'

    filters = ""
    if findings or cases:
        filters = (
            "<div class='filters'>"
            + (_select("class", "Class", (f.vuln_class.value for f in findings)) if findings else "")
            + _select("resource", "Resource", [str(c["resource"]) for c in cases] + [f.resource for f in findings])
            + _select("subject", "Subject", [str(c["subject"]) for c in cases] + [f.subject for f in findings])
            + "</div>"
        )

    # Collapsed: the findings are what the page is opened for, and this is the
    # answer to the question that comes after them — what else was tested.
    everything = ""
    if cases:
        everything = (
            f"<details class='all'><summary>All cases ({len(cases)})</summary>"
            "<p class='sub'>Every request the run planned, passed ones included.</p>"
            "<table><thead><tr><th>Outcome</th><th>Request</th><th>Subject</th>"
            "<th>Variant</th><th>Expected</th><th>Observed</th></tr></thead><tbody>"
            + "".join(_case_row(c) for c in cases)
            + "</tbody></table></details>"
        )

    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>overstep report</title>"
        f"<style>{_STYLE}</style></head><body>"
        "<h1>overstep</h1>"
        "<p class='sub'>Matrix-driven authorization test report</p>"
        f"{_header(run_info(result))}"
        f"<div class='cards'>{cards}</div>"
        f"{filters}"
        f"{body}"
        f"{everything}"
        + (f"<script>{_SCRIPT}</script>" if filters else "")
        + "</body></html>"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
