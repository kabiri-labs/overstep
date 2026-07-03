"""HTML report — a self-contained page for humans."""
from __future__ import annotations

import html
import os
from typing import List

from overstep.models import Finding, TestCase
from overstep.report import summarize

_SEVERITY_COLOR = {"high": "#d64545", "medium": "#d98a29", "low": "#3a7bd5"}

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
"""


def _card(number, label) -> str:
    return f'<div class="card"><div class="n">{number}</div><div class="l">{html.escape(label)}</div></div>'


def _row(f: Finding) -> str:
    color = _SEVERITY_COLOR.get(f.severity, "#888")
    ev = f.evidence
    return (
        "<tr>"
        f'<td><span class="badge" style="background:{color}">{html.escape(f.vuln_class.value)}</span>'
        f'<div class="sev" style="color:{color}">{html.escape(f.severity)}</div></td>'
        f"<td><code>{html.escape(f.method)} {html.escape(f.path)}</code><br>"
        f"<small>{html.escape(f.subject)} · {html.escape(f.role)} · {html.escape(f.variant.value)}</small></td>"
        f"<td>expected <b>{html.escape(f.expected.value)}</b><br>observed <b>{html.escape(f.observed.value)}</b> ({f.status})</td>"
        f"<td>{html.escape(f.detail)}"
        "<details><summary>evidence</summary>"
        f"<pre>{html.escape(ev.body_snippet[:1200])}</pre></details></td>"
        "</tr>"
    )


def write(cases: List[TestCase], findings: List[Finding], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    s = summarize(cases, findings)

    cards = "".join(
        [
            _card(s["total_tests"], "tests run"),
            _card(s["positive_tests"], "positive"),
            _card(s["negative_tests"], "negative"),
            _card(s["vulnerabilities"], "vulnerabilities"),
            _card(s["findings"], "total findings"),
        ]
    )

    if findings:
        body = (
            "<table><thead><tr><th>Class</th><th>Endpoint / subject</th>"
            "<th>Decision</th><th>Detail</th></tr></thead><tbody>"
            + "".join(_row(f) for f in findings)
            + "</tbody></table>"
        )
    else:
        body = '<p class="empty">No findings — the API matched the authorization matrix. ✅</p>'

    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>overstep report</title>"
        f"<style>{_STYLE}</style></head><body>"
        "<h1>overstep</h1>"
        "<p class='sub'>Matrix-driven authorization test report</p>"
        f"<div class='cards'>{cards}</div>"
        f"{body}"
        "</body></html>"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
