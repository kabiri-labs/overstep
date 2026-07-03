"""Reporters that turn a RunResult into machine- and human-readable output.

Importing this package registers every built-in reporter (JSON, HTML, SARIF,
JUnit) into the shared registry in :mod:`overstep.report.base`.
"""
from __future__ import annotations

from overstep.report.base import ReporterSpec, all_reporters, get_reporter, register, summarize

# Import for side effects: each module registers its reporter on import.
from overstep.report import html_report, json_report, junit, sarif  # noqa: E402,F401

__all__ = [
    "ReporterSpec",
    "all_reporters",
    "get_reporter",
    "register",
    "summarize",
]
