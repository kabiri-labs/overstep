"""Reporter plumbing: a small registry so output formats are pluggable.

Every reporter is a function ``write(result, path)`` registered under a name and a
default filename. The pipeline discovers them through :func:`all_reporters`, so
adding a format is a one-line decorator with no changes to the pipeline or CLI.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List

from overstep.models import Effect, RunResult, VulnClass

WriteFn = Callable[[RunResult, str], None]


@dataclass(frozen=True)
class ReporterSpec:
    name: str
    filename: str
    write: WriteFn


_REGISTRY: Dict[str, ReporterSpec] = {}


def register(name: str, filename: str) -> Callable[[WriteFn], WriteFn]:
    def decorator(fn: WriteFn) -> WriteFn:
        _REGISTRY[name] = ReporterSpec(name=name, filename=filename, write=fn)
        return fn

    return decorator


def all_reporters() -> List[ReporterSpec]:
    return list(_REGISTRY.values())


def get_reporter(name: str) -> ReporterSpec:
    return _REGISTRY[name]


def summarize(result: RunResult) -> Dict[str, object]:
    """A compact roll-up used by the CLI and the JSON/HTML reports."""
    positive = sum(1 for c in result.cases if c.expected == Effect.ALLOW)
    negative = sum(1 for c in result.cases if c.expected == Effect.DENY)
    by_class = Counter(f.vuln_class.value for f in result.findings)
    return {
        "total_tests": len(result.cases),
        "positive_tests": positive,
        "negative_tests": negative,
        "findings": len(result.findings),
        "vulnerabilities": len(result.vulnerabilities),
        "drift": len(result.drift),
        "waived": len(result.waived),
        "by_class": dict(by_class),
    }
