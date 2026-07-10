"""The transport seam: how a test case is actually delivered to a target.

overstep's domain — the matrix, the planner, the classifier, the reports — does
not care *how* a request reaches the system under test. That concern is isolated
here behind a small registry, exactly like the reporter registry in
:mod:`overstep.report.base`. HTTP is one transport; another (e.g. MCP tool-calls)
can be added by registering a second executor, without touching the core.

A transport is a callable with the same shape as :func:`overstep.executor.run`::

    execute(base_url, subjects, cases, **kwargs) -> List[Observation]

The :func:`dispatch` function groups the planned cases by each case's declared
``transport`` and routes every group to the matching executor, so a single run
can mix transports.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from overstep.models import Effect, Observation, Subject, TestCase

# Same shape as executor.run — a transport turns cases into observations.
ExecuteFn = Callable[..., List[Observation]]

DEFAULT_TRANSPORT = "http"


@dataclass(frozen=True)
class TransportSpec:
    name: str
    execute: ExecuteFn


_REGISTRY: Dict[str, TransportSpec] = {}


def register(name: str, execute: ExecuteFn) -> TransportSpec:
    """Register (or replace) a transport by name; returns the new spec."""
    spec = TransportSpec(name=name, execute=execute)
    _REGISTRY[name] = spec
    return spec


def all_transports() -> List[TransportSpec]:
    return list(_REGISTRY.values())


def get_transport(name: str) -> TransportSpec:
    return _REGISTRY[name]


def transport_names() -> List[str]:
    return list(_REGISTRY.keys())


def dispatch(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    **kwargs,
) -> List[Observation]:
    """Route each case to its transport's executor and merge the observations.

    Cases are grouped by ``case.transport`` (defaulting to ``http``). Each group
    is handed to that transport's executor with ``base_url``, ``subjects`` and the
    shared keyword arguments (concurrency, verify_tls, read_only, retries, …).
    """
    groups: Dict[str, List[TestCase]] = {}
    for case in cases:
        groups.setdefault(case.transport or DEFAULT_TRANSPORT, []).append(case)

    observations: List[Observation] = []
    for name, group in groups.items():
        spec = _REGISTRY.get(name)
        if spec is None:
            # An unknown transport can't be executed; record a transport error so
            # the case is visible rather than silently dropped.
            observations.extend(
                Observation(
                    test_id=c.id,
                    status=0,
                    effect=Effect.DENY,
                    error=f"no transport registered for '{name}'",
                )
                for c in group
            )
            continue
        observations.extend(spec.execute(base_url, subjects, group, **kwargs))
    return observations
