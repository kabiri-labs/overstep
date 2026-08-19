"""The transport seam: how a test case is actually delivered to a target.

overstep's domain — the matrix, the planner, the classifier, the reports — does
not care *how* a request reaches the system under test. That concern is isolated
here behind a small registry, exactly like the reporter registry in
:mod:`overstep.report.base`. HTTP is one transport; another (e.g. MCP tool-calls)
can be added by registering a second executor, without touching the core.

A transport is a callable with the same shape as :func:`overstep.modules.rest.executor.run`::

    execute(base_url, subjects, cases, **kwargs) -> List[Observation]

The :func:`dispatch` function groups the planned cases by each case's declared
``transport`` and routes every group to the matching executor, so a single run
can mix transports.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from overstep.models import Effect, Observation, Subject, TestCase

# Same shape as executor.run — a transport turns cases into observations.
ExecuteFn = Callable[..., List[Observation]]

# The rest of what a surface has to be able to do for itself. Each takes the
# case (and the subject it is sent as) and answers in that surface's own terms.
RecordFn = Callable[..., Dict[str, object]]   # a masked, structured request record
ReproFn = Callable[..., str]                  # a copy-pasteable command
StepFn = Callable[..., object]                # one setup/teardown step

DEFAULT_TRANSPORT = "http"


@dataclass(frozen=True)
class TransportSpec:
    """Everything the core needs from a surface, and nothing it needs to know.

    Delivery was the only capability here, which is why every other
    surface-specific decision ended up in a core module reaching into a
    module's internals: `repro` imported both surfaces to render either kind of
    command, and `fixtures` imported the MCP client to run a setup step that
    happened to be a tool-call. Each of those is a question only the surface can
    answer, so the surface answers it.

    The three added capabilities are optional. A transport that registers none
    of them still executes cases; the core falls back and says what it could not
    do, rather than a missing capability failing a run.
    """

    name: str
    execute: ExecuteFn
    build_record: Optional[RecordFn] = None
    build_repro: Optional[ReproFn] = None
    run_step: Optional[StepFn] = None


_REGISTRY: Dict[str, TransportSpec] = {}


def register(
    name: str,
    execute: ExecuteFn,
    *,
    build_record: Optional[RecordFn] = None,
    build_repro: Optional[ReproFn] = None,
    run_step: Optional[StepFn] = None,
) -> TransportSpec:
    """Register (or replace) a transport by name; returns the new spec."""
    spec = TransportSpec(
        name=name,
        execute=execute,
        build_record=build_record,
        build_repro=build_repro,
        run_step=run_step,
    )
    _REGISTRY[name] = spec
    return spec


def restore(spec: TransportSpec) -> TransportSpec:
    """Put a whole spec back, capabilities and all.

    `register` defines a transport completely, which means re-registering a name
    with only its executor silently drops everything else it could do. That is
    the right behaviour for a definition and a trap for a caller holding a saved
    spec: a test that stubbed delivery and restored it by re-registering the old
    execute function used to be harmless, and the moment specs carried more than
    delivery it left the real transport unable to render a repro for the rest of
    the session. Anything round-tripping a spec should use this instead.
    """
    _REGISTRY[spec.name] = spec
    return spec


def capability(transport: str, name: str):
    """One transport's implementation of a capability, or None.

    Looked up by name rather than reached for directly so an unregistered
    transport — or one that implements only delivery — is a `None` the caller
    can describe, not an exception in the middle of building a report.
    """
    spec = _REGISTRY.get(transport or DEFAULT_TRANSPORT)
    return getattr(spec, name, None) if spec else None


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
