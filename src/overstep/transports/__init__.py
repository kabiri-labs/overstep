"""Transports: the pluggable seam between the core and the system under test.

Importing this package registers every built-in transport (currently HTTP) into
the shared registry in :mod:`overstep.transports.base`, mirroring how
:mod:`overstep.report` registers reporters.
"""
from __future__ import annotations

from overstep.transports.base import (
    DEFAULT_TRANSPORT,
    TransportSpec,
    all_transports,
    dispatch,
    get_transport,
    register,
    transport_names,
)

# Import for side effects: each module registers its transport on import.
from overstep.transports import http  # noqa: E402,F401
from overstep.transports import mcp  # noqa: E402,F401

__all__ = [
    "DEFAULT_TRANSPORT",
    "TransportSpec",
    "all_transports",
    "dispatch",
    "get_transport",
    "register",
    "transport_names",
]
