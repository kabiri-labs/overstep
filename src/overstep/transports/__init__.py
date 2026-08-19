"""The registry the core reaches the surfaces through.

The registry itself is core — it knows that *a* surface delivers cases, renders
evidence and runs setup steps, and nothing about how any of them does it.
Importing this package pulls in the built-in modules so they register
themselves, mirroring how :mod:`overstep.report` registers reporters.
"""
from __future__ import annotations

from overstep.transports.base import (
    DEFAULT_TRANSPORT,
    TransportSpec,
    all_transports,
    capability,
    dispatch,
    get_transport,
    register,
    restore,
    transport_names,
)

# Import for side effects: each surface registers itself on import.
from overstep.modules.mcp import transport as _mcp  # noqa: E402,F401
from overstep.modules.rest import transport as _rest  # noqa: E402,F401

__all__ = [
    "DEFAULT_TRANSPORT",
    "TransportSpec",
    "all_transports",
    "capability",
    "dispatch",
    "get_transport",
    "register",
    "restore",
    "transport_names",
]
