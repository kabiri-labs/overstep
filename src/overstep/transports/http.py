"""The HTTP transport: overstep's original (and default) delivery mechanism.

The executor itself lives in :mod:`overstep.executor`; this module just registers
it under the ``http`` name so the dispatcher can route HTTP cases to it. Keeping
the executor where it was preserves every existing import.
"""
from __future__ import annotations

from overstep.executor import run as _http_run
from overstep.http_repro import build_record, build_repro
from overstep.transports.base import register

register("http", _http_run, build_record=build_record, build_repro=build_repro)
