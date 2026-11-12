"""How a run talks to the network: how long it waits, through what, and how fast.

Three settings, one place. They used to be a literal — ``timeout=15.0`` — typed
into every function that opens a connection: the two transports, the login
providers, the setup steps, the MCP client and its OAuth discovery. A target
slower than that could not be tested at all, because nothing a user could reach
changed the number, and a proxy or a pause between requests had nowhere to be
said either.

They are carried in a context variable rather than threaded through every
signature between the command line and the socket. That keeps the seams the
pipeline is injected through — executor, authenticator, setup runner — the shape
they already have, so a caller that replaces one is not broken by a setting it
has no use for. ``asyncio.run`` copies the context, so the value set around a
run is the value its tasks see.

Embedding code sets them the same way the CLI does::

    with netopts.using(timeout=60, delay=0.2):
        result = run_pipeline(matrix)
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterator, Optional

# What every connection waited before any of this was configurable. Kept as the
# default so a run that sets nothing behaves exactly as it did.
DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class NetOptions:
    # Seconds to wait on a connection or a response before giving up.
    timeout: float = DEFAULT_TIMEOUT
    # A proxy URL for every request the run makes, or None to leave httpx to its
    # defaults — which already honour HTTP_PROXY / HTTPS_PROXY / NO_PROXY.
    proxy: Optional[str] = None
    # The least time between the start of one test request and the next, across
    # the whole run rather than per connection. Zero means no pause.
    delay: float = 0.0


_current: ContextVar[NetOptions] = ContextVar("overstep_netopts", default=NetOptions())


def current() -> NetOptions:
    return _current.get()


@contextmanager
def using(**changes: Any) -> Iterator[NetOptions]:
    """Apply settings for the duration of a block; ``None`` leaves one alone."""
    options = replace(current(), **{k: v for k, v in changes.items() if v is not None})
    if options.timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if options.delay < 0:
        raise ValueError("delay cannot be negative")
    token = _current.set(options)
    try:
        yield options
    finally:
        _current.reset(token)


def timeout(explicit: Optional[float] = None) -> float:
    """The timeout to use: a caller's own, or the run's."""
    return current().timeout if explicit is None else explicit


def client_kwargs(explicit_timeout: Optional[float] = None) -> Dict[str, Any]:
    """The keyword arguments every ``httpx`` client in a run is built with.

    The proxy is only passed when one was asked for. Passing ``proxy=None``
    would look the same and mean something else: it tells httpx there is no
    proxy, which switches off the environment variables people already rely on.
    """
    kwargs: Dict[str, Any] = {"timeout": timeout(explicit_timeout)}
    proxy = current().proxy
    if proxy:
        kwargs["proxy"] = proxy
    return kwargs


class Gate:
    """Bounds how many requests are in flight, and how close together they start.

    The first half is the semaphore the transports always had. The second is
    the pause: with a delay set, each request waits until at least that long
    after the previous one *started* — one clock for the whole dispatch, since
    a per-connection pause multiplied by the concurrency is no limit a target
    would recognise. Used as ``async with gate:`` exactly like the semaphore it
    replaces.
    """

    def __init__(self, concurrency: int, delay: Optional[float] = None) -> None:
        self._slots = asyncio.Semaphore(concurrency)
        self._delay = current().delay if delay is None else delay
        self._turn = asyncio.Lock()
        self._next = 0.0

    async def __aenter__(self) -> "Gate":
        await self._slots.acquire()
        if self._delay > 0:
            try:
                async with self._turn:
                    loop = asyncio.get_running_loop()
                    wait = self._next - loop.time()
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._next = loop.time() + self._delay
            except BaseException:
                self._slots.release()
                raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._slots.release()
