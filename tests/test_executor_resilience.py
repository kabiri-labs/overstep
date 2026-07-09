"""Tests for executor resilience: 429 retry/backoff, read-only mode, teardown."""
import asyncio

import httpx
import pytest

from overstep.executor import execute
from overstep.matrix import Matrix
from overstep.models import Effect


def _matrix() -> Matrix:
    return Matrix(
        base_url="http://api.test",
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1"}}],
        resources=[
            {"name": "get_user", "request": {"method": "GET", "path": "/users/{id}"},
             "type": "object", "owner_param": "id", "owner_attr": "user_id"},
        ],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )


def _run_with_transport(matrix, cases, transport, **kwargs):
    async def _run():
        import overstep.executor as ex
        orig = httpx.AsyncClient

        def factory(*a, **kw):
            kw["transport"] = transport
            return orig(*a, **kw)

        ex.httpx.AsyncClient = factory
        try:
            return await execute("http://api.test", matrix.subjects, cases, **kwargs)
        finally:
            ex.httpx.AsyncClient = orig

    return asyncio.run(_run())


def test_retries_on_429_then_succeeds():
    from overstep.planner import plan

    m = _matrix()
    cases = [c for c in plan(m) if c.variant.value == "self"]
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"Retry-After": "0"}, text="slow down")
        return httpx.Response(200, json={"id": "u1"})

    obs = _run_with_transport(m, cases, httpx.MockTransport(handler), max_retries=3, backoff_base=0.0)
    assert calls["n"] == 3               # two 429s, then a 200
    assert obs[0].status == 200
    assert obs[0].effect == Effect.ALLOW


def test_gives_up_after_max_retries():
    from overstep.planner import plan

    m = _matrix()
    cases = [c for c in plan(m) if c.variant.value == "self"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="nope")

    obs = _run_with_transport(m, cases, httpx.MockTransport(handler), max_retries=2, backoff_base=0.0)
    assert obs[0].status == 429
    assert obs[0].effect == Effect.DENY


def test_read_only_skips_mutating_methods():
    from overstep.planner import plan

    m = _matrix()
    m.resources[0].request.method = "DELETE"
    cases = plan(m)
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200)

    obs = _run_with_transport(m, cases, httpx.MockTransport(handler), read_only=True)
    # No DELETE ever hit the network.
    assert called["n"] == 0
    assert all(o.skipped for o in obs)
    assert all(o.effect == Effect.DENY for o in obs)


def test_read_only_still_runs_get():
    from overstep.planner import plan

    m = _matrix()
    cases = [c for c in plan(m) if c.variant.value == "self"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "u1"})

    obs = _run_with_transport(m, cases, httpx.MockTransport(handler), read_only=True)
    assert obs[0].skipped is False
    assert obs[0].status == 200
