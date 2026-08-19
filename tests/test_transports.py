"""Tests for the transport abstraction.

overstep's core (matrix -> planner -> classifier -> report) is transport-agnostic;
the HTTP-specific execution now lives behind a registered *transport*. These tests
pin the seam: HTTP is a registered transport, resources/cases carry a transport
discriminator, and the dispatcher routes each case to the right transport.
"""
import asyncio

import httpx
import pytest

from overstep.models import Effect, Observation, Resource
from overstep.planner import plan
from overstep.transports import (
    TransportSpec,
    all_transports,
    dispatch,
    get_transport,
    register,
)


def test_http_transport_is_registered():
    names = {t.name for t in all_transports()}
    assert "http" in names
    spec = get_transport("http")
    assert isinstance(spec, TransportSpec)
    assert callable(spec.execute)


def test_resource_and_case_default_to_http(matrix):
    assert matrix.resources[0].transport == "http"
    for case in plan(matrix):
        assert case.transport == "http"


def test_planner_propagates_the_module_read_off_each_resource(matrix):
    """A case carries the module its resource belongs to; dispatch keys on it."""
    cases = plan(matrix)

    # Every resource in the shared fixture declares a `request`.
    assert all(r.transport == "http" for r in matrix.resources)
    assert all(c.transport == "http" for c in cases)


def test_dispatch_routes_cases_by_transport(matrix):
    """A case tagged with a transport only reaches that transport's executor."""
    seen = {"dummy": [], "http": []}

    def dummy_exec(base_url, subjects, cases, **kwargs):
        seen["dummy"] = [c.id for c in cases]
        return [Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases]

    def http_exec(base_url, subjects, cases, **kwargs):
        seen["http"] = [c.id for c in cases]
        return [Observation(test_id=c.id, status=403, effect=Effect.DENY) for c in cases]

    register("dummy", dummy_exec)
    original_http = get_transport("http").execute
    register("http", http_exec)  # temporarily swap the http executor for a stub
    try:
        cases = plan(matrix)
        # Tag half the cases as the dummy transport.
        for i, c in enumerate(cases):
            c.transport = "dummy" if i % 2 == 0 else "http"

        obs = dispatch("http://testserver", matrix.subjects, cases)

        dummy_ids = {c.id for c in cases if c.transport == "dummy"}
        http_ids = {c.id for c in cases if c.transport == "http"}
        assert set(seen["dummy"]) == dummy_ids
        assert set(seen["http"]) == http_ids
        # Every case produced exactly one observation, regardless of transport.
        assert {o.test_id for o in obs} == {c.id for c in cases}
    finally:
        register("http", original_http)  # restore the real http transport


def test_dispatch_over_http_end_to_end(matrix):
    """The real HTTP transport runs through the dispatcher against a mock server."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Grant only alice's own object; deny everything else.
        if request.url.path == "/users/u1" and request.headers.get("authorization") == "Bearer a":
            return httpx.Response(200, json={"id": "u1"})
        return httpx.Response(403, json={"error": "forbidden"})

    transport = httpx.MockTransport(handler)
    cases = plan(matrix)

    import overstep.executor as ex

    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)

    ex.httpx.AsyncClient = factory
    try:
        obs = dispatch("http://testserver", matrix.subjects, cases)
    finally:
        ex.httpx.AsyncClient = orig

    by_id = {o.test_id: o for o in obs}
    assert by_id["get_user::alice::self"].effect == Effect.ALLOW
    assert by_id["get_user::alice::self"].status == 200
    # A denied call comes back as DENY.
    assert by_id["admin_list::alice::na"].effect == Effect.DENY


def test_a_resource_cannot_name_a_transport_that_does_not_exist(matrix):
    """The check this replaces is now a state that cannot be reached.

    A resource used to declare `transport:` beside its body, so it could name a
    transport nothing had registered — or, worse, name a real one that
    contradicted what it actually sent, which validation had to catch by
    comparing the two. The module is read off the body instead, so there is no
    second declaration to disagree with and nothing left to validate.
    """
    resource = matrix.resources[0]

    with pytest.raises(AttributeError):
        resource.transport = "carrier-pigeon"

    assert resource.transport == "http"
    assert "transport" not in Resource.model_fields
