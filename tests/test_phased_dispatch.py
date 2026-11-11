"""Destructive cases are scheduled last, so a run's result does not depend on timing.

An expected-allow DELETE really deletes. Sent in the same concurrent pool as
everything else, it removes an object other in-flight cases still target: their
404 is then reported as an unexpected denial on a different test each run, and
- worse - an expected-deny probe against the vanished object reads as a correct
refusal whether or not the check behind it exists.

The target here is the smallest one where that happens: three orders, one per
subject, shared by a GET, a PATCH and an admin-only DELETE resource. Every
handler sleeps for a random moment, because the race needs requests to overlap
and an in-process server otherwise answers them in the order they were sent.
"""
import asyncio
import random

import httpx
import pytest

from overstep.matrix import Matrix
from overstep.models import Effect, Observation
from overstep.pipeline import phases, run_pipeline
from overstep.planner import plan

TOKENS = {"a": ("alice", "user"), "b": ("bob", "user"), "r": ("root", "admin")}


def orders_app(arrivals=None):
    """A correct orders API whose DELETE deletes. Fresh state per call."""
    fastapi = pytest.importorskip("fastapi")
    app = fastapi.FastAPI()
    orders = {"o-a": "alice", "o-b": "bob", "o-r": "root"}

    async def caller(request):
        # Jitter first, so arrival order is not send order.
        await asyncio.sleep(random.uniform(0, 0.004))
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token not in TOKENS:
            raise fastapi.HTTPException(401)
        if arrivals is not None:
            arrivals.append((request.method, TOKENS[token][0]))
        return TOKENS[token]

    def owned(order_id, name, role):
        if order_id not in orders:
            raise fastapi.HTTPException(404)
        if role != "admin" and orders[order_id] != name:
            raise fastapi.HTTPException(403)

    @app.get("/orders/{order_id}")
    async def get_order(order_id: str, request: fastapi.Request):
        name, role = await caller(request)
        owned(order_id, name, role)
        return {"id": order_id, "owner": orders[order_id]}

    @app.patch("/orders/{order_id}")
    async def patch_order(order_id: str, request: fastapi.Request):
        name, role = await caller(request)
        owned(order_id, name, role)
        return {"id": order_id}

    @app.delete("/orders/{order_id}")
    async def delete_order(order_id: str, request: fastapi.Request):
        name, role = await caller(request)
        if role != "admin":
            raise fastapi.HTTPException(403)
        if order_id not in orders:
            raise fastapi.HTTPException(404)
        del orders[order_id]
        return {"deleted": order_id}

    return app


def orders_matrix() -> Matrix:
    objects = {"alice": "o-a", "bob": "o-b", "root": "o-r"}

    def resource(name, method):
        return {
            "name": name,
            "request": {"method": method, "path": "/orders/{id}"},
            "type": "object",
            "owner": "id",
            "objects": dict(objects),
        }

    shared = {"allow": [{"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"}]}
    return Matrix(
        modules={"rest": {"base_url": "http://orders.test"}},
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a"},
            {"name": "bob", "role": "user", "token": "b"},
            {"name": "root", "role": "admin", "token": "r"},
        ],
        resources=[
            # Declared first on purpose: file order must not be what saves the run.
            resource("delete_order", "DELETE"),
            resource("get_order", "GET"),
            resource("patch_order", "PATCH"),
        ],
        policy={
            "delete_order": {"allow": [{"role": "admin", "scope": "any"}]},
            "get_order": shared,
            "patch_order": shared,
        },
    )


def run_against(app, matrix):
    import overstep.modules.rest.executor as ex

    orig = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.ASGITransport(app=app)
        return orig(*a, **kw)

    ex.httpx.AsyncClient = factory
    try:
        return run_pipeline(matrix)
    finally:
        ex.httpx.AsyncClient = orig


def test_forty_runs_against_a_target_that_really_deletes_agree():
    matrix = orders_matrix()
    outcomes = set()
    for _ in range(40):
        result = run_against(orders_app(), matrix)
        assert not result.health.inconclusive
        outcomes.add(tuple(sorted((f.test_id, f.vuln_class.value) for f in result.findings)))

    # The target enforces the matrix exactly, so the one stable answer is "nothing".
    assert outcomes == {()}


def test_deletes_arrive_after_everything_else_and_refused_ones_first():
    arrivals = []
    run_against(orders_app(arrivals), orders_matrix())

    methods = [method for method, _ in arrivals]
    assert set(methods) == {"GET", "PATCH", "DELETE"}
    last_get = max(i for i, m in enumerate(methods) if m == "GET")
    first_patch = min(i for i, m in enumerate(methods) if m == "PATCH")
    last_patch = max(i for i, m in enumerate(methods) if m == "PATCH")
    first_delete = min(i for i, m in enumerate(methods) if m == "DELETE")
    assert last_get < first_patch
    assert last_patch < first_delete

    deletes = [who for method, who in arrivals if method == "DELETE"]
    # root is the only subject allowed to delete; its requests come last.
    assert "root" in deletes and deletes.index("root") > 0
    assert set(deletes[deletes.index("root"):]) == {"root"}


def test_phases_keep_every_case_exactly_once_in_the_documented_order():
    cases = plan(orders_matrix())
    grouped = phases(cases)

    assert sorted(c.id for group in grouped for c in group) == sorted(c.id for c in cases)
    assert all(group for group in grouped), "an empty phase would be an empty dispatch"

    def rank(case):
        if not case.is_mutating:
            return 0
        destructive = case.method.upper() == "DELETE"
        return 1 + 2 * destructive + (case.expected == Effect.ALLOW)

    ranks = [{rank(c) for c in group} for group in grouped]
    assert all(len(r) == 1 for r in ranks)
    flat = [r.pop() for r in ranks]
    assert flat == sorted(flat)
    assert len(flat) == 5


def test_observations_come_back_in_plan_order_whatever_order_they_ran_in():
    seen = []

    def executor(base_url, subjects, cases, **kwargs):
        seen.append([c.id for c in cases])
        # Reversed, to prove the pipeline does not rely on a transport's order.
        return [
            Observation(test_id=c.id, status=200 if c.expected == Effect.ALLOW else 403,
                        effect=c.expected)
            for c in reversed(cases)
        ]

    result = run_pipeline(orders_matrix(), executor=executor)

    assert len(seen) > 1, "a single dispatch is the concurrent pool this replaces"
    assert [o.test_id for o in result.observations] == [c.id for c in result.cases]
    assert result.findings == []


def test_a_mutating_mcp_tool_is_held_back_and_its_refusals_go_first():
    matrix = Matrix(
        modules={"mcp": {"servers": [{"name": "docs", "url": "http://mcp.test/mcp"}]}},
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a"},
            {"name": "root", "role": "admin", "token": "r"},
        ],
        resources=[
            {"name": "reset", "type": "function",
             "call": {"server": "docs", "tool": "reset_tenant", "mutating": True}},
            {"name": "list_docs", "type": "function",
             "call": {"server": "docs", "tool": "list_docs"}},
        ],
        policy={
            "reset": {"allow": [{"role": "admin"}]},
            "list_docs": {"allow": [{"role": "user"}, {"role": "admin"}]},
        },
    )
    grouped = phases([c for c in plan(matrix) if c.resource in {"reset", "list_docs"}])
    order = [(c.resource, c.expected) for group in grouped for c in group]

    first_reset = min(i for i, (r, _) in enumerate(order) if r == "reset")
    assert all(r == "list_docs" for r, _ in order[:first_reset])
    resets = [e for r, e in order if r == "reset"]
    assert resets == sorted(resets, key=lambda e: e == Effect.ALLOW)
    assert Effect.DENY in resets and Effect.ALLOW in resets


# --- validate ---------------------------------------------------------------


def _shared_object_warnings(matrix):
    return [str(p) for p in matrix.diagnose() if "delete_order" in str(p) and "shares" in str(p)]


def test_validate_warns_when_an_allowed_delete_shares_objects():
    warnings = _shared_object_warnings(orders_matrix())

    assert len(warnings) == 1
    assert "get_order" in warnings[0] and "patch_order" in warnings[0]


def test_validate_stays_quiet_about_objects_setup_creates_fresh_each_run():
    """The advice is "create them in setup:", so a matrix that already does is fine."""
    matrix = orders_matrix()
    captured = {"alice": "{{A_ORDER}}", "bob": "{{B_ORDER}}", "root": "{{R_ORDER}}"}
    for resource in matrix.resources:
        resource.objects = dict(captured)

    assert _shared_object_warnings(matrix) == []


def test_validate_stays_quiet_when_nobody_may_delete_or_nothing_is_shared():
    refused = orders_matrix()
    refused.policy["delete_order"].allow.clear()
    assert _shared_object_warnings(refused) == []

    separate = orders_matrix()
    separate.resource_map()["delete_order"].objects.update(
        {"alice": "d-a", "bob": "d-b", "root": "d-r"}
    )
    assert _shared_object_warnings(separate) == []
