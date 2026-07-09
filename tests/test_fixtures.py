"""Tests for setup steps (fixtures / capture) and object-id resolution."""
import json

import httpx
import pytest

from overstep.fixtures import SetupError, run_setup
from overstep.matrix import Matrix
from overstep.planner import plan


def _transport(recorder=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if recorder is not None:
            recorder.append(request)
        if request.url.path == "/orders" and request.method == "POST":
            return httpx.Response(201, json={"id": "o-123", "status": "new"})
        if request.url.path == "/fail":
            return httpx.Response(500, json={})
        if request.url.path == "/notjson":
            return httpx.Response(200, text="plain")
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _client(recorder=None):
    return httpx.Client(transport=_transport(recorder), base_url="http://test")


def _setup_matrix():
    return Matrix(
        base_url="http://test",
        subjects=[
            {"name": "alice", "role": "user", "headers": {"Authorization": "Bearer tok-alice"},
             "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "attributes": {"user_id": "u2"}},
        ],
        setup=[
            {"name": "create order", "as": "alice",
             "request": {"method": "POST", "path": "/orders", "body": {"item": "x"}},
             "extract": {"ALICE_ORDER": "$.id"}},
        ],
        resources=[],
    )


def test_setup_captures_value_and_uses_subject_auth():
    recorder = []
    matrix = _setup_matrix()
    with _client(recorder) as client:
        context = run_setup(matrix, base_url="http://test", client=client)

    assert context == {"ALICE_ORDER": "o-123"}
    # The step ran as alice, so her token rode along.
    assert recorder[0].headers["Authorization"] == "Bearer tok-alice"


def test_setup_is_noop_without_steps():
    matrix = Matrix(base_url="http://test", subjects=[], resources=[])
    assert run_setup(matrix, base_url="http://test") == {}


def test_setup_raises_on_error_status():
    matrix = Matrix(
        base_url="http://test",
        subjects=[{"name": "a", "role": "user"}],
        setup=[{"request": {"method": "GET", "path": "/fail"}}],
        resources=[],
    )
    with _client() as client, pytest.raises(SetupError):
        run_setup(matrix, base_url="http://test", client=client)


def test_setup_raises_when_capture_missing():
    matrix = Matrix(
        base_url="http://test",
        subjects=[{"name": "a", "role": "user"}],
        setup=[{"request": {"method": "POST", "path": "/orders"}, "extract": {"X": "$.nope"}}],
        resources=[],
    )
    with _client() as client, pytest.raises(SetupError):
        run_setup(matrix, base_url="http://test", client=client)


def test_expect_status_allows_declared_code():
    matrix = Matrix(
        base_url="http://test",
        subjects=[{"name": "a", "role": "user"}],
        setup=[{"request": {"method": "POST", "path": "/orders"}, "expect_status": [201]}],
        resources=[],
    )
    with _client() as client:
        assert run_setup(matrix, base_url="http://test", client=client) == {}


# --- object-id resolution in the planner ------------------------------------

def _object_matrix():
    return Matrix(
        base_url="http://test",
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "attributes": {"user_id": "u2"}},
        ],
        resources=[
            {"name": "get_order",
             "request": {"method": "GET", "path": "/orders/{id}", "body": {"note": "{{ALICE_ORDER}}"}},
             "type": "object", "owner_param": "id",
             "objects": {"alice": "{{ALICE_ORDER}}", "bob": "o-bob"}},
        ],
        policy={"get_order": {"allow": [{"role": "user", "scope": "own"}]}},
    )


def test_objects_map_drives_self_and_other_paths():
    cases = {c.id: c for c in plan(_object_matrix(), {"ALICE_ORDER": "o-aaa"})}
    assert cases["get_order::alice::self"].path == "/orders/o-aaa"    # alice's captured order
    assert cases["get_order::alice::other"].path == "/orders/o-bob"   # reaching bob's -> BOLA probe
    assert cases["get_order::bob::self"].path == "/orders/o-bob"
    assert cases["get_order::bob::other"].path == "/orders/o-aaa"


def test_captures_fill_request_body():
    case = {c.id: c for c in plan(_object_matrix(), {"ALICE_ORDER": "o-aaa"})}["get_order::alice::self"]
    assert case.body == {"note": "o-aaa"}


def test_validate_flags_setup_and_objects_unknown_subjects():
    matrix = Matrix(
        subjects=[{"name": "alice", "role": "user"}],
        setup=[{"name": "s", "as": "ghost", "request": {"method": "GET", "path": "/x"}}],
        resources=[
            {"name": "r", "request": {"method": "GET", "path": "/r/{id}"}, "type": "object",
             "owner_param": "id", "objects": {"nobody": "1"}},
        ],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    problems = matrix.validate_refs()
    assert any("unknown subject 'ghost'" in p for p in problems)
    assert any("unknown\n" not in p and "'nobody'" in p for p in problems)


def test_run_teardown_is_best_effort_and_uses_captures():
    import httpx

    from overstep.fixtures import run_teardown
    from overstep.matrix import Matrix

    deleted = {"paths": []}

    def handler(request: httpx.Request) -> httpx.Response:
        deleted["paths"].append(request.url.path)
        # One cleanup fails; teardown must not raise, only warn.
        if request.url.path.endswith("/boom"):
            return httpx.Response(500)
        return httpx.Response(204)

    matrix = Matrix(
        subjects=[{"name": "alice", "role": "user", "token": "a"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/r"}}],
        policy={"r": {"allow": [{"role": "user"}]}},
        teardown=[
            {"name": "drop order", "as": "alice",
             "request": {"method": "DELETE", "path": "/orders/{{order_id}}"}},
            {"name": "boom", "request": {"method": "DELETE", "path": "/boom"}},
        ],
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    warnings = run_teardown(matrix, base_url="http://api.test", context={"order_id": "o-123"}, client=client)
    # The {{order_id}} capture was substituted into the cleanup path.
    assert "/orders/o-123" in deleted["paths"]
    # The failing step surfaced as a warning rather than an exception.
    assert any("boom" in w for w in warnings)


def test_run_teardown_noop_without_steps():
    from overstep.fixtures import run_teardown
    from overstep.matrix import Matrix

    matrix = Matrix(
        subjects=[{"name": "alice", "role": "user"}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/r"}}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    assert run_teardown(matrix, base_url="http://api.test") == []
