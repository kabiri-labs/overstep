"""Tests for the generalized object-identifier injection model.

Covers every injection location (path, query, header, cookie, form, json,
graphql_variables, mcp_argument), SELF vs OTHER, multiple simultaneous
injections, per-injection owner_attr overrides, backward compatibility with the
legacy owner_param/owner_arg, and validation.
"""
import asyncio
import os

import httpx

from overstep.jsonpath import extract, set_at
from overstep.matrix import Matrix, load_matrix
from overstep.planner import plan

_EXAMPLE = os.path.join(
    os.path.dirname(__file__), "..", "examples", "injections", "matrix.yaml"
)

_SUBJECTS = [
    {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1", "tenant": "t1"}},
    {"name": "bob", "role": "user", "token": "b", "attributes": {"user_id": "u2", "tenant": "t2"}},
]

_OBJECTS = {"alice": "o-alice", "bob": "o-bob"}


def _by_id(cases):
    return {c.id: c for c in cases}


def _http_matrix(resource_extra, request=None):
    request = request or {"method": "GET", "path": "/orders"}
    resource = {
        "name": "get_order",
        "request": request,
        "type": "object",
        "objects": dict(_OBJECTS),
        **resource_extra,
    }
    return Matrix(
        base_url="http://api.test",
        roles=["user"],
        subjects=[dict(s) for s in _SUBJECTS],
        resources=[resource],
        policy={"get_order": {"allow": [{"role": "user", "scope": "any"}]}},
    )


# --- JSON path setter -------------------------------------------------------

def test_set_at_creates_nested_objects():
    body = set_at({}, "$.order.id", "o-alice")
    assert body == {"order": {"id": "o-alice"}}
    assert extract("$.order.id", body) == "o-alice"


def test_set_at_creates_arrays_for_numeric_segments():
    body = set_at(None, "$.items[0].id", "o-1")
    assert body == {"items": [{"id": "o-1"}]}
    assert extract("$.items[0].id", body) == "o-1"


def test_set_at_preserves_existing_siblings():
    body = set_at({"order": {"total": 10}}, "$.order.id", "o-alice")
    assert body == {"order": {"total": 10, "id": "o-alice"}}


# --- Injection locations ----------------------------------------------------

def test_query_injection_self_and_other():
    m = _http_matrix({"ownership": {"injections": [{"location": "query", "selector": "order_id"}]}})
    cases = _by_id(plan(m))
    assert cases["get_order::alice::self"].query["order_id"] == "o-alice"
    assert cases["get_order::alice::other"].query["order_id"] == "o-bob"


def test_header_injection():
    m = _http_matrix({"ownership": {"injections": [{"location": "header", "selector": "X-Account-ID"}]}})
    cases = _by_id(plan(m))
    assert cases["get_order::alice::self"].headers["X-Account-ID"] == "o-alice"
    assert cases["get_order::bob::other"].headers["X-Account-ID"] == "o-alice"


def test_cookie_injection_merges_into_cookie_header():
    m = _http_matrix(
        {
            "request": {"method": "GET", "path": "/orders", "headers": {"Cookie": "sid=abc"}},
            "ownership": {"injections": [{"location": "cookie", "selector": "owner"}]},
        }
    )
    cases = _by_id(plan(m))
    cookie = cases["get_order::alice::self"].headers["Cookie"]
    assert "sid=abc" in cookie and "owner=o-alice" in cookie


def test_form_injection():
    m = _http_matrix(
        {
            "request": {"method": "POST", "path": "/orders"},
            "ownership": {"injections": [{"location": "form", "selector": "account"}]},
        }
    )
    cases = _by_id(plan(m))
    assert cases["get_order::alice::other"].form["account"] == "o-bob"


def test_json_injection_into_nested_body():
    m = _http_matrix(
        {
            "request": {"method": "POST", "path": "/orders", "body": {"order": {"note": "x"}}},
            "ownership": {"injections": [{"location": "json", "selector": "$.order.id"}]},
        }
    )
    cases = _by_id(plan(m))
    body = cases["get_order::alice::self"].body
    assert body["order"]["id"] == "o-alice"
    assert body["order"]["note"] == "x"  # existing content preserved


def test_json_injection_creates_body_when_absent():
    m = _http_matrix({"ownership": {"injections": [{"location": "json", "selector": "$.id"}]}})
    cases = _by_id(plan(m))
    assert cases["get_order::alice::self"].body == {"id": "o-alice"}


def test_graphql_variables_injection():
    m = _http_matrix(
        {
            "request": {
                "method": "POST",
                "path": "/graphql",
                "body": {"query": "query($documentId:ID!){doc(id:$documentId){id}}", "variables": {}},
            },
            "ownership": {"injections": [{"location": "graphql_variables", "selector": "documentId"}]},
        }
    )
    cases = _by_id(plan(m))
    body = cases["get_order::alice::other"].body
    assert body["variables"]["documentId"] == "o-bob"
    assert body["query"].startswith("query(")


def test_multiple_simultaneous_injections():
    m = _http_matrix(
        {
            "request": {"method": "GET", "path": "/orders/{id}"},
            "ownership": {
                "injections": [
                    {"location": "path", "selector": "id"},
                    {"location": "header", "selector": "X-Tenant", "owner_attr": "tenant"},
                ]
            },
        }
    )
    cases = _by_id(plan(m))
    alice_other = cases["get_order::alice::other"]
    assert alice_other.path == "/orders/o-bob"           # object id from objects map
    assert alice_other.headers["X-Tenant"] == "t2"       # tenant from bob's attributes


def test_owner_attr_override_pulls_a_different_attribute():
    m = _http_matrix(
        {"ownership": {"injections": [{"location": "query", "selector": "t", "owner_attr": "tenant"}]}}
    )
    cases = _by_id(plan(m))
    assert cases["get_order::alice::self"].query["t"] == "t1"
    assert cases["get_order::alice::other"].query["t"] == "t2"


def test_owner_attr_only_injection_drives_variant_generation():
    """A resource whose sole locator is an owner_attr injection must still emit
    real SELF/OTHER probes for subjects that carry that attribute."""
    m = Matrix(
        base_url="http://api.test",
        roles=["user"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"tenant": "t1"}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"tenant": "t2"}},
        ],
        resources=[
            {
                "name": "get_by_tenant",
                "request": {"method": "GET", "path": "/records"},
                "type": "object",
                # No objects map and no user_id attribute: the ONLY locator is the
                # tenant, sourced via owner_attr.
                "ownership": {"injections": [{"location": "query", "selector": "tenant", "owner_attr": "tenant"}]},
            }
        ],
        policy={"get_by_tenant": {"allow": [{"role": "user", "scope": "any"}]}},
    )
    assert m.validate_refs() == []  # subjects have tenant -> resolvable
    cases = _by_id(plan(m))
    # SELF is generated (previously skipped) and carries the subject's own tenant.
    assert cases["get_by_tenant::alice::self"].query["tenant"] == "t1"
    # OTHER has a real target and the victim's tenant injected (not empty).
    assert cases["get_by_tenant::alice::other"].query["tenant"] == "t2"


def test_cookie_injection_survives_subject_cookie_auth():
    """A subject's session Cookie must not clobber an injected object-id cookie."""
    from overstep.executor import build_headers

    m = _http_matrix(
        {
            "request": {"method": "GET", "path": "/orders"},
            "ownership": {"injections": [{"location": "cookie", "selector": "owner"}]},
        }
    )
    # alice authenticates with a session cookie.
    m.subjects[0].headers = {"Cookie": "sid=alice-session"}
    case = _by_id(plan(m))["get_order::alice::other"]  # injected owner=o-bob
    cookie = build_headers(m.subjects[0], case)["Cookie"]
    assert "sid=alice-session" in cookie   # session preserved
    assert "owner=o-bob" in cookie         # injected object id preserved


# --- MCP --------------------------------------------------------------------

def _mcp_matrix(ownership_or_legacy):
    resource = {
        "name": "read_doc",
        "transport": "mcp",
        "call": {"server": "docs", "tool": "read_document"},
        "type": "object",
        "objects": dict(_OBJECTS),
        **ownership_or_legacy,
    }
    return Matrix(
        roles=["user"],
        subjects=[dict(s) for s in _SUBJECTS],
        servers=[{"name": "docs", "url": "http://mcp.test/mcp"}],
        resources=[resource],
        policy={"read_doc": {"allow": [{"role": "user", "scope": "any"}]}},
    )


def test_mcp_argument_injection_new_model():
    m = _mcp_matrix({"ownership": {"injections": [{"location": "mcp_argument", "selector": "doc_id"}]}})
    cases = _by_id(plan(m))
    assert cases["read_doc::alice::other"].mcp.arguments["doc_id"] == "o-bob"


def test_mcp_argument_injection_jsonpath():
    m = _mcp_matrix({"ownership": {"injections": [{"location": "mcp_argument", "selector": "$.filter.id"}]}})
    cases = _by_id(plan(m))
    assert cases["read_doc::alice::self"].mcp.arguments["filter"]["id"] == "o-alice"


# --- Backward compatibility -------------------------------------------------

def test_legacy_owner_param_still_injects_into_path():
    m = _http_matrix({"owner_param": "id", "request": {"method": "GET", "path": "/orders/{id}"}})
    cases = _by_id(plan(m))
    assert cases["get_order::alice::self"].path == "/orders/o-alice"
    assert cases["get_order::alice::other"].path == "/orders/o-bob"


def test_legacy_owner_arg_still_injects_into_mcp_argument():
    m = _mcp_matrix({"owner_arg": "doc_id"})
    cases = _by_id(plan(m))
    assert cases["read_doc::alice::other"].mcp.arguments["doc_id"] == "o-bob"


# --- Validation -------------------------------------------------------------

def test_validation_rejects_mcp_argument_on_http_resource():
    m = _http_matrix({"ownership": {"injections": [{"location": "mcp_argument", "selector": "doc_id"}]}})
    assert any("cannot use an 'mcp_argument'" in p for p in m.validate_refs())


def test_validation_rejects_http_location_on_mcp_resource():
    m = _mcp_matrix({"ownership": {"injections": [{"location": "query", "selector": "doc_id"}]}})
    assert any("must use location 'mcp_argument'" in p for p in m.validate_refs())


def test_validation_flags_path_injection_that_is_not_a_parameter():
    m = _http_matrix({"ownership": {"injections": [{"location": "path", "selector": "id"}]}})
    # path is /orders (no {id}) -> selector is not a parameter
    assert any("is not a parameter in path" in p for p in m.validate_refs())


def test_validation_warns_on_unresolvable_ownership():
    m = Matrix(
        base_url="http://api.test",
        roles=["user"],
        subjects=[{"name": "carol", "role": "user", "token": "c"}],  # no objects, no user_id
        resources=[
            {
                "name": "get_order",
                "request": {"method": "GET", "path": "/orders"},
                "type": "object",
                "ownership": {"injections": [{"location": "query", "selector": "order_id"}]},
            }
        ],
        policy={"get_order": {"allow": [{"role": "user", "scope": "any"}]}},
    )
    assert any("no subject with a resolvable object" in p for p in m.validate_refs())


def test_object_resource_needs_a_locator():
    m = _http_matrix({})  # no owner_param, no ownership
    assert any("must set owner_param or ownership.injections" in p for p in m.validate_refs())


# --- End-to-end: the form body is actually sent form-encoded ----------------

def test_form_body_is_sent_url_encoded():
    from overstep.executor import execute

    m = _http_matrix(
        {
            "request": {"method": "POST", "path": "/orders"},
            "ownership": {"injections": [{"location": "form", "selector": "account"}]},
        }
    )
    cases = [c for c in plan(m) if c.id == "get_order::alice::self"]
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["content_type"] = request.headers.get("content-type", "")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)

    async def _run():
        import overstep.executor as ex
        orig = httpx.AsyncClient
        ex.httpx.AsyncClient = lambda *a, **kw: orig(*a, **{**kw, "transport": transport})
        try:
            return await execute("http://api.test", m.subjects, cases)
        finally:
            ex.httpx.AsyncClient = orig

    asyncio.run(_run())
    assert "application/x-www-form-urlencoded" in seen["content_type"]
    assert "account=o-alice" in seen["body"]


# --- Shipped example --------------------------------------------------------

def test_shipped_injection_example_is_valid_and_resolves():
    m = load_matrix(_EXAMPLE)
    assert m.validate_refs() == []
    cases = _by_id(plan(m))
    # A few representative injections land where they should.
    assert cases["get_order::alice::other"].query["order_id"] == "order-b1"
    assert cases["get_account::alice::self"].headers["X-Account-ID"] == "acct-a"
    assert cases["get_account::alice::self"].headers["X-Tenant"] == "t1"
    assert cases["update_order::bob::other"].body["order"]["id"] == "order-a1"
    assert cases["read_document_gql::alice::other"].body["variables"]["documentId"] == "doc-b"
    assert cases["read_document_mcp::alice::other"].mcp.arguments["doc_id"] == "doc-b"
