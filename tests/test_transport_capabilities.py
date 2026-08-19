"""The seams that let a surface answer its own questions.

Delivery used to be the only thing a transport could register, so every other
surface-specific decision ended up inside a core module: `repro` imported both
surfaces to render either kind of command, `fixtures` imported the MCP client to
run a setup step that happened to be a tool-call, and `auth` imported MCP
discovery to resolve a `discover_from`.

A `TransportSpec` now carries three optional capabilities beside `execute`, and
there is a separate registry for discovery, which is not per-case. These cases
pin the seams themselves — that a capability is reached through the registry, and
that a transport which registers none of them still works.
"""
import pytest

from overstep import discovery
from overstep.models import (
    AuthProvider,
    Effect,
    McpInvocation,
    Observation,
    ResourceType,
    Subject,
    TestCase,
    Variant,
)
from overstep.transports import (
    capability,
    get_transport,
    register,
    restore,
)


@pytest.fixture
def rest_case():
    return TestCase(
        id="t", resource="r", subject="alice", role="user", method="GET",
        path_template="/x/{id}", path="/x/1", variant=Variant.NA,
        expected=Effect.DENY, resource_type=ResourceType.FUNCTION, transport="http",
    )


@pytest.fixture
def mcp_case():
    return TestCase(
        id="t", resource="r", subject="alice", role="user", method="tools/call",
        path_template="read", path="read", variant=Variant.NA,
        expected=Effect.DENY, resource_type=ResourceType.FUNCTION, transport="mcp",
        mcp=McpInvocation(url="http://docs.test/mcp", tool="read",
                          arguments={"doc_id": "d-bob"}),
    )


@pytest.fixture
def alice():
    return Subject(name="alice", role="user", token="alice-token")


# --- the built-ins answer for themselves --------------------------------------


@pytest.mark.parametrize("transport", ["http", "mcp"])
@pytest.mark.parametrize("name", ["build_record", "build_repro"])
def test_each_surface_registers_its_own_rendering(transport, name):
    assert capability(transport, name) is not None, (
        f"the {transport} transport registered no {name}"
    )


def test_only_the_mcp_transport_knows_how_to_run_a_step():
    """A setup step is a tool-call or an HTTP request; only one goes through here.

    The REST path never needed the seam — `fixtures` already built its request
    inline from the step, and there is nothing surface-private about it.
    """
    assert capability("mcp", "run_step") is not None
    assert capability("http", "run_step") is None


def test_the_repro_reaches_the_surface_that_can_render_it(rest_case, mcp_case, alice):
    """Each surface's own shape, through one core entry point."""
    from overstep.repro import to_curl

    rest = to_curl("http://api.test", alice, rest_case)
    mcp = to_curl("", alice, mcp_case)

    assert rest.startswith("curl") and "http://api.test/x/1" in rest
    assert "tools/call" in mcp and "http://docs.test/mcp" in mcp
    # The credential is a shell variable in both, never the literal token.
    assert "alice-token" not in rest and "alice-token" not in mcp
    assert "$OVERSTEP_TOKEN_ALICE" in rest and "$OVERSTEP_TOKEN_ALICE" in mcp


# --- a transport that registers nothing else ----------------------------------


def test_a_delivery_only_transport_still_runs_and_says_what_it_cannot_do(rest_case):
    """The capabilities are optional, and their absence is described, not raised.

    A missing repro must not take down the report a finding is being written
    into — the finding is still real and still worth reporting without one.
    """
    from overstep.repro import request_record, to_curl

    def deliver(base_url, subjects, cases, **kwargs):
        return [Observation(test_id=c.id, status=200, effect=Effect.ALLOW) for c in cases]

    register("carrier-pigeon", deliver)
    try:
        rest_case.transport = "carrier-pigeon"

        assert capability("carrier-pigeon", "build_repro") is None
        assert "no repro available" in to_curl("http://api.test", Subject(name="a"), rest_case)
        assert request_record("http://api.test", Subject(name="a"), rest_case) == {
            "method": "GET", "transport": "carrier-pigeon",
        }
    finally:
        from overstep.transports.base import _REGISTRY

        _REGISTRY.pop("carrier-pigeon", None)


def test_restoring_a_transport_keeps_every_capability():
    """The footgun this API grew the moment a spec carried more than delivery.

    `register` defines a transport completely, so re-registering a saved
    *execute function* silently drops the rest. A test that stubbed HTTP delivery
    and restored it that way left the real transport unable to render a repro for
    every case that followed — which reached the golden-file comparison as a
    baffling diff in an unrelated suite.
    """
    original = get_transport("http")
    assert original.build_repro is not None

    def stub(base_url, subjects, cases, **kwargs):
        return []

    register("http", stub)
    try:
        assert get_transport("http").build_repro is None, "the hazard is real"
    finally:
        restore(original)

    assert get_transport("http") == original
    assert get_transport("http").build_repro is not None


# --- discovery: not per case, so its own registry ------------------------------


def test_the_mcp_surface_registers_a_discovery_resolver():
    assert "mcp" in discovery.resolver_names()


def test_a_resolver_that_does_not_recognise_the_reference_declines():
    """Returning None means "not mine" and lets the next surface try."""
    provider = AuthProvider(name="p", type="oauth2_client_credentials",
                            discover_from="not-a-server-or-url")

    from overstep.mcp_auth import resolve_discovery

    assert resolve_discovery(_EmptyMatrix(), provider, client=None, verify_tls=True) is None


def test_an_unresolvable_reference_stops_the_run_rather_than_silently_yielding_none():
    """A provider naming something nothing resolves cannot authenticate.

    Falling through to "no token endpoint" would surface much later, as every
    request that subject makes being rejected for reasons nobody can trace.
    """
    provider = AuthProvider(name="p", type="oauth2_client_credentials",
                            discover_from="not-a-server-or-url")

    with pytest.raises(discovery.DiscoveryFailed) as excinfo:
        discovery.resolve(_EmptyMatrix(), provider, client=None, verify_tls=True)

    assert "not-a-server-or-url" in str(excinfo.value)
    assert "mcp" in str(excinfo.value), "the error should name what was asked"


def test_a_resolver_that_recognises_and_fails_is_not_treated_as_declining():
    """The distinction the two outcomes carry.

    A metadata document failing its issuer check is an error to surface, not a
    reason to let another surface guess at the same reference.
    """
    calls = []

    def claims_and_fails(matrix, provider, *, client, verify_tls):
        calls.append("first")
        raise discovery.DiscoveryFailed("issuer mismatch")

    def would_have_answered(matrix, provider, *, client, verify_tls):
        calls.append("second")
        return discovery.Discovered(token_endpoint="http://wrong.test/token")

    saved = dict(discovery._RESOLVERS)
    discovery._RESOLVERS.clear()
    try:
        discovery.register("a", claims_and_fails)
        discovery.register("b", would_have_answered)

        with pytest.raises(discovery.DiscoveryFailed, match="issuer mismatch"):
            discovery.resolve(_EmptyMatrix(), AuthProvider(name="p", discover_from="x"),
                              client=None, verify_tls=True)

        assert calls == ["first"], "a failing resolver must not fall through"
    finally:
        discovery._RESOLVERS.clear()
        discovery._RESOLVERS.update(saved)


class _EmptyMatrix:
    """Just enough matrix for a resolver to decline against."""

    def server_map(self):
        return {}
