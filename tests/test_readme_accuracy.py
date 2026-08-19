"""Claims the README makes about the tool's own guarantees, checked against it.

`test_readme_contract.py` pins the README's *structure* — the command reference,
the marker vocabulary. This pins two claims about behaviour that a reader would
act on, both of which the README got wrong at 0.37.1 and both of which were found
in review rather than by the suite:

* the maturity table says a capability is implemented, which now means the test
  suite exercises it. Nothing checked that;
* the inconclusive-run section describes when a clean result is trustworthy. The
  rewrite dropped the one case where it is not, which is the fail-open direction.

A documentation bug in either place is not cosmetic. The first oversells the
evidence behind a security claim; the second tells somebody their CI gate catches
an expired credential when, for their matrix, it does not.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as handle:
        return handle.read()


def _test_sources() -> str:
    """Every test module's source, concatenated. Excludes this one."""
    parts = []
    for name in sorted(os.listdir(TESTS)):
        if not name.endswith(".py") or name == os.path.basename(__file__):
            continue
        with open(os.path.join(TESTS, name), "r", encoding="utf-8") as handle:
            parts.append(handle.read())
    return "\n".join(parts)


# Each capability the maturity table marks implemented, and the identifier that
# proves a test reaches it. A row without a way to check it does not belong in
# the table.
IMPLEMENTED_CAPABILITIES = {
    "object-level (BOLA) probes": "VulnClass.BOLA",
    "function-level (BFLA) probes": "VulnClass.BFLA",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "property-level (BOPLA) forbidden fields": "forbidden_fields",
    "multi-tenancy via policy conditions": "condition",
    "ownership injections": "injections",
    "cross-method probing": "probe_methods",
    "credential audience probe": "token_audience",
    "session-binding probe": "session_binding",
    "tool-enumeration probe": "tool_enumeration",
    "stdio transport": "stdio",
    "OAuth discovery": "discover_from",
}


@pytest.mark.parametrize("capability,marker", sorted(IMPLEMENTED_CAPABILITIES.items()))
def test_each_implemented_capability_is_exercised_by_the_suite(capability, marker):
    """"Implemented" has to mean something a reader can verify.

    The definition used to say "covered by the test suite *and* exercised by a
    bundled demo". No bundled matrix declares `forbidden_fields`, a policy
    `condition`, `probe_methods`, `token_audience` or an `auth` provider, so five
    rows claimed evidence that did not exist. The definition now claims test
    coverage, and this is what holds it to that.
    """
    assert marker in _test_sources(), (
        f"'{capability}' is marked implemented but no test mentions {marker!r}"
    )


def test_the_maturity_scale_claims_only_test_coverage():
    """The definition itself, pinned to what the tests can actually back up.

    Restoring "exercised by a bundled demo" would silently reinstate the
    overclaim, because the parametrized check above cannot see a demo matrix.
    """
    text = _read("README.md")
    match = re.search(r"(?m)^Conservative markers: (.+?)(?=\n\n)", text, re.DOTALL)
    assert match, "the README no longer defines its maturity scale"

    definition = " ".join(match.group(1).split())

    assert "exercised by the test suite" in definition
    assert "bundled demo" not in definition, (
        "the scale claims demo coverage again; either add the capabilities to a "
        "demo matrix or keep the claim to what the suite proves"
    )


def test_the_readme_states_the_all_negative_fail_open_case():
    """The one case where a clean run does not mean the credentials worked.

    `health.assess` only reaches the credential check when the matrix has
    expected-allow cases, so an all-negative suite whose every credential is
    rejected reports conclusive and clean. That is defensible behaviour — an
    intentionally all-negative matrix has no positive control to lose — but a
    reader who is not told will believe their gate catches an expired token.
    """
    text = _read("README.md")

    assert "all-negative" in text, "the README does not mention the all-negative case"
    assert "positive control" in text
    assert "conclusive and clean" in text, (
        "the README describes the caveat without saying what the run actually reports"
    )


def test_the_all_negative_case_behaves_as_the_readme_now_says():
    """And the claim is checked against the code, not just present in prose.

    Without this, the README and `health.assess` could drift apart again in
    either direction and the paragraph above would still pass.
    """
    from overstep.health import assess
    from overstep.models import Effect, Observation, ResourceType, TestCase, Variant

    def case(case_id):
        return TestCase(
            id=case_id, resource="r", subject="s", role="user", method="GET",
            path_template="/x", path="/x", variant=Variant.NA,
            expected=Effect.DENY, resource_type=ResourceType.FUNCTION, transport="http",
        )

    # Every case negative, and the target rejected every credential it was given.
    cases = [case("a"), case("b")]
    observations = [Observation(test_id=c.id, status=401, effect=Effect.DENY) for c in cases]

    health = assess(cases, observations)

    assert not any(c.is_positive_control for c in cases)
    assert not health.inconclusive, (
        "an all-negative matrix is now condemned; the README says it is not"
    )
    assert health.reasons == []


def test_one_positive_control_is_what_restores_the_credential_check():
    """The fix the README tells the reader to apply has to actually work."""
    from overstep.health import assess
    from overstep.models import Effect, Observation, ResourceType, TestCase, Variant

    def case(case_id, expected):
        return TestCase(
            id=case_id, resource="r", subject="s", role="user", method="GET",
            path_template="/x", path="/x", variant=Variant.NA,
            expected=expected, resource_type=ResourceType.FUNCTION, transport="http",
        )

    cases = [case("a", Effect.DENY), case("control", Effect.ALLOW)]
    # The same target, still rejecting everything — including the control.
    observations = [Observation(test_id=c.id, status=401, effect=Effect.DENY) for c in cases]

    health = assess(cases, observations)

    assert health.inconclusive
    assert any("expected-allow" in reason for reason in health.reasons)
