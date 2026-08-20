"""Tests for the safe expression evaluator."""
import pytest

from overstep.expressions import referenced_attributes, safe_eval


def test_equality_and_membership():
    ctx = {"subject": {"tenant": "t1", "roles": ["user"]}, "target": {"tenant": "t1"}}
    assert safe_eval("subject.tenant == target.tenant", ctx) is True
    assert safe_eval("'user' in subject.roles", ctx) is True
    assert safe_eval("'admin' in subject.roles", ctx) is False


def test_boolean_and_comparison_operators():
    ctx = {"subject": {"level": 3}}
    assert safe_eval("subject.level >= 2 and subject.level < 5", ctx) is True
    assert safe_eval("not (subject.level == 1)", ctx) is True


def test_subscript_access():
    ctx = {"subject": {"attrs": {"id": "u1"}}}
    assert safe_eval("subject['attrs']['id'] == 'u1'", ctx) is True


def test_calls_are_rejected():
    with pytest.raises(ValueError):
        safe_eval("__import__('os').system('id')", {})


def test_unknown_name_is_rejected():
    with pytest.raises(ValueError):
        safe_eval("secret == 1", {})


def test_private_and_dunder_attributes_are_rejected():
    """The one traversal that reaches outside the supplied context.

    Nothing in the allow-list can call, so this was never an escape on its own —
    but ``subject.__class__.__init__.__globals__`` hands an expression every
    global of the module that defined the object, and a condition has no reason
    to ask for it.
    """
    ctx = {"subject": {"tenant": "t1"}}
    for expr in (
        "subject.__class__",
        "subject.__init__.__globals__",
        "subject.__class__.__init__.__globals__['__name__'] == 'x'",
    ):
        with pytest.raises(ValueError):
            safe_eval(expr, ctx)


def test_ordinary_attribute_access_still_works():
    ctx = {"subject": {"tenant": "t1", "_internal": "x"}, "target": {"tenant": "t1"}}
    assert safe_eval("subject.tenant == target.tenant", ctx) is True
    # A leading underscore is refused even where a dict really does hold the key.
    with pytest.raises(ValueError):
        safe_eval("subject._internal == 'x'", ctx)


def test_missing_attribute_is_an_error_not_none():
    """The typo that used to grant access.

    Returning ``None`` for an attribute that is not there read a typo as a
    value, and two typos compared equal. `subject.dept == target.dept`, written
    for an attribute really called `department`, was `None == None` — true, so
    the rule granted.
    """
    ctx = {
        "subject": {"user_id": "u1", "department": "eng"},
        "target": {"user_id": "u2", "department": "sales"},
    }
    assert safe_eval("subject.department == target.department", ctx) is False
    with pytest.raises(ValueError, match="unknown attribute"):
        safe_eval("subject.dept == target.dept", ctx)
    # One side missing was already false; it must stay an error, not silently
    # agree with the other side's real value.
    with pytest.raises(ValueError, match="unknown attribute"):
        safe_eval("subject.dept == target.department", ctx)


def test_attribute_holding_none_is_still_a_value():
    """Absent and ``None`` are different, and only one of them is a mistake."""
    ctx = {"subject": {"tier": None}, "target": {"tier": None}}
    assert safe_eval("subject.tier == target.tier", ctx) is True


def test_referenced_attributes_reports_what_a_condition_reads():
    assert referenced_attributes("subject.tenant == target.tenant") == {
        ("subject", "tenant"),
        ("target", "tenant"),
    }
    assert referenced_attributes("subject.tier > 1 and 'x' in subject.tags") == {
        ("subject", "tier"),
        ("subject", "tags"),
    }


def test_and_stops_at_the_operand_that_decides():
    """The idiom this most needs to support: a guard before a dereference.

    `subject.tags and 'x' in subject.tags` is falsy in Python when `tags` is
    None. Evaluating both operands up front raised TypeError on the membership
    test instead, the planner read the error as "this rule grants nothing", and
    an allow the author had written correctly became a denial in silence.
    """
    ctx = {"subject": {"tags": None, "role": "user"}}
    assert safe_eval("subject.tags and 'x' in subject.tags", ctx) is None
    assert safe_eval("subject.role == 'user' or 'x' in subject.tags", ctx) is True


def test_boolean_operators_yield_python_values():
    """Not just truthiness: `and`/`or` return the deciding operand."""
    ctx = {"subject": {"tags": [], "role": "user", "tier": 3}}
    assert safe_eval("subject.tags or subject.role", ctx) == "user"
    assert safe_eval("subject.role and subject.tier", ctx) == 3
    assert safe_eval("subject.tags and subject.tier", ctx) == []


def test_short_circuit_chains_beyond_two_operands():
    ctx = {"subject": {"a": False, "role": "user"}}
    # The third operand would raise if it were reached.
    assert safe_eval("subject.a and subject.role and 'x' in subject.a", ctx) is False


def test_short_circuiting_does_not_hide_a_typo_from_validate():
    """The negative half, and the reason this is safe to do at all.

    Skipping an operand at runtime must not skip it at check time. `validate`
    reads a condition statically, so an attribute nobody declares is still
    reported even when the operand naming it would never be evaluated — which is
    what keeps `or` from quietly granting on a rule whose second half is wrong.
    """
    from overstep.matrix import Matrix

    m = Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user"],
        subjects=[{"name": "alice", "role": "user", "attributes": {"department": "eng"}}],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={
            "r": {
                "allow": [
                    # The left operand is true for alice, so the right is never
                    # evaluated — and `dept` is still a typo for `department`.
                    {"role": "user", "condition": "subject.department == 'eng' or subject.dept == 'x'"}
                ]
            }
        },
    )
    problems = m.validate_refs()
    assert any("subject.dept" in p and "no subject declares" in p for p in problems)


def test_referenced_attributes_sees_past_a_short_circuit():
    """The static reader must not inherit the evaluator's laziness."""
    assert referenced_attributes("subject.a or subject.b") == {
        ("subject", "a"),
        ("subject", "b"),
    }
