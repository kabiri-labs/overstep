"""Tests for the safe expression evaluator."""
import pytest

from overstep.expressions import MAX_DEPTH, referenced_attributes, safe_eval


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


def test_a_skipped_branch_is_still_checked():
    """Legality is a property of the expression, not of the path taken.

    While every operand was evaluated the distinction did not exist. Once `and`
    and `or` stop early it does, and checking each node as it is reached would
    leave an unreached branch unchecked — so `True or __import__('os')` would
    answer True, and in the planner a condition that used to raise and deny
    would grant. The whole tree is checked before any of it runs.
    """
    with pytest.raises(ValueError, match="not allowed"):
        safe_eval("True or __import__('os')", {})
    with pytest.raises(ValueError, match="not allowed"):
        safe_eval("False and __import__('os')", {})


def test_a_skipped_branch_cannot_smuggle_a_private_attribute():
    ctx = {"subject": {"role": "user"}}
    with pytest.raises(ValueError, match="private attribute"):
        safe_eval("True or subject.__class__", ctx)


def test_a_skipped_branch_cannot_smuggle_an_unknown_name():
    with pytest.raises(ValueError, match="unknown name"):
        safe_eval("True or secret", {})


def test_slices_are_still_refused():
    ctx = {"subject": {"tags": [1, 2, 3]}}
    with pytest.raises(ValueError):
        safe_eval("subject.tags[0:2] == [1, 2]", ctx)


def test_refusal_reason_answers_for_the_evaluator():
    """One function decides what a condition may contain, for both callers."""
    from overstep.expressions import refusal_reason

    assert refusal_reason("subject.tenant == target.tenant") is None
    assert refusal_reason("'x' in subject.tags") is None
    assert "BinOp" in refusal_reason("subject.a + 1 > 2")
    assert "unknown name" in refusal_reason("request == 1")
    assert "private attribute" in refusal_reason("subject.__class__ == 1")
    assert "does not parse" in refusal_reason("subject.a ==")


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, 3000, 10000])
def test_a_deep_expression_is_refused_the_same_way_on_every_version(depth):
    """Pin the limit, not the interpreter's breaking point.

    How much nesting a parser tolerates, and whether it gives up with
    RecursionError or MemoryError, differs by version: 3.11 abandons 3000 nested
    operators where 3.10, 3.12 and 3.13 parse them and leave the evaluator to
    blow its own stack. An earlier version of this test pinned a depth that only
    3.11 refused, passed locally, and failed CI on 3.12. The depth is decided
    here now, so the answer is the same everywhere.
    """
    from overstep.expressions import refusal_reason

    reason = refusal_reason("not " * depth + "subject.a")
    assert reason is not None and "nests deeper than" in reason


def test_safe_eval_refuses_a_deep_expression_rather_than_raising_recursion():
    """The refusal has to be a ValueError like every other, on every version."""
    ctx = {"subject": {"a": 1}}
    with pytest.raises(ValueError, match="nests deeper than"):
        safe_eval("not " * 3000 + "subject.a", ctx)


def test_the_depth_limit_leaves_real_conditions_alone():
    """Nothing a policy would write comes near the limit."""
    from overstep.expressions import _depth
    import ast

    for expr in (
        "subject.tenant == target.tenant",
        "subject.tenant == target.tenant and subject.tier >= 2 and 'x' in subject.tags",
        "not (subject.a == target.a) or subject.b == target.b",
    ):
        assert _depth(ast.parse(expr, mode="eval")) < MAX_DEPTH // 2


def test_refusal_reason_agrees_with_safe_eval():
    """The property that makes delegating worth it: no expression is refused by
    one and accepted by the other."""
    from overstep.expressions import refusal_reason

    ctx = {"subject": {"a": 1, "tags": [1]}, "target": {"a": 2}}
    for expr in (
        "subject.a == target.a",
        "subject.a + 1 > 2",
        "request == 1",
        "subject.__class__ == 1",
        "[x for x in subject.tags]",
        "subject.a if subject.a else 0",
        "'x' in subject.tags",
    ):
        refused = refusal_reason(expr) is not None
        try:
            safe_eval(expr, ctx)
            evaluated = True
        except ValueError:
            evaluated = False
        assert refused != evaluated, expr
