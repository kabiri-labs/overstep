"""Tests for the safe expression evaluator."""
import pytest

from overstep.expressions import safe_eval


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
