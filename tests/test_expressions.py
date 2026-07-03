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
