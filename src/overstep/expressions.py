"""A tiny, safe expression evaluator for custom allow conditions.

Conditions in the matrix (e.g. ``subject.tenant == target.tenant``) are handy for
things like tenant isolation, but running ``eval`` on user-supplied strings is a
non-starter for a security tool. This module walks the AST and only permits a
small allow-list of read-only nodes: comparisons, boolean logic, attribute/index
access and literals. No calls, no names outside the supplied context, no
mutation.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, Set, Tuple

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load,
    ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.And, ast.Or, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Attribute, ast.Subscript,
}


def _member(obj: Any, name: str) -> Any:
    """Attribute access that also works on plain dicts (subject.tenant).

    Private and dunder names are refused. A condition describes identities and
    objects, so it has no business reading ``__class__`` — and that one step
    leads to ``__init__.__globals__`` and every module global behind it. Nothing
    is callable here, so this is not an escape today; it is the gap that would
    become one the moment another node type is allowed, and closing it costs a
    condition nobody would write on purpose.

    An attribute that is not there is an error, not ``None``. Returning ``None``
    read a typo as a value, and two of them compared equal: ``subject.dept ==
    target.dept``, written for an attribute really called ``department``, is
    ``None == None`` — true, so the rule granted access, the negative test it
    should have produced became a positive one, and a real broken endpoint was
    never probed. Failing instead lets the caller decide, and every caller here
    decides *deny*.
    """
    if name.startswith("_"):
        raise ValueError(f"private attribute not allowed in expression: {name}")
    if isinstance(obj, dict):
        if name not in obj:
            raise ValueError(f"unknown attribute in expression: {name}")
        return obj[name]
    try:
        return getattr(obj, name)
    except AttributeError:
        raise ValueError(f"unknown attribute in expression: {name}") from None


def _eval(node: ast.AST, names: Dict[str, Any]) -> Any:
    if type(node) not in _ALLOWED_NODES:
        raise ValueError(f"expression node not allowed: {type(node).__name__}")

    if isinstance(node, ast.Expression):
        return _eval(node.body, names)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise ValueError(f"unknown name in expression: {node.id}")
        return names[node.id]
    if isinstance(node, ast.Attribute):
        return _member(_eval(node.value, names), node.attr)
    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Slice):
            raise ValueError("slices are not allowed")
        return _eval(node.value, names)[_eval(node.slice, names)]
    if isinstance(node, ast.List):
        return [_eval(e, names) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, names) for e in node.elts)
    if isinstance(node, ast.Dict):
        return {_eval(k, names): _eval(v, names) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval(node.operand, names)
    if isinstance(node, ast.BoolOp):
        values = [_eval(v, names) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        return any(values)
    if isinstance(node, ast.Compare):
        left = _eval(node.left, names)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, names)
            if not _compare(op, left, right):
                return False
            left = right
        return True
    raise ValueError("unsupported expression")


def _compare(op: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    raise ValueError(f"comparison not allowed: {type(op).__name__}")


def referenced_attributes(expr: str) -> Set[Tuple[str, str]]:
    """Every ``(root, attribute)`` pair the expression reads.

    ``subject.tenant == target.tenant`` yields ``{("subject", "tenant"),
    ("target", "tenant")}``. This is what lets a matrix be checked before it is
    run: a condition naming an attribute no subject declares is a typo, and the
    only alternative to reporting it is discovering it as a wrong verdict.

    Raises ``SyntaxError`` if the expression does not parse.
    """
    found: Set[Tuple[str, str]] = set()
    for node in ast.walk(ast.parse(expr, mode="eval")):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            found.add((node.value.id, node.attr))
    return found


def safe_eval(expr: str, names: Dict[str, Any]) -> Any:
    """Evaluate ``expr`` against ``names`` using only the allow-listed nodes."""
    return _eval(ast.parse(expr, mode="eval"), names)
