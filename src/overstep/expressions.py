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
from typing import Any, Dict, Optional, Set, Tuple

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
        # Python's `and`/`or` stop at the operand that decides the answer, and
        # yield that operand rather than a bool. Evaluating all of them up front
        # broke the one idiom that most wants writing — a condition guarding its
        # own dereference. `subject.tags and 'x' in subject.tags` is falsy in
        # Python when `tags` is None; here it raised TypeError on the membership
        # test, the planner read the error as "this rule grants nothing", and an
        # allow the author had written correctly became a denial in silence.
        result = _eval(node.values[0], names)
        for operand in node.values[1:]:
            if isinstance(node.op, ast.And):
                if not result:
                    return result
            elif result:
                return result
            result = _eval(operand, names)
        return result
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


# The only roots a condition can read. Anything else is a name the evaluator has
# nothing to bind, so naming one is a mistake rather than a narrowing.
CONTEXT_ROOTS = ("subject", "target")


def refusal_reason(expr: str) -> Optional[str]:
    """Why the evaluator would refuse ``expr``, or ``None`` if it would not.

    Validation and evaluation have to agree about what a condition may contain,
    and the only way to guarantee that is to ask the same code. Reimplementing
    the rules here would let the two drift, and the drift is silent in the worst
    direction: ``_expected_effect`` reads a refusal as "this rule grants
    nothing", so a condition ``validate`` called fine turns a rule the author
    meant to grant into one that denies, and the positive test it should have
    produced into a negative one.

    Everything except the *values* is decidable without running anything — the
    node types, the private names, the roots — so all of it is answered here.
    Whether a particular subject actually carries an attribute is not, and stays
    with the caller that knows the subjects.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        return f"does not parse ({exc.msg})"
    except RecursionError:
        # Deep enough nesting exhausts the stack inside the parser itself. It is
        # a refusal like any other, and reporting it beats letting it escape as
        # a traceback from whatever asked.
        return "is nested too deeply to parse"

    try:
        _check(tree, {root: {} for root in CONTEXT_ROOTS})
    except ValueError as exc:
        return str(exc)
    except RecursionError:
        return "is nested too deeply to evaluate"
    return None


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


def _check(tree: ast.AST, names: Dict[str, Any]) -> None:
    """Reject anything the evaluator may not run, anywhere in the expression.

    Legality is a property of the expression, not of the path taken through it.
    While every operand was evaluated that distinction did not exist — checking
    each node as it was reached amounted to checking all of them. Once ``and``
    and ``or`` stop early it does exist, and an unreached branch would never be
    checked at all: ``True or __import__('os')`` would answer ``True``, and in
    the planner a condition that used to raise and deny would grant.

    So the whole tree is checked first and evaluation stays lazy. Names and
    private attributes are checked here too, for the same reason and by the same
    argument: ``True or secret`` and ``True or subject.__class__`` are refusals
    that must not depend on which half runs.
    """
    for node in ast.walk(tree):
        if type(node) not in _ALLOWED_NODES:
            raise ValueError(f"expression node not allowed: {type(node).__name__}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise ValueError(
                f"private attribute not allowed in expression: {node.attr}"
            )
        if isinstance(node, ast.Name) and node.id not in names:
            raise ValueError(f"unknown name in expression: {node.id}")


def safe_eval(expr: str, names: Dict[str, Any]) -> Any:
    """Evaluate ``expr`` against ``names`` using only the allow-listed nodes.

    The expression is checked in full before any of it is evaluated, so what it
    is allowed to contain does not depend on which branch a short-circuiting
    operator takes.
    """
    tree = ast.parse(expr, mode="eval")
    _check(tree, names)
    return _eval(tree, names)
