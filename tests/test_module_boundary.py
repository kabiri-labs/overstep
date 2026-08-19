"""Which modules may import which, measured rather than asserted in prose.

The README says overstep is one shared core with two peer modules over it, and
that delivery is the only seam between them. That claim was never checked, and
when first measured it was not true: `models`, `planner`, `auth`, `fixtures` and
`repro` all imported MCP internals, `preflight` reached into the REST executor
for a constant, and the MCP matcher imported the REST matcher to read its own
`deny_status`.

None of that is visible from a file listing, which is why it survived. This
module computes the real import graph and holds it to two rules:

* **no core module may import a module's internals** — the direction that makes
  "shared core" a description rather than a wish;
* **neither surface may import the other** — the direction that makes them peers.

`SCHEMA_COMPOSITION` is the exception, and at 1.0.0 it is a decision rather than
a backlog. Every edge that was core *logic* reaching into a surface is gone —
eight were measured, six were given seams and two were misplaced primitives.
What is left is core *schema* composing a surface's schema, which is what a
typed plugin configuration looks like: `Matrix.modules.mcp` is an `McpModule`,
`TestCase.mcp` an `McpInvocation`.

Removing those would mean making the module blocks opaque to the core — a dict
each surface parses — which costs validation and typing at the one place a
matrix is checked, to buy a tidier graph. That trade was considered and declined.
The set is asserted exactly, in both directions, so the exception cannot grow and
cannot be quietly left behind if it is ever closed.

Which modules belong to which surface is read off the package layout rather than
listed here, so the rule and the tree cannot disagree.
"""
import ast
import os

import pytest

SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "overstep"
)

def _surface_modules(surface: str) -> set:
    """Every module under one surface's package, read off the tree.

    Derived rather than listed. The first version of this file carried two
    literal sets, because the packages did not exist yet and there was no other
    way to say which module belonged to whom — which made the boundary itself
    something that could silently drift from the layout it described. Now a file
    is a surface's the moment it is placed there.
    """
    root = os.path.join(SRC, "modules", surface)
    return {
        f"modules.{surface}." + os.path.splitext(name)[0]
        for name in os.listdir(root)
        if name.endswith(".py") and name != "__init__.py"
    }


REST_MODULES = _surface_modules("rest")
MCP_MODULES = _surface_modules("mcp")
MODULE_OWNED = REST_MODULES | MCP_MODULES

# The entry point wires everything together on purpose; it is not core logic.
EXEMPT = {"cli", "__main__", ""}

# The two edges the 1.0.0 surface keeps on purpose. `models` and `planner` read
# `DEFAULT_PROTOCOL_VERSION` because the MCP models they compose default with it.
SCHEMA_COMPOSITION = {
    ("models", "modules.mcp.protocol"),
    ("planner", "modules.mcp.protocol"),
}


def _module_name(path: str) -> str:
    rel = os.path.relpath(path, SRC)[: -len(".py")].replace(os.sep, ".")
    return rel[: -len(".__init__")] if rel.endswith("__init__") else rel


def _imports(path: str) -> set:
    """Every `overstep.*` module this file imports, by short name."""
    tree = ast.parse(open(path, "r", encoding="utf-8").read())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            continue
        for name in names:
            if name == "overstep" or not name.startswith("overstep."):
                continue
            found.add(name[len("overstep.") :])
    return found


def _graph() -> dict:
    graph = {}
    for root, _, files in os.walk(SRC):
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            graph[_module_name(path)] = _imports(path)
    return graph


def _core_to_module_edges() -> set:
    return {
        (importer, imported)
        for importer, imports in _graph().items()
        if importer not in MODULE_OWNED and importer not in EXEMPT
        for imported in imports
        if imported in MODULE_OWNED
    }


def test_the_graph_is_actually_being_read():
    """A parser that silently found nothing would pass every check below."""
    graph = _graph()

    assert len(graph) > 20, f"only {len(graph)} modules found; the walk is wrong"
    assert "modules.mcp.protocol" in graph["models"], "the import parser missed a known edge"


def test_no_core_module_imports_a_surface_beyond_the_schema_exception():
    """The rule that makes "shared core" a description rather than a wish."""
    new = _core_to_module_edges() - SCHEMA_COMPOSITION

    assert not new, (
        "core modules gained a dependency on a surface module: "
        + ", ".join(f"{a} -> {b}" for a, b in sorted(new))
    )


def test_the_schema_exception_is_exactly_what_it_claims():
    """Asserted in both directions, so the exception can neither grow nor rot.

    An entry that no longer holds is as much a problem as one that should not be
    there: it would mean the list describes a shape the code left behind, and
    nobody reading it could tell which entries were still real.
    """
    stale = SCHEMA_COMPOSITION - _core_to_module_edges()

    assert not stale, (
        "these no longer exist and must be removed from SCHEMA_COMPOSITION: "
        + ", ".join(f"{a} -> {b}" for a, b in sorted(stale))
    )


@pytest.mark.parametrize("surface,other", [("rest", MCP_MODULES), ("mcp", REST_MODULES)])
def test_neither_surface_imports_the_other(surface, other):
    """Peers, not a base and an extension.

    The MCP matcher used to import the REST matcher to read its own
    `deny_status`, which is the shape this forbids: a dependency between two
    things that are supposed to be alternatives.
    """
    mine = REST_MODULES if surface == "rest" else MCP_MODULES
    graph = _graph()

    crossings = {
        (importer, imported)
        for importer in mine
        for imported in graph.get(importer, set())
        if imported in other
    }

    assert not crossings, (
        f"the {surface} module imports the other surface: "
        + ", ".join(f"{a} -> {b}" for a, b in sorted(crossings))
    )


def test_both_surfaces_read_a_status_specification_from_the_same_place():
    """The concrete fix behind the rule above, pinned so it cannot regress.

    `allow_status` and `deny_status` accept the same three spellings because they
    describe the same thing. Sharing the parser is right; sharing it by importing
    the other surface's module was not.
    """
    from overstep import statuses
    from overstep.modules.mcp import matching as mcp_matching
    from overstep.modules.rest import matching as rest_matching

    assert rest_matching.status_matches is statuses.status_matches
    assert mcp_matching.status_matches is statuses.status_matches
    assert statuses.status_matches(["2xx"], 204)
    assert statuses.status_matches(["200-299"], 201)
    assert not statuses.status_matches([200], 404)


def test_read_only_asks_the_case_rather_than_a_module_constant():
    """One question, asked of the case, answered for either surface.

    Two modules answered it two ways and a core module imported the REST
    executor's constant to ask it a third time. That import is gone because the
    question moved to where both surfaces can answer it.
    """
    from overstep.models import Effect, McpInvocation, ResourceType, TestCase, Variant

    def case(**fields):
        return TestCase(
            id="t", resource="r", subject="s", role="user",
            path_template="/x", path="/x", variant=Variant.NA,
            expected=Effect.DENY, resource_type=ResourceType.FUNCTION, **fields,
        )

    assert case(method="DELETE").is_mutating
    assert case(method="post").is_mutating          # the verb is normalised
    assert not case(method="GET").is_mutating

    # MCP has no verb, so the invocation carries the answer instead.
    assert case(
        method="tools/call", transport="mcp",
        mcp=McpInvocation(url="http://x/mcp", tool="reset", mutating=True),
    ).is_mutating
    assert not case(
        method="tools/call", transport="mcp",
        mcp=McpInvocation(url="http://x/mcp", tool="read", mutating=False),
    ).is_mutating
