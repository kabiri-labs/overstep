"""The surfaces overstep tests, one package each.

Authorization is one problem class; REST and MCP are two places it shows up.
Everything either of them knows privately — how a request is delivered, how a
response is read as allow or deny, how a finding is rendered as something you
can re-run — lives under its own name here.

They used to sit differently: MCP had a consistent `mcp_` prefix while REST
occupied the package root unmarked, so the file listing said one was the tool
and the other an addition. Neither is at the root now.

What stays outside is the core: the matrix, the planner, ownership, the
classifier, drift, waivers, coverage and the reporters. A module may depend on
the core; the core may not depend on a module, and neither module may depend on
the other. `tests/test_module_boundary.py` measures both.
"""
