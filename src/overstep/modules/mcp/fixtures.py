"""Running one setup or teardown step as an MCP tool-call.

A step creates the object a later BOLA probe reaches for, and it is delivered
over whichever surface the step declares. `overstep.fixtures` sequences the
steps, renders their templates and collects the captures — all of which is the
same whatever carried the request — but it also knew how to make a tool-call,
which is not.

That is the surface's question, so the surface answers it: the MCP transport
registers this as its `run_step`, and `fixtures` asks the registry.
"""
from __future__ import annotations

from overstep.modules.mcp.client import mcp_tool_call
from overstep.modules.mcp.matching import content_text
from overstep.templating import render


def run_step(matrix, step, subject, context, label, *, verify_tls: bool, error_cls) -> str:
    """Run an MCP setup/teardown tool-call and return its result content text.

    Raises SetupError on an unknown server, a JSON-RPC error or an isError result.
    """
    server = matrix.server_map().get(step.call.server)
    if server is None:
        raise error_cls(f"setup step '{label}' references unknown server '{step.call.server}'")
    arguments = render(dict(step.call.arguments), context)
    message = mcp_tool_call(server, subject, step.call.tool, arguments, verify_tls=verify_tls)
    error = message.get("error") if isinstance(message, dict) else None
    result = message.get("result") if isinstance(message, dict) else None
    result = result if isinstance(result, dict) else {}
    if error is not None:
        raise error_cls(f"setup step '{label}' errored: {error.get('message')}")
    if result.get("isError"):
        raise error_cls(f"setup step '{label}' returned an error result")
    return content_text(result.get("content"))


