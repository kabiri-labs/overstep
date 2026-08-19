"""The MCP surface: tools and resource URIs over JSON-RPC.

Streamable HTTP and stdio are two ways in; the protocol's own authorization
rules — credential audience, session binding — are checked here rather than in
the core, because they are requirements the specification places on an MCP
server and mean nothing to any other surface.
"""
