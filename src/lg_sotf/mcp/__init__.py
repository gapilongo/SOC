"""Model Context Protocol server (``lg-sotf mcp``): LG-SOTF tools for Claude and other MCP clients.

A small in-house implementation of the MCP stdio transport (JSON-RPC 2.0,
protocol version ``2025-06-18``) without the MCP SDK. The server is a thin
client of the LG-SOTF REST API: every tool is one API call made with the
operator's API key, so authentication, RBAC, tenant isolation and audit are
enforced by the API exactly as for any other client.

Modules:

* :mod:`lg_sotf.mcp.client`: bounded REST client (timeouts, retries for
  reads, no redirects, response size cap);
* :mod:`lg_sotf.mcp.tools`: tool definitions, argument validation and the
  untrusted-data wrapping of results;
* :mod:`lg_sotf.mcp.protocol`: JSON-RPC dispatch of the MCP methods;
* :mod:`lg_sotf.mcp.server`: the newline-delimited stdio loop;
* :mod:`lg_sotf.mcp.command`: the ``lg-sotf mcp`` click command.
"""

from lg_sotf.mcp.protocol import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, McpServer

__all__ = ["PROTOCOL_VERSION", "SUPPORTED_PROTOCOL_VERSIONS", "McpServer"]
