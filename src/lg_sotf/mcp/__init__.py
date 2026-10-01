"""Model Context Protocol server (``lg-sotf mcp``): LG-SOTF tools for Claude and other MCP clients.

A small in-house implementation of the MCP stdio transport (JSON-RPC 2.0,
protocol version ``2025-06-18``) without the MCP SDK. The server is a thin
client of the LG-SOTF REST API: every tool makes one or a few API calls with the
operator's API key, so authentication, RBAC, tenant isolation and audit are
enforced by the API exactly as for any other client.

No tool approves, rejects, rolls back or retries an action, decides an
escalation or changes configuration: those routes refuse API keys.

Modules:

* :mod:`lg_sotf.mcp.client`: bounded REST client (timeouts, retries for
  reads, no redirects, response size cap);
* :mod:`lg_sotf.mcp.base`: the tool record, argument models and call context;
* :mod:`lg_sotf.mcp.tools`: the tool catalog, argument validation and result
  wrapping;
* :mod:`lg_sotf.mcp.tester`: the verdict, action and tester tools (whoami,
  get_verdict, list_actions, get_action, ingest_test_alerts,
  wait_for_verdict, get_test_run);
* :mod:`lg_sotf.mcp.runs`: test runs kept in memory, outcomes and agreement;
* :mod:`lg_sotf.mcp.shaping`: invisible-character stripping, untrusted-data
  sanitizing and fencing, and size budgets;
* :mod:`lg_sotf.mcp.protocol`: JSON-RPC dispatch of the MCP methods;
* :mod:`lg_sotf.mcp.server`: the newline-delimited stdio loop;
* :mod:`lg_sotf.mcp.command`: the ``lg-sotf mcp`` click command.
"""

from lg_sotf.mcp.protocol import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, McpServer

__all__ = ["PROTOCOL_VERSION", "SUPPORTED_PROTOCOL_VERSIONS", "McpServer"]
