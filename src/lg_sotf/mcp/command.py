"""``lg-sotf mcp``: run the MCP server on stdin/stdout for Claude Desktop, Claude Code or another MCP client."""

from __future__ import annotations

import asyncio
import sys

import click

from lg_sotf.mcp.client import ApiConfigError, LgSotfApiClient
from lg_sotf.mcp.protocol import McpServer
from lg_sotf.mcp.server import run_stdio
from lg_sotf.settings import Settings, get_settings


async def _main(settings: Settings, api_key: str) -> None:
    cfg = settings.mcp
    api = LgSotfApiClient(
        cfg.api_url,
        api_key,
        timeout_s=cfg.timeout_s,
        max_retries=cfg.max_retries,
        max_response_bytes=cfg.max_response_bytes,
    )
    try:
        await run_stdio(McpServer(api, max_output_chars=cfg.max_output_chars))
    finally:
        await api.aclose()


@click.command("mcp")
def mcp_command() -> None:
    """Run the Model Context Protocol server over stdio.

    A thin client of the LG-SOTF REST API: set LG_SOTF_MCP__API_URL (the API's
    base URL; https, or http for localhost) and LG_SOTF_MCP__API_KEY (an API
    key with the 'read' scope, plus 'write' for add_note) in the environment
    of the MCP client's server entry. The key is never accepted as an argument.
    Logs go to stderr; stdout carries protocol messages only.
    """
    from lg_sotf.observability.logging import configure_logging

    settings = get_settings()
    configure_logging(settings, stream=sys.stderr)
    key = settings.mcp.api_key.get_secret_value() if settings.mcp.api_key is not None else ""
    if not key.strip():
        click.echo("Error: LG_SOTF_MCP__API_KEY is not set (an LG-SOTF API key with the 'read' scope).", err=True)
        sys.exit(2)
    try:
        asyncio.run(_main(settings, key))
    except ApiConfigError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except KeyboardInterrupt:
        pass


__all__ = ["mcp_command"]
