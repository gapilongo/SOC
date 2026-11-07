"""``lg-sotf mcp``: run the MCP server on stdin/stdout for Claude Desktop, Claude Code or another MCP client."""

from __future__ import annotations

import asyncio
import os
import stat
import sys

import click

from lg_sotf.mcp.client import ApiConfigError, LgSotfApiClient
from lg_sotf.mcp.protocol import McpServer
from lg_sotf.mcp.server import run_stdio
from lg_sotf.security.redaction import redact_text
from lg_sotf.settings import Settings

KEY_FILE_VARIABLE = "LG_SOTF_MCP__API_KEY_FILE"
MAX_KEY_FILE_BYTES = 4_096


def read_api_key_file(path: str) -> str:
    """The API key stored in ``path``.

    Refused (:class:`ApiConfigError`): a ``path`` that is itself an API key
    (refused without echoing it, since every other message names the path),
    a missing or unreadable file, anything but a regular file, a file larger
    than :data:`MAX_KEY_FILE_BYTES`, an empty file, one holding more than one
    token or a character no key has (a leading UTF-8 byte order mark is
    dropped), and, on POSIX systems, a file its group or other users can read
    or write (``chmod 600`` it). The checks run on the opened file
    descriptor, so the file cannot be swapped between the check and the
    read. The key itself never appears in an error.
    """
    name = KEY_FILE_VARIABLE
    value = path.strip()
    if not value:
        raise ApiConfigError(f"{name} is empty")
    # The two variables are easy to mix up. These errors reach the MCP client's log (Claude Desktop's
    # mcp-server-*.log, Claude Code's /mcp), which a model asked to debug the failed start can read.
    if redact_text(value)[1]:
        raise ApiConfigError(
            f"{name} holds an API key, not a file path; save the key to a file and set {name} to its path"
        )
    expanded = os.path.expanduser(value)
    shown = redact_text(expanded)[0]
    flags = os.O_RDONLY | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(expanded, flags)
    except FileNotFoundError as exc:
        raise ApiConfigError(f"{name}: {shown} does not exist") from exc
    except PermissionError as exc:
        raise ApiConfigError(f"{name}: {shown} cannot be read (permission denied)") from exc
    except OSError as exc:
        raise ApiConfigError(f"{name}: {shown} cannot be read ({type(exc).__name__})") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ApiConfigError(f"{name}: {shown} is not a regular file")
        # Readable: they could take the key. Writable: they could swap in a key of their own tenant, so the
        # notes and test alerts written here would land there and every alert the model reads would be theirs.
        if os.name != "nt" and info.st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            raise ApiConfigError(
                f"{name}: {shown} is readable or writable by its group or by other users; "
                f"run: chmod 600 {shown}"
            )
        if info.st_size > MAX_KEY_FILE_BYTES:
            raise ApiConfigError(f"{name}: {shown} is larger than {MAX_KEY_FILE_BYTES} bytes")
        raw = b""
        while len(raw) <= MAX_KEY_FILE_BYTES:
            chunk = os.read(fd, MAX_KEY_FILE_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if len(raw) > MAX_KEY_FILE_BYTES:
        raise ApiConfigError(f"{name}: {shown} is larger than {MAX_KEY_FILE_BYTES} bytes")
    try:
        # utf-8-sig: a leading byte order mark (PowerShell 5.1 "-Encoding UTF8", Notepad "UTF-8 with BOM") is dropped.
        key = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise ApiConfigError(f"{name}: {shown} is not UTF-8 text") from exc
    if not key:
        raise ApiConfigError(f"{name}: {shown} is empty")
    if any(c.isspace() for c in key):
        raise ApiConfigError(f"{name}: {shown} must contain the API key only")
    if not all(c.isascii() and c.isprintable() for c in key):
        raise ApiConfigError(
            f"{name}: {shown} holds characters an API key never has (invisible, control or non-ASCII); "
            "save the key alone as plain text"
        )
    return key


def resolve_api_key(settings: Settings) -> str:
    """The key from ``LG_SOTF_MCP__API_KEY`` or ``LG_SOTF_MCP__API_KEY_FILE`` (setting both is refused)."""
    cfg = settings.mcp
    from_env = cfg.api_key.get_secret_value() if cfg.api_key is not None else ""
    key_file = (cfg.api_key_file or "").strip()
    if from_env.strip() and key_file:
        raise ApiConfigError(f"set LG_SOTF_MCP__API_KEY or {KEY_FILE_VARIABLE}, not both")
    if key_file:
        return read_api_key_file(key_file)
    if not from_env.strip():
        raise ApiConfigError(
            "LG_SOTF_MCP__API_KEY is not set (an LG-SOTF API key with the 'read' scope); "
            f"or set {KEY_FILE_VARIABLE} to a file that holds it"
        )
    return from_env


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


def run_mcp(settings: Settings) -> None:
    """Run the Model Context Protocol server over stdio (``lg-sotf mcp``).

    A thin client of the LG-SOTF REST API, configured by ``settings.mcp``: the
    API's base URL and either an API key or a key file. Logs go to stderr;
    stdout carries protocol messages only. Configuration errors exit with
    status 2.
    """
    from lg_sotf.observability.logging import configure_logging

    configure_logging(settings, stream=sys.stderr)
    try:
        key = resolve_api_key(settings)
    except ApiConfigError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    try:
        asyncio.run(_main(settings, key))
    except ApiConfigError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except KeyboardInterrupt:
        pass


__all__ = ["read_api_key_file", "resolve_api_key", "run_mcp"]
