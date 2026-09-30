"""MCP stdio transport: newline-delimited JSON-RPC messages on stdin/stdout.

Each message is one line of UTF-8 JSON. Lines longer than
:data:`MAX_LINE_BYTES` are discarded (up to their newline) and answered
with a parse error, so a runaway client cannot make the server buffer
without bound. Requests are handled concurrently (at most
:data:`MAX_CONCURRENT_REQUESTS` at once, so a slow API call does not delay a
``ping``); responses are written whole, one per line, under a lock. Nothing
but protocol messages is ever written to stdout: logs go to stderr.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Awaitable, Callable, Dict, Optional, Protocol, Set

from lg_sotf.mcp.protocol import PARSE_ERROR, McpServer, error_response
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

MAX_LINE_BYTES = 1_048_576
READ_CHUNK_BYTES = 65_536
MAX_CONCURRENT_REQUESTS = 4

Writer = Callable[[bytes], Awaitable[None]]


class Reader(Protocol):
    async def read(self, n: int = -1) -> bytes: ...


def encode_message(message: Dict[str, Any]) -> bytes:
    """One JSON line (no embedded newlines: ``json.dumps`` escapes them)."""
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


async def serve(server: McpServer, reader: Reader, write: Writer) -> None:
    """Read messages until EOF, dispatch them and write the responses."""
    lock = asyncio.Lock()
    slots = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    pending: Set[asyncio.Task[None]] = set()

    async def send(response: Optional[Dict[str, Any]]) -> None:
        if response is None:
            return
        data = encode_message(response)
        async with lock:
            await write(data)

    async def handle(line: bytes) -> None:
        try:
            await send(await server.handle_line(line))
        finally:
            slots.release()

    buffer = b""
    discarding = False
    while True:
        chunk = await reader.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        buffer += chunk
        while True:
            newline = buffer.find(b"\n")
            if newline == -1:
                if len(buffer) > MAX_LINE_BYTES:
                    if not discarding:
                        discarding = True
                        log.warning("mcp.message_too_large", limit=MAX_LINE_BYTES)
                        await send(error_response(None, PARSE_ERROR, "message exceeds the size limit"))
                    buffer = b""
                break
            line, buffer = buffer[:newline], buffer[newline + 1 :]
            if discarding:
                discarding = False
                continue
            if len(line) > MAX_LINE_BYTES:
                log.warning("mcp.message_too_large", limit=MAX_LINE_BYTES)
                await send(error_response(None, PARSE_ERROR, "message exceeds the size limit"))
                continue
            if not line.strip():
                continue
            await slots.acquire()
            task = asyncio.create_task(handle(line))
            pending.add(task)
            task.add_done_callback(pending.discard)
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def _stdin_reader() -> asyncio.StreamReader:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_LINE_BYTES)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    return reader


async def _write_stdout(data: bytes) -> None:
    out = sys.stdout.buffer
    out.write(data)
    out.flush()


async def run_stdio(server: McpServer) -> None:
    """Serve one MCP session on this process's stdin/stdout."""
    reader = await _stdin_reader()
    await serve(server, reader, _write_stdout)


__all__ = ["MAX_LINE_BYTES", "encode_message", "run_stdio", "serve"]
