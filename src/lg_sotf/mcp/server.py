"""MCP stdio transport: newline-delimited JSON-RPC messages on stdin/stdout.

Each message is one line of UTF-8 JSON. Lines longer than
:data:`MAX_LINE_BYTES` are discarded (up to their newline) and answered
with a parse error, so a runaway client cannot make the server buffer
without bound.

Only ``tools/call`` calls the LG-SOTF API, so only a tool call runs as a
task: at most :data:`MAX_CONCURRENT_REQUESTS` at once, and at most
:data:`MAX_PENDING_CALLS` running or waiting for a turn (one more is answered
at once with an ``isError`` result asking the client to retry). Every other
message (``initialize``, ``ping``, ``tools/list``, notifications) is answered
as soon as it is read, so a slow tool call never delays a ``ping`` or a
cancellation. ``notifications/cancelled`` stops the named tool call if it is
still running, and no response is sent for it (MCP cancellation).

Responses are written whole, one per line, under a lock. Nothing but
protocol messages is ever written to stdout: logs go to stderr.

One message never ends the session: a message nested too deeply to parse
is a parse error, strings the client sent are echoed back as valid JSON even
when they hold a lone surrogate, and any other failure while handling one
message is logged (by exception type only) and answered with an internal error.
"""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from typing import Any, Awaitable, Callable, Dict, Optional, Protocol, Set, Union

from lg_sotf.mcp.protocol import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    NOT_JSON,
    PARSE_ERROR,
    McpServer,
    error_response,
    valid_id,
)
from lg_sotf.mcp.tools import text_result
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

MAX_LINE_BYTES = 1_048_576
READ_CHUNK_BYTES = 65_536
MAX_CONCURRENT_REQUESTS = 4
MAX_PENDING_CALLS = 32
BUSY_RETRY_AFTER_S = 5
BUSY = (
    "tools/call refused: {count} tool calls are already running or waiting in this MCP session. "
    "retry_after_s: {retry}"
)

Writer = Callable[[bytes], Awaitable[None]]
RequestId = Union[str, int]


class Reader(Protocol):
    async def read(self, n: int = -1) -> bytes: ...


def encode_message(message: Dict[str, Any]) -> bytes:
    """One JSON line (no embedded newlines: ``json.dumps`` escapes them).

    A lone surrogate (which a client can send as ``"\\ud800"``) cannot be encoded
    as UTF-8; ``backslashreplace`` writes it as that same JSON escape instead of failing.
    """
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8", errors="backslashreplace") + b"\n"


def _tool_call_id(message: Any) -> Optional[RequestId]:
    """The id of a ``tools/call`` request (the only method that calls the API), else ``None``."""
    if isinstance(message, dict) and message.get("method") == "tools/call" and valid_id(message.get("id")):
        request_id: RequestId = message["id"]
        return request_id
    return None


def _cancelled_id(message: Any) -> Optional[RequestId]:
    """The ``requestId`` of a ``notifications/cancelled``, else ``None``."""
    if not isinstance(message, dict) or message.get("method") != "notifications/cancelled" or "id" in message:
        return None
    params = message.get("params")
    request_id = params.get("requestId") if isinstance(params, dict) else None
    return request_id if valid_id(request_id) else None


async def serve(server: McpServer, reader: Reader, write: Writer) -> None:
    """Read messages until EOF, dispatch them and write the responses."""
    lock = asyncio.Lock()
    slots = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    tasks: Set[asyncio.Task[None]] = set()
    calls: Dict[RequestId, asyncio.Task[None]] = {}  # tool calls still being computed, by request id

    async def send(response: Optional[Dict[str, Any]]) -> None:
        if response is None:
            return
        data = encode_message(response)
        async with lock:
            await write(data)

    async def internal_error(exc: Exception, request_id: Optional[RequestId]) -> None:
        log.error("mcp.message_failed", error_type=type(exc).__name__)
        try:
            await send(error_response(request_id, INTERNAL_ERROR, "internal error"))
        except Exception as send_exc:  # noqa: BLE001 - best effort: the session goes on
            log.error("mcp.response_failed", error_type=type(send_exc).__name__)

    async def run_call(request_id: RequestId, message: Dict[str, Any]) -> None:
        try:
            async with slots:
                response = await server.handle(message)
            calls.pop(request_id, None)  # answered: a cancellation arriving now no longer applies
            await send(response)
        except Exception as exc:  # noqa: BLE001 - one failing call must not go unanswered
            await internal_error(exc, request_id)

    def forget(request_id: RequestId, task: asyncio.Task[None]) -> None:
        tasks.discard(task)
        if calls.get(request_id) is task:
            del calls[request_id]

    async def dispatch(line: bytes) -> None:
        try:
            message = json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):  # RecursionError: nested too deeply
            await send(error_response(None, PARSE_ERROR, NOT_JSON))
            return
        request_id = _tool_call_id(message)
        if request_id is not None:
            if request_id in calls:
                await send(error_response(request_id, INVALID_REQUEST, "invalid request: id is already in use"))
            elif len(tasks) >= MAX_PENDING_CALLS:
                log.warning("mcp.busy", pending=len(tasks))
                busy = BUSY.format(count=len(tasks), retry=BUSY_RETRY_AFTER_S)
                await send({"jsonrpc": "2.0", "id": request_id, "result": text_result(busy, is_error=True)})
            else:
                task = asyncio.create_task(run_call(request_id, message))
                tasks.add(task)
                calls[request_id] = task
                task.add_done_callback(functools.partial(forget, request_id))
            return
        cancelled = _cancelled_id(message)
        if cancelled is not None:
            running = calls.pop(cancelled, None)
            if running is not None:
                running.cancel()
                log.info("mcp.request_cancelled")
            return
        # initialize, ping, tools/list, other notifications and invalid messages: no I/O, answered now.
        await send(await server.handle(message))

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
            try:
                await dispatch(line)
            except Exception as exc:  # noqa: BLE001 - one failing message must not end the session
                await internal_error(exc, None)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


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
