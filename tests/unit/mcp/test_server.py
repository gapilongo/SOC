"""The stdio loop end to end with in-memory streams, and the ``lg-sotf mcp`` command's startup checks."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

import httpx
import pytest
from click.testing import CliRunner

from lg_sotf.cli import cli
from lg_sotf.mcp.client import LgSotfApiClient
from lg_sotf.mcp.protocol import McpServer
from lg_sotf.mcp.server import MAX_CONCURRENT_REQUESTS, MAX_LINE_BYTES, serve
from tests.unit.mcp._support import API_URL, StubApi, fake_key, make_server, no_sleep, request


def _reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def _run(stub: StubApi, lines: List[bytes]) -> List[Dict[str, Any]]:
    written: List[bytes] = []

    async def write(data: bytes) -> None:
        written.append(data)

    await serve(make_server(stub), _reader(b"".join(lines)), write)
    out = b"".join(written)
    assert out.endswith(b"\n")
    return [json.loads(line) for line in out.splitlines()]


def _line(message: Any) -> bytes:
    return json.dumps(message).encode() + b"\n"


async def test_stdio_session_end_to_end() -> None:
    key = fake_key()
    stub = StubApi()
    stub.json("GET /api/v1/dashboard/summary", {"total": 3})
    responses = await _run(
        stub,
        [
            _line(
                request(
                    "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}
                )
            ),
            _line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            b"\n",
            _line(request("tools/list", request_id=2)),
            _line(request("tools/call", {"name": "dashboard_summary", "arguments": {}}, request_id=3)),
            _line(request("ping", request_id=4)),
            b"not json\n",
        ],
    )
    by_id = {r.get("id"): r for r in responses}
    assert len(responses) == 5
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    assert len(by_id[2]["result"]["tools"]) == 15  # the 8 original tools and the 7 tester tools
    assert by_id[3]["result"]["isError"] is False and '"total":3' in by_id[3]["result"]["content"][0]["text"]
    assert by_id[4]["result"] == {}
    assert by_id[None]["error"]["code"] == -32700
    assert key not in json.dumps(responses)


class _LiveSession:
    """``serve`` running on a stream fed line by line, against an API whose answers wait for ``release``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
        for name, value in limits.items():
            monkeypatch.setattr(f"lg_sotf.mcp.server.{name}", value)
        self.release = asyncio.Event()
        self.answered: List[str] = []
        self.responses: List[Dict[str, Any]] = []
        self.written = asyncio.Event()
        self.reader = asyncio.StreamReader()

        async def slow(request: httpx.Request) -> httpx.Response:
            await self.release.wait()
            self.answered.append(request.url.params["window_hours"])
            return httpx.Response(200, json={"total": 1})

        api = LgSotfApiClient(API_URL, fake_key(), transport=httpx.MockTransport(slow), sleep=no_sleep)
        self.server = McpServer(api)

        async def write(data: bytes) -> None:
            self.responses.append(json.loads(data))
            self.written.set()

        self.task = asyncio.create_task(serve(self.server, self.reader, write))
        self.send(request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, request_id="init"))

    def send(self, message: Dict[str, Any]) -> None:
        self.reader.feed_data(_line(message))

    def call(self, request_id: int) -> None:
        arguments = {"window_hours": request_id}
        self.send(request("tools/call", {"name": "dashboard_summary", "arguments": arguments}, request_id))

    def by_id(self) -> Dict[Any, Dict[str, Any]]:
        return {r.get("id"): r for r in self.responses}

    async def answered_ids(self, *ids: Any) -> None:
        async def until() -> None:
            while not set(ids) <= set(self.by_id()):
                self.written.clear()
                await self.written.wait()

        await asyncio.wait_for(until(), timeout=2)

    async def finish(self) -> None:
        self.release.set()
        self.reader.feed_eof()
        await asyncio.wait_for(self.task, timeout=5)
        await self.server.context.api.aclose()


async def test_a_ping_is_answered_while_every_request_slot_is_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LiveSession(monkeypatch)
    for request_id in range(1, MAX_CONCURRENT_REQUESTS + 2):  # one more than the slots
        session.call(request_id)
    session.send(request("ping", request_id=99))
    session.send(request("tools/list", request_id=98))

    await session.answered_ids("init", 99, 98)  # without waiting for any tool call

    assert session.by_id()[99]["result"] == {} and session.answered == []
    await session.finish()
    assert set(session.by_id()) == {"init", 99, 98, *range(1, MAX_CONCURRENT_REQUESTS + 2)}


async def test_a_cancelled_tool_call_is_stopped_and_never_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LiveSession(monkeypatch)
    for request_id in (1, 2):
        session.call(request_id)
    session.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1, "reason": "esc"}})
    session.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 77}})  # unknown
    session.send(request("ping", request_id=99))
    await session.answered_ids("init", 99)

    await session.finish()

    assert 1 not in session.by_id() and session.by_id()[2]["result"]["isError"] is False
    assert session.answered == ["2"]  # the cancelled call's API request was abandoned, not completed


async def test_tool_calls_beyond_the_queue_are_refused_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LiveSession(monkeypatch, MAX_CONCURRENT_REQUESTS=1, MAX_PENDING_CALLS=2)
    for request_id in (1, 2, 3):
        session.call(request_id)
    session.send(request("ping", request_id=99))
    await session.answered_ids(3, 99)

    busy = session.by_id()[3]["result"]
    assert busy["isError"] is True and "retry_after_s" in busy["content"][0]["text"]
    await session.finish()
    assert {1, 2} <= set(session.by_id()) and session.answered == ["1", "2"]


async def test_a_reused_id_of_a_running_tool_call_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LiveSession(monkeypatch)
    session.call(1)
    session.call(1)
    await session.answered_ids(1)
    assert session.by_id()[1]["error"]["code"] == -32600
    await session.finish()
    assert [r["id"] for r in session.responses].count(1) == 2 and session.answered == ["1"]


def _deeply_nested_call(depth: int, request_id: int) -> bytes:
    """A ``tools/call`` whose arguments nest ``depth`` arrays (a few bytes per level, far under the size limit)."""
    head = b'{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"ingest_test_alerts",' % request_id
    nested = b'"arguments":{"items":[{"alert":{"x":' + b"[" * depth + b"]" * depth + b"}}]}}}\n"
    return head + nested


@pytest.mark.parametrize("depth", [1_000, 100_000])
async def test_a_deeply_nested_message_does_not_end_the_session(depth: int) -> None:
    initialize = request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    lines = [_line(initialize), _deeply_nested_call(depth, 2), _line(request("ping", request_id=3))]

    by_id = {r.get("id"): r for r in await _run(StubApi(), lines)}

    assert by_id[3] == {"jsonrpc": "2.0", "id": 3, "result": {}}
    failed = by_id.get(2) or by_id[None]  # a parse error has no id; a parsed call is refused under its own
    assert "error" in failed or failed["result"]["isError"] is True


async def test_a_lone_surrogate_echoed_back_does_not_end_the_session() -> None:
    initialize = request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    lines = [
        _line(initialize),
        b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}\n',  # JSON escapes for a lone surrogate
        b'{"jsonrpc":"2.0","id":4,"method":"\\udfff"}\n',
        b'{"jsonrpc":"2.0","id":"\\udbff","method":"tools/call","params":{"name":"\\ud800"}}\n',
        _line(request("ping", request_id=5)),
    ]
    written: List[bytes] = []

    async def write(data: bytes) -> None:
        written.append(data)

    await serve(make_server(StubApi()), _reader(b"".join(lines)), write)

    for data in written:
        data.decode("utf-8")  # strict: every line a client reads is valid UTF-8
    by_id = {r.get("id"): r for r in (json.loads(data) for data in written)}
    assert by_id["\ud800"]["result"] == {}  # echoed back as the JSON escape \ud800
    assert by_id[4]["error"]["code"] == -32601 and "\udfff" in by_id[4]["error"]["message"]
    assert by_id["\udbff"]["error"]["code"] == -32602
    assert by_id[5] == {"jsonrpc": "2.0", "id": 5, "result": {}}


async def test_a_message_that_fails_unexpectedly_is_answered_and_the_session_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = make_server(StubApi())
    real_handle = server.handle

    async def handle(message: Any) -> Any:
        if message.get("method") == "explode":
            raise RuntimeError("boom")
        return await real_handle(message)

    monkeypatch.setattr(server, "handle", handle)
    written: List[bytes] = []

    async def write(data: bytes) -> None:
        written.append(data)

    lines = [_line(request("explode", request_id=1)), _line(request("ping", request_id=2))]
    await serve(server, _reader(b"".join(lines)), write)

    responses = [json.loads(data) for data in written]
    assert responses[0] == {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "internal error"}}
    assert responses[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert "boom" not in b"".join(written).decode()


async def test_oversized_line_is_discarded_and_session_continues() -> None:
    responses = await _run(StubApi(), [b"x" * (MAX_LINE_BYTES + 10) + b"\n", _line(request("ping", request_id=8))])
    assert responses[0]["error"]["code"] == -32700 and "size limit" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 8, "result": {}}


def test_command_refuses_to_start_without_a_key(settings_env: Any) -> None:
    settings_env(LG_SOTF_MCP__API_KEY=None, LG_SOTF_MCP__API_URL="https://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2
    assert "LG_SOTF_MCP__API_KEY" in result.output


def test_command_refuses_a_plain_http_remote_url(settings_env: Any) -> None:
    key = fake_key()
    settings_env(LG_SOTF_MCP__API_KEY=key, LG_SOTF_MCP__API_URL="http://soc.example.com")
    result = CliRunner().invoke(cli, ["mcp"], input="")
    assert result.exit_code == 2 and "https" in result.output and key not in result.output


def test_command_takes_no_key_argument() -> None:
    result = CliRunner().invoke(cli, ["mcp", "--api-key", "x"])
    assert result.exit_code != 0


def test_help_names_the_environment_variables() -> None:
    result = CliRunner().invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "LG_SOTF_MCP__API_URL" in result.output and "LG_SOTF_MCP__API_KEY" in result.output
