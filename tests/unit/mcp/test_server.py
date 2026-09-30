"""The stdio loop end to end with in-memory streams, and the ``lg-sotf mcp`` command's startup checks."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

from click.testing import CliRunner

from lg_sotf.mcp.command import mcp_command
from lg_sotf.mcp.server import MAX_LINE_BYTES, serve
from tests.unit.mcp._support import StubApi, fake_key, make_server, request


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
    assert len(by_id[2]["result"]["tools"]) == 8
    assert by_id[3]["result"]["isError"] is False and '"total":3' in by_id[3]["result"]["content"][0]["text"]
    assert by_id[4]["result"] == {}
    assert by_id[None]["error"]["code"] == -32700
    assert key not in json.dumps(responses)


async def test_oversized_line_is_discarded_and_session_continues() -> None:
    responses = await _run(StubApi(), [b"x" * (MAX_LINE_BYTES + 10) + b"\n", _line(request("ping", request_id=8))])
    assert responses[0]["error"]["code"] == -32700 and "size limit" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 8, "result": {}}


def test_command_refuses_to_start_without_a_key(settings_env: Any) -> None:
    settings_env(LG_SOTF_MCP__API_KEY=None, LG_SOTF_MCP__API_URL="https://soc.example.com")
    result = CliRunner().invoke(mcp_command, [], input="")
    assert result.exit_code == 2
    assert "LG_SOTF_MCP__API_KEY" in result.output


def test_command_refuses_a_plain_http_remote_url(settings_env: Any) -> None:
    key = fake_key()
    settings_env(LG_SOTF_MCP__API_KEY=key, LG_SOTF_MCP__API_URL="http://soc.example.com")
    result = CliRunner().invoke(mcp_command, [], input="")
    assert result.exit_code == 2 and "https" in result.output and key not in result.output


def test_command_takes_no_key_argument() -> None:
    result = CliRunner().invoke(mcp_command, ["--api-key", "x"])
    assert result.exit_code != 0


def test_help_names_the_environment_variables() -> None:
    result = CliRunner().invoke(mcp_command, ["--help"])
    assert result.exit_code == 0
    assert "LG_SOTF_MCP__API_URL" in result.output and "LG_SOTF_MCP__API_KEY" in result.output
