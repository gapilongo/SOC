"""MCP protocol conformance: handshake, version negotiation, notifications, tools/list, JSON-RPC errors."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from lg_sotf import __version__
from lg_sotf.mcp.protocol import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSION,
    SERVER_NOT_INITIALIZED,
)
from lg_sotf.mcp.tools import TOOLS
from tests.unit.mcp._support import StubApi, initialized, make_server, request

EXPECTED_TOOLS = {
    "search_alerts",
    "get_alert",
    "get_alert_timeline",
    "list_escalations",
    "get_escalation",
    "dashboard_summary",
    "add_note",
    "get_evidence_pack",
}


async def test_initialize_handshake() -> None:
    server = make_server(StubApi())
    response = await server.handle(
        request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude", "version": "1"}},
            request_id="init-1",
        )
    )
    assert response is not None
    assert response["jsonrpc"] == "2.0" and response["id"] == "init-1" and "error" not in response
    result = response["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "lg-sotf" and result["serverInfo"]["version"] == __version__
    assert "untrusted" in result["instructions"].lower()
    assert await server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.initialized and server.client_info["name"] == "claude"


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        ("2025-03-26", "2025-03-26"),
        ("2024-11-05", "2024-11-05"),
        ("1999-01-01", PROTOCOL_VERSION),
        (None, PROTOCOL_VERSION),
    ],
)
async def test_version_negotiation(requested: Any, expected: str) -> None:
    server = make_server(StubApi())
    params: Dict[str, Any] = {"capabilities": {}}
    if requested is not None:
        params["protocolVersion"] = requested
    response = await server.handle(request("initialize", params))
    assert response is not None and response["result"]["protocolVersion"] == expected


async def test_ping_and_notifications_never_answered() -> None:
    server = make_server(StubApi())
    assert await server.handle(request("ping", request_id=7)) == {"jsonrpc": "2.0", "id": 7, "result": {}}
    for method in ("notifications/initialized", "notifications/cancelled", "notifications/unknown", "tools/list"):
        assert await server.handle({"jsonrpc": "2.0", "method": method, "params": {}}) is None


async def test_tools_require_initialize() -> None:
    server = make_server(StubApi())
    response = await server.handle(request("tools/list"))
    assert response is not None and response["error"]["code"] == SERVER_NOT_INITIALIZED
    response = await server.handle(request("tools/call", {"name": "get_alert", "arguments": {"alert_id": "a"}}))
    assert response is not None and response["error"]["code"] == SERVER_NOT_INITIALIZED


async def test_tools_list_schema() -> None:
    server = await initialized(make_server(StubApi()))
    response = await server.handle(request("tools/list"))
    assert response is not None
    tools = response["result"]["tools"]
    assert {t["name"] for t in tools} == EXPECTED_TOOLS
    assert "lookup_indicator" not in {t["name"] for t in tools}
    for tool in tools:
        assert tool["description"] and tool["title"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        for prop in schema["properties"].values():
            if prop["type"] == "string" and "enum" not in prop:
                assert "maxLength" in prop or "format" in prop, (tool["name"], prop)
        assert set(schema.get("required", [])) <= set(schema["properties"])
        assert tool["annotations"]["readOnlyHint"] is (tool["name"] != "add_note")


def test_schemas_match_argument_models() -> None:
    for tool in TOOLS.values():
        model_fields = {f.alias or name for name, f in tool.args.model_fields.items()}
        assert set(tool.input_schema["properties"]) == model_fields, tool.name
        required = {f.alias or name for name, f in tool.args.model_fields.items() if f.is_required()}
        assert set(tool.input_schema.get("required", [])) == required, tool.name


async def test_json_rpc_errors() -> None:
    server = await initialized(make_server(StubApi()))

    parse = await server.handle_line(b"{not json")
    assert parse == {"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": parse["error"]["message"]}}

    for bad in ({"id": 1, "method": "ping"}, {"jsonrpc": "1.0", "id": 1, "method": "ping"}, "text", 42):
        response = await server.handle(bad)
        assert response is not None and response["error"]["code"] == INVALID_REQUEST, bad
    missing_method = await server.handle({"jsonrpc": "2.0", "id": 3})
    assert missing_method is not None and missing_method["error"]["code"] == INVALID_REQUEST
    bad_id = await server.handle({"jsonrpc": "2.0", "id": {"x": 1}, "method": "ping"})
    assert bad_id is not None and bad_id["error"]["code"] == INVALID_REQUEST

    batch = await server.handle([request("ping"), request("ping", request_id=2)])
    assert batch is not None and batch["error"]["code"] == INVALID_REQUEST

    unknown = await server.handle(request("resources/list", request_id=9))
    assert unknown is not None and unknown["id"] == 9 and unknown["error"]["code"] == METHOD_NOT_FOUND

    params_not_object = await server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": [1]})
    assert params_not_object is not None and params_not_object["error"]["code"] == INVALID_PARAMS

    # A response from the client (no method) is ignored.
    assert await server.handle({"jsonrpc": "2.0", "id": 5, "result": {}}) is None


@pytest.mark.parametrize(
    "params",
    [
        {"name": "no_such_tool", "arguments": {}},
        {"arguments": {}},
        {"name": "get_alert", "arguments": {}},
        {"name": "get_alert", "arguments": {"alert_id": "../../etc/passwd"}},
        {"name": "get_alert", "arguments": {"alert_id": "a", "extra": 1}},
        {"name": "get_alert", "arguments": "a"},
        {"name": "search_alerts", "arguments": {"limit": 500}},
        {"name": "search_alerts", "arguments": {"status": ["bogus"]}},
        {"name": "search_alerts", "arguments": {"q": "x" * 201}},
        {"name": "add_note", "arguments": {"alert_id": "a", "text": ""}},
        {"name": "add_note", "arguments": {"alert_id": "a", "text": "x" * 4001}},
        {"name": "dashboard_summary", "arguments": {"window_hours": 0}},
    ],
)
async def test_invalid_tool_calls_are_invalid_params(params: Dict[str, Any]) -> None:
    stub = StubApi()
    server = await initialized(make_server(stub))
    response = await server.handle(request("tools/call", params))
    assert response is not None and response["error"]["code"] == INVALID_PARAMS
    assert stub.requests == []


async def test_unexpected_handler_error_is_internal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    server = await initialized(make_server(StubApi()))

    def boom() -> None:
        raise RuntimeError("secret detail")

    monkeypatch.setattr("lg_sotf.mcp.protocol.tool_definitions", boom)
    response = await server.handle(request("tools/list"))
    assert response is not None and response["error"] == {"code": -32603, "message": "internal error"}
