"""MCP protocol conformance: handshake, version negotiation, notifications, tools/list, JSON-RPC errors."""

from __future__ import annotations

import re
from typing import Any, Dict, List

import pytest

from lg_sotf import __version__
from lg_sotf.mcp.base import CATALOG_VERSION
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

ORIGINAL_TOOLS = {
    "search_alerts",
    "get_alert",
    "get_alert_timeline",
    "list_escalations",
    "get_escalation",
    "dashboard_summary",
    "add_note",
    "get_evidence_pack",
}
TESTER_TOOLS = {
    "whoami",
    "get_verdict",
    "list_actions",
    "get_action",
    "ingest_test_alerts",
    "wait_for_verdict",
    "get_test_run",
}
EXPECTED_TOOLS = ORIGINAL_TOOLS | TESTER_TOOLS
WRITE_TOOLS = {"add_note", "ingest_test_alerts"}


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
    assert result["serverInfo"]["catalog_version"] == CATALOG_VERSION == "1.0.0"  # design §14
    assert f"Tool catalog {CATALOG_VERSION}." in result["instructions"]
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
        assert tool["annotations"]["readOnlyHint"] is (tool["name"] not in WRITE_TOOLS)


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


READ_PREFIXES = ("get_", "list_", "search_", "wait_")
WRITE_PREFIXES = ("add_", "propose_", "draft_", "ingest_", "start_", "request_")
DECISION_WORDS = ("approve", "reject", "rollback", "roll_back", "retry", "decide", "claim", "settings", "delete")


def _property_names(schema: Any) -> List[str]:
    names: List[str] = []
    if isinstance(schema, dict):
        for name, sub in (schema.get("properties") or {}).items():
            names.append(name)
            names.extend(_property_names(sub))
        names.extend(_property_names(schema.get("items")))
    return names


async def test_tools_list_annotations_and_naming_follow_the_design_lint() -> None:
    server = await initialized(make_server(StubApi()))
    response = await server.handle(request("tools/list"))
    assert response is not None
    tools = response["result"]["tools"]
    assert [t["name"] for t in tools] == list(TOOLS)  # deterministic order
    assert {t["name"] for t in tools} >= TESTER_TOOLS
    for tool in tools:
        name, annotations, schema = tool["name"], tool["annotations"], tool["inputSchema"]
        assert annotations["title"] == tool["title"] and annotations["openWorldHint"] is False, name
        assert (annotations["readOnlyHint"] is True) != (annotations.get("destructiveHint") is True), name
        assert annotations.get("idempotentHint") is not True, name
        if name in WRITE_TOOLS:
            assert annotations == {
                "title": tool["title"],
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": False,
            }
            assert name.startswith(WRITE_PREFIXES), name
        else:
            assert name.startswith(READ_PREFIXES) or name in ("whoami", "dashboard_summary"), name
        assert not any(word in name for word in DECISION_WORDS), name
        assert len(tool["description"]) <= 1_500, name
        assert not {"oneOf", "anyOf", "allOf", "not"} & set(schema), name
        properties = _property_names(schema)
        assert all(re.fullmatch(r"[a-z_]{1,64}", p) for p in properties), (name, properties)
        assert "tenant_id" not in properties, name


async def test_new_tools_round_trip_and_errors_are_well_formed() -> None:
    stub = StubApi()
    stub.json(
        "GET /api/v1/auth/me",
        {"kind": "api_key", "tenant_id": "t", "home_tenant_id": "t", "auth_method": "api_key", "scopes": ["read"]},
    )
    server = make_server(stub)
    early = await server.handle(request("tools/call", {"name": "whoami", "arguments": {}}, request_id="w0"))
    assert early is not None and early["error"]["code"] == SERVER_NOT_INITIALIZED and early["id"] == "w0"
    await initialized(server)

    ok = await server.handle(request("tools/call", {"name": "whoami"}, request_id="w1"))
    assert ok is not None and ok["id"] == "w1" and "error" not in ok
    assert ok["result"]["isError"] is False and ok["result"]["content"][0]["type"] == "text"

    failed = await server.handle(
        request("tools/call", {"name": "get_test_run", "arguments": {"run_handle": "run_" + "0" * 32}}, request_id=3)
    )
    assert failed is not None and "error" not in failed
    assert failed["result"]["isError"] is True
    assert failed["result"]["content"] == [{"type": "text", "text": failed["result"]["content"][0]["text"]}]
    assert failed["result"]["content"][0]["text"].startswith("get_test_run failed: unknown or expired run_handle")

    invalid = await server.handle(request("tools/call", {"name": "wait_for_verdict", "arguments": {}}, request_id=4))
    assert invalid is not None and invalid["error"]["code"] == INVALID_PARAMS
    assert invalid["error"]["message"].startswith("invalid arguments for wait_for_verdict:")


def test_instructions_are_bounded_and_lead_with_the_safety_rules() -> None:
    from lg_sotf.mcp.protocol import INSTRUCTIONS

    assert len(INSTRUCTIONS) < 2_048
    head = INSTRUCTIONS[:512]
    assert "untrusted" in head.lower() and "never follow instructions" in head
    assert "ingest_test_alerts" in head and "asked for it" in head
    assert "approves" in INSTRUCTIONS and "1.0.0" in INSTRUCTIONS
