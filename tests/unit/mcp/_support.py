"""Stub LG-SOTF API for the MCP tests (httpx.MockTransport) and a runtime-built fake API key."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

from lg_sotf.mcp.client import LgSotfApiClient
from lg_sotf.mcp.protocol import McpServer

API_URL = "https://soc.example.com"


def fake_key() -> str:
    """Shaped like an LG-SOTF key, built at runtime (no credential literal in the source)."""
    return "lgk_" + "0" * 32 + "_" + "x" * 40


Responder = Callable[[httpx.Request], httpx.Response]


@dataclass
class StubApi:
    """Records requests; answers from ``routes`` (``"GET /api/v1/alerts"`` → responder) or 404."""

    routes: Dict[str, Responder] = field(default_factory=dict)
    requests: List[httpx.Request] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        responder = self.routes.get(f"{request.method} {request.url.path}")
        if responder is None:
            return httpx.Response(
                404, json={"error": {"code": "not_found", "message": "not found", "request_id": "req-12345678"}}
            )
        return responder(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def json(self, key: str, body: Any, status: int = 200) -> None:
        self.routes[key] = lambda _request: httpx.Response(status, json=body)


async def no_sleep(_seconds: float) -> None:
    return None


def make_client(stub: StubApi, *, url: str = API_URL, key: Optional[str] = None, **kwargs: Any) -> LgSotfApiClient:
    return LgSotfApiClient(url, key or fake_key(), transport=stub.transport(), sleep=no_sleep, **kwargs)


def make_server(
    stub: StubApi, *, max_output_chars: int = 60_000, clock: Optional[FakeClock] = None, **kwargs: Any
) -> McpServer:
    if clock is None:
        return McpServer(make_client(stub, **kwargs), max_output_chars=max_output_chars, sleep=no_sleep)
    return McpServer(make_client(stub, **kwargs), max_output_chars=max_output_chars, sleep=clock.sleep, clock=clock)


class FakeClock:
    """A monotonic clock that only moves when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.sleeps: List[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def request(method: str, params: Optional[Dict[str, Any]] = None, request_id: Any = 1) -> Dict[str, Any]:
    message: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


async def initialized(server: McpServer) -> McpServer:
    response = await server.handle(
        request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}})
    )
    assert response is not None and "result" in response
    assert await server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    return server


def payload(result: Dict[str, Any]) -> Any:
    """The JSON inside a wrapped tool result."""
    text = result["content"][0]["text"]
    start = text.index("<untrusted_alert_data>\n") + len("<untrusted_alert_data>\n")
    end = text.index("\n</untrusted_alert_data>")
    return json.loads(text[start:end])


async def call(server: McpServer, name: str, arguments: Dict[str, Any], request_id: Any = 1) -> Dict[str, Any]:
    """``tools/call`` on an initialized server; returns the JSON-RPC response."""
    response = await server.handle(request("tools/call", {"name": name, "arguments": arguments}, request_id))
    assert response is not None
    return response


def result_text(response: Dict[str, Any]) -> str:
    assert "result" in response, response
    content = response["result"]["content"]
    assert len(content) == 1 and content[0]["type"] == "text"
    return str(content[0]["text"])
