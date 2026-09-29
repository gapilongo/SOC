"""``/ws``: tenant-scoped event stream over a real uvicorn server and the ``websockets`` client."""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator, Dict

import pytest
import pytest_asyncio
import uvicorn
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from lg_sotf.queue.events import make_event
from tests.integration.api.conftest import TENANT_A, TENANT_B, UI_ORIGIN, ApiHarness

pytestmark = pytest.mark.integration


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:  # pragma: no cover - uvicorn API differs by version
        pass


@pytest_asyncio.fixture
async def served(api: ApiHarness) -> AsyncIterator[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = _Server(uvicorn.Config(api.app, lifespan="off", log_config=None, access_log=False))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.01)
    try:
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)
        sock.close()


async def _recv(ws: Any, wait_s: float = 3.0) -> Dict[str, Any]:
    return json.loads(await asyncio.wait_for(ws.recv(), wait_s))


async def test_stream_delivers_only_the_principals_tenant(api: ApiHarness, served: str) -> None:
    token = api.token(await api.user(TENANT_A, "viewer"))
    async with connect(f"{served}/ws?token={token}") as ws:
        hello = await _recv(ws)
        assert hello["type"] == "hello" and hello["tenant_id"] == TENANT_A
        await api.ctx.events.publish(TENANT_B, make_event("alert.created", TENANT_B, "b-1", {"status": "queued"}))
        await api.ctx.events.publish(TENANT_A, make_event("alert.updated", TENANT_A, "a-1", {"status": "closed"}))
        event = await _recv(ws)
        assert (event["type"], event["tenant_id"], event["alert_id"]) == ("alert.updated", TENANT_A, "a-1")
        with pytest.raises(asyncio.TimeoutError):
            await _recv(ws, wait_s=0.3)


async def test_versioned_path_and_heartbeat(api: ApiHarness, served: str) -> None:
    api.ctx.ws.heartbeat_s = 0.2
    token = api.token(await api.user(TENANT_A, "analyst"))
    async with connect(f"{served}/api/v1/ws?token={token}") as ws:
        assert (await _recv(ws))["type"] == "hello"
        assert (await _recv(ws))["type"] == "ping"


@pytest.mark.parametrize("query", ["", "?token=", "?token=not-a-jwt"])
async def test_missing_or_invalid_token_is_refused_at_handshake(api: ApiHarness, served: str, query: str) -> None:
    with pytest.raises(InvalidStatus) as excinfo:
        async with connect(f"{served}/ws{query}"):
            pass
    assert excinfo.value.response.status_code == 403


async def test_api_keys_are_not_accepted_in_the_url(api: ApiHarness, served: str) -> None:
    _, token = await api.api_key(TENANT_A, ["read"])
    with pytest.raises(InvalidStatus):
        async with connect(f"{served}/ws?token={token}"):
            pass


async def test_foreign_browser_origin_is_refused(api: ApiHarness, served: str) -> None:
    token = api.token(await api.user(TENANT_A, "viewer"))
    with pytest.raises(InvalidStatus):
        async with connect(f"{served}/ws?token={token}", origin="https://evil.example"):
            pass
    async with connect(f"{served}/ws?token={token}", origin=UI_ORIGIN) as ws:
        assert (await _recv(ws))["type"] == "hello"


async def test_socket_closes_when_the_token_expires(api: ApiHarness, served: str) -> None:
    user = await api.user(TENANT_A, "viewer")
    ttl = api.ctx.tokens.access_ttl_s
    issued = api.ctx.tokens.issue_access(user, now=datetime.now(UTC) - timedelta(seconds=ttl - 1))
    async with connect(f"{served}/ws?token={issued.token}") as ws:
        assert (await _recv(ws))["type"] == "hello"
        with pytest.raises(ConnectionClosed) as excinfo:
            while True:
                await asyncio.wait_for(ws.recv(), 5)
    assert excinfo.value.rcvd is not None and excinfo.value.rcvd.code == 4401
