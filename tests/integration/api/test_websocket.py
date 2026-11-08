"""``/ws``: tenant-scoped event stream over a real uvicorn server and the ``websockets`` client."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator

import pytest
import pytest_asyncio
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from lg_sotf.queue.events import make_event
from tests.integration.api._support import PASSWORD, TENANT_A, TENANT_B, UI_ORIGIN, ApiHarness
from tests.integration.api._support import recv_json as _recv
from tests.integration.api._support import serve_api as _serving

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def served(api: ApiHarness) -> AsyncIterator[str]:
    async with _serving(api) as url:
        yield url


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


async def _closed_code(ws: Any, wait_s: float = 5.0) -> int:
    with pytest.raises(ConnectionClosed) as excinfo:
        while True:
            await asyncio.wait_for(ws.recv(), wait_s)
    assert excinfo.value.rcvd is not None
    return excinfo.value.rcvd.code


async def test_logout_closes_an_open_socket(make_api: Any) -> None:
    """AUTHZ-3: a revoked (logged-out) token stops receiving events."""
    api = await make_api(api={"ws_revalidate_s": 0.2})
    await api.user(TENANT_A, "viewer", email="ws.out@a.example.com")
    login = await api.client.post("/api/v1/auth/login", json={"email": "ws.out@a.example.com", "password": PASSWORD})
    token = login.json()["access_token"]
    async with _serving(api) as served:
        async with connect(f"{served}/ws?token={token}") as ws:
            assert (await _recv(ws))["type"] == "hello"
            out = await api.client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert out.status_code == 204
            assert await _closed_code(ws) == 4401


async def test_deactivated_user_socket_is_closed(make_api: Any) -> None:
    api = await make_api(api={"ws_revalidate_s": 0.2})
    user = await api.user(TENANT_A, "viewer")
    async with _serving(api) as served:
        async with connect(f"{served}/ws?token={api.token(user)}") as ws:
            assert (await _recv(ws))["type"] == "hello"
            await api.repos.users.update(TENANT_A, user.id, is_active=False)
            assert await _closed_code(ws) == 1008


async def test_suspended_tenant_socket_is_closed(make_api: Any) -> None:
    api = await make_api(api={"ws_revalidate_s": 0.2})
    user = await api.user(TENANT_A, "viewer")
    async with _serving(api) as served:
        async with connect(f"{served}/ws?token={api.token(user)}") as ws:
            assert (await _recv(ws))["type"] == "hello"
            await api.repos.tenants.set_status(TENANT_A, "suspended")
            api.ctx.tenants.invalidate(TENANT_A)
            assert await _closed_code(ws) == 1008


async def test_one_tenant_cannot_take_every_socket(make_api: Any) -> None:
    """AUTHZ-4: per-principal and per-tenant quotas keep other tenants able to connect."""
    api = await make_api(api={"ws_max_per_principal": 2, "ws_max_per_tenant": 3, "ws_max_subscribers": 4})
    a1, a2 = await api.user(TENANT_A, "viewer"), await api.user(TENANT_A, "viewer")
    b = await api.user(TENANT_B, "viewer")
    async with _serving(api) as served, contextlib.AsyncExitStack() as stack:
        for _ in range(2):
            ws = await stack.enter_async_context(connect(f"{served}/ws?token={api.token(a1)}"))
            assert (await _recv(ws))["type"] == "hello"
        with pytest.raises(InvalidStatus):  # principal quota
            async with connect(f"{served}/ws?token={api.token(a1)}"):
                pass
        ws = await stack.enter_async_context(connect(f"{served}/ws?token={api.token(a2)}"))
        assert (await _recv(ws))["type"] == "hello"
        with pytest.raises(InvalidStatus):  # tenant quota
            async with connect(f"{served}/ws?token={api.token(a2)}"):
                pass
        assert api.ctx.events.subscriber_count == 3
        async with connect(f"{served}/ws?token={api.token(b)}") as other:
            assert (await _recv(other))["type"] == "hello"
