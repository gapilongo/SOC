"""``WS /ws?token=<access token>``: the tenant's live event stream.

* The token is an access JWT (or OIDC token); API keys are not accepted in
  URLs. Invalid tokens are refused during the handshake (HTTP 403). Browser
  connections must come from an allowed CORS origin.
* After ``{"type": "hello", ...}`` the socket receives every event published
  for the principal's tenant (contract section 7), and ``{"type": "ping"}``
  heartbeats. Delivery is at-most-once: clients re-read state after a
  reconnect.
* While the socket is open the principal is re-checked every
  ``api.ws_revalidate_s``: a logged-out (revoked) or expired token closes
  it with 4401; a disabled or deleted account, or a suspended tenant, with
  1008. REST refuses the same token at once; the socket follows within one
  interval (plus the tenant cache's 15 s).
* Concurrent sockets are capped per principal (``api.ws_max_per_principal``)
  and per tenant (``api.ws_max_per_tenant``) before the process-wide limit,
  so one tenant cannot take every slot; over-quota connections get 1013.
* The server closes the socket with 4401 when the token expires, 1013 when
  the client falls too far behind (or the server is at its subscriber
  limit) and 1008 when a send times out or the client misbehaves.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from lg_sotf.api.auth.authenticate import bearer_principal, client_ip, failure_blocked, record_failure
from lg_sotf.api.auth.principal import Principal, role_at_least
from lg_sotf.api.context import ApiContext, allowed_origins, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.middleware import mark_principal
from lg_sotf.observability.logging import bind_context, get_logger, log_failure
from lg_sotf.queue.events import SubscriberLimitReached, SubscriberQuotaReached

log = get_logger(__name__)

router = APIRouter(tags=["events"])

CLOSE_POLICY = 1008
CLOSE_TOO_BIG = 1009
CLOSE_TRY_AGAIN = 1013
CLOSE_TOKEN_EXPIRED = 4401
WS_BUCKET = "ws"


def _origin_allowed(ctx: ApiContext, origin: Optional[str]) -> bool:
    if origin is None:
        return True
    return origin.rstrip("/") in allowed_origins(ctx.settings)


async def _still_authorized(ctx: ApiContext, token: str, principal: Principal) -> Optional[int]:
    """``None`` while the socket may stay open, else the close code."""
    try:
        current = await bearer_principal(ctx, token)
    except ApiError as exc:
        if exc.status_code >= 500:
            return None  # the identity provider is unreachable: keep serving until the token expires
        if exc.status_code == 401 and "account" not in exc.detail:
            return CLOSE_TOKEN_EXPIRED  # revoked (logout) or expired
        return CLOSE_POLICY  # disabled / deleted account
    if current.tenant_id != principal.tenant_id or not role_at_least(current.role, "viewer"):
        return CLOSE_POLICY
    tenant = await ctx.tenants.get(principal.tenant_id)
    if tenant is None or tenant.status != "active":
        return CLOSE_POLICY
    return None


async def _authenticate(ctx: ApiContext, websocket: WebSocket) -> Optional[Principal]:
    token = websocket.query_params.get("token")
    if not token or len(token) > 8_192:
        return None
    ip = client_ip(websocket)
    if await failure_blocked(ctx, ip, token) is not None:
        return None
    try:
        principal = await bearer_principal(ctx, token)
        tenant = await ctx.tenants.get(principal.tenant_id)
        if tenant is None or tenant.status != "active":
            return None
    except ApiError as exc:
        if exc.status_code == 401:
            await record_failure(ctx, ip, token)
        return None
    if not role_at_least(principal.role, "viewer"):
        return None
    return principal


@router.websocket("/ws")
async def events_socket(websocket: WebSocket) -> None:
    ctx = get_ctx(websocket)
    if not _origin_allowed(ctx, websocket.headers.get("origin")):
        log.info("ws.origin_refused")
        await websocket.close(code=CLOSE_POLICY)
        return
    principal = await _authenticate(ctx, websocket)
    if principal is None:
        await websocket.close(code=CLOSE_POLICY)
        return
    decision = await ctx.limiter.hit(
        WS_BUCKET, principal.id, ctx.settings.api.rate_limit_per_minute, tenant_id=principal.tenant_id
    )
    if not decision.allowed:
        await websocket.close(code=CLOSE_TRY_AGAIN)
        return
    mark_principal(websocket.scope, principal.tenant_id, principal.id)
    bind_context(tenant_id=principal.tenant_id)
    try:
        async with ctx.events.subscribe(principal.tenant_id, owner=principal.id) as subscription:
            await websocket.accept()
            await _send(
                websocket,
                ctx,
                {
                    "type": "hello",
                    "tenant_id": principal.tenant_id,
                    "expires_at": principal.expires_at.isoformat() if principal.expires_at else None,
                },
            )
            code = await _serve(websocket, ctx, principal, subscription, websocket.query_params.get("token", ""))
    except SubscriberQuotaReached as exc:
        log.info("ws.subscriber_quota", reason=str(exc))
        code = CLOSE_TRY_AGAIN
    except SubscriberLimitReached:
        log.warning("ws.subscriber_limit")
        code = CLOSE_TRY_AGAIN
    except (WebSocketDisconnect, TimeoutError):
        code = None
    if code is not None and websocket.application_state != WebSocketState.DISCONNECTED:
        try:
            await websocket.close(code=code)
        except RuntimeError:
            pass
    log.info("ws.closed", code=code)


async def _send(websocket: WebSocket, ctx: ApiContext, message: Dict[str, Any]) -> None:
    await asyncio.wait_for(
        websocket.send_text(json.dumps(message, separators=(",", ":"), default=str)), ctx.ws.send_timeout_s
    )


async def _serve(
    websocket: WebSocket, ctx: ApiContext, principal: Principal, subscription: Any, token: str
) -> Optional[int]:
    tenant_id = principal.tenant_id

    async def forward() -> int:
        async for event in subscription:
            if event.get("tenant_id") != tenant_id:
                continue
            await _send(websocket, ctx, event)
        return CLOSE_TRY_AGAIN  # the subscription ended: this client lagged (or the bus closed)

    async def heartbeat() -> int:
        while True:
            await asyncio.sleep(ctx.ws.heartbeat_s)
            await _send(websocket, ctx, {"type": "ping", "ts": datetime.now(UTC).isoformat()})

    async def receive() -> Optional[int]:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return None
            data = message.get("text") or message.get("bytes") or ""
            if len(data) > ctx.ws.max_message_bytes:
                return CLOSE_TOO_BIG

    async def expiry() -> int:
        if principal.expires_at is None:
            await asyncio.Event().wait()
        remaining = (principal.expires_at - datetime.now(UTC)).total_seconds() if principal.expires_at else 0
        await asyncio.sleep(max(0.0, remaining))
        return CLOSE_TOKEN_EXPIRED

    async def revalidate() -> int:
        while True:
            await asyncio.sleep(ctx.settings.api.ws_revalidate_s)
            try:
                code = await _still_authorized(ctx, token, principal)
            except Exception as exc:  # noqa: BLE001 - a database/Redis blip must not drop every socket
                log_failure(log, "ws.revalidate_failed", exc, level="warning", error_type=type(exc).__name__)
                continue
            if code is not None:
                log.info("ws.principal_revoked", code=code)
                return code

    tasks = [asyncio.create_task(coro) for coro in (forward(), heartbeat(), receive(), expiry(), revalidate())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finished = next(iter(done))
    exc = finished.exception()
    if exc is not None:
        if isinstance(exc, TimeoutError):
            log.info("ws.send_timeout")
            return CLOSE_POLICY
        if isinstance(exc, (WebSocketDisconnect, RuntimeError, OSError)):
            return None
        log_failure(log, "ws.failed", exc, level="warning", error_type=type(exc).__name__)
        return 1011
    return finished.result()
