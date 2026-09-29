"""Liveness, readiness and Prometheus metrics.

Probes are served at the root (``/healthz``, ``/readyz``) and under
``/api/v1``. ``/metrics`` is served at the root only: the public ingress
routes ``/api`` to this service, so metrics must never be reachable there.
"""

from __future__ import annotations

import asyncio
import hmac
from typing import Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import generate_latest

from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.db.errors import DatabaseUnavailable
from lg_sotf.ingestion.metrics import REGISTRY as INGESTION_REGISTRY
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import render_latest

log = get_logger(__name__)

PING_TIMEOUT_S = 2.0

router = APIRouter(tags=["health"])
metrics_router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness (no dependencies)")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", summary="Readiness (database and Redis reachable)")
async def readyz(request: Request) -> JSONResponse:
    ctx = get_ctx(request)
    checks: Dict[str, str] = {}
    try:
        latency = await asyncio.wait_for(ctx.db.ping(acquire_timeout_s=PING_TIMEOUT_S / 2), timeout=PING_TIMEOUT_S)
        # None: every pooled connection is busy serving requests, so the database is answering.
        checks["database"] = "ok" if latency is not None else "busy"
    except (DatabaseUnavailable, TimeoutError) as exc:
        log.warning("health.not_ready", dependency="database", error_type=type(exc).__name__)
        checks["database"] = "error"
    try:
        await asyncio.wait_for(ctx.redis.ping(), timeout=PING_TIMEOUT_S)
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001 - any Redis failure means not ready
        log.warning("health.not_ready", dependency="redis", error_type=type(exc).__name__)
        checks["redis"] = "error"
    ready = "error" not in checks.values()
    return JSONResponse(
        {"status": "ok" if ready else "unavailable", "checks": checks}, status_code=200 if ready else 503
    )


@metrics_router.get("/metrics", summary="Prometheus metrics", response_class=Response)
async def metrics(request: Request) -> Response:
    ctx = get_ctx(request)
    token = ctx.settings.api.metrics_token
    if token is not None:
        expected = token.get_secret_value().strip().encode()
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        # An empty configured token (e.g. ``LG_SOTF_API__METRICS_TOKEN=`` in an env file) fails closed:
        # it must never be satisfied by an empty bearer value.
        if not expected:
            log.warning("metrics.token_empty")
        if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip().encode(), expected):
            raise ApiError(401, "unauthorized", "metrics token required", headers={"WWW-Authenticate": "Bearer"})
    payload, content_type = render_latest()
    return Response(payload + generate_latest(INGESTION_REGISTRY), media_type=content_type)
