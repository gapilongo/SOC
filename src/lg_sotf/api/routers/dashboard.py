# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/dashboard/summary`` (viewer, cached 15 s per tenant in Redis) and ``/usage/llm`` (admin)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from redis.exceptions import RedisError

from lg_sotf.api.auth.deps import ADMIN, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import DashboardOut, UsageDayOut, UsageOut
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

CACHE_TTL_S = 15
MAX_WINDOW_HOURS = 24 * 90
DEFAULT_USAGE_DAYS = 30
MAX_USAGE_DAYS = 400

dashboard = APIRouter(prefix="/dashboard", tags=["dashboard"])
usage = APIRouter(prefix="/usage", tags=["usage"])


def cache_key(ctx: ApiContext, tenant_id: str, window_hours: int) -> str:
    return f"{ctx.prefix}:t:{tenant_id}:cache:dashboard:{window_hours}"


async def _compute(ctx: ApiContext, tenant_id: str, window_hours: int) -> DashboardOut:
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_hours)
    repos = ctx.repos
    async with ctx.db.tenant_tx(tenant_id, readonly=True) as conn:
        counts = await repos.alerts.dashboard_counts(tenant_id, since, conn=conn)
        times = await repos.alerts.response_times(tenant_id, since, conn=conn)
        open_escalations = await repos.escalations.count_active(tenant_id, conn=conn)
        runs = await repos.runs.counts_by_status(tenant_id, active_only=True, conn=conn)
        usage_rows = await repos.llm_usage.list_range(tenant_id, since.date(), now.date(), conn=conn)
    return DashboardOut(
        window_hours=window_hours,
        since=since,
        generated_at=now,
        alerts_total=counts.total,
        by_status=counts.by_status,
        by_severity=counts.by_severity,
        by_disposition=counts.by_disposition,
        mtta_s=times.mtta_s,
        mttr_s=times.mttr_s,
        acknowledged=times.acknowledged,
        resolved=times.resolved,
        open_escalations=open_escalations,
        runs_by_status=runs,
        queue_depth=int(runs.get("queued", 0)),
        llm_cost_usd=float(sum((r.cost_usd for r in usage_rows), Decimal(0))),
        llm_tokens=sum(r.input_tokens + r.output_tokens for r in usage_rows),
    )


@dashboard.get("/summary", response_model=DashboardOut, summary="Counts, MTTA/MTTR, queue depth and LLM cost")
async def summary(
    request: Request,
    window_hours: int = Query(default=24, ge=1, le=MAX_WINDOW_HOURS),
    principal: Principal = Depends(require(VIEWER)),
) -> DashboardOut:
    ctx = get_ctx(request)
    key = cache_key(ctx, principal.tenant_id, window_hours)
    try:
        cached = await ctx.redis.get(key)
        if cached is not None:
            return DashboardOut.model_validate_json(cached)
    except (RedisError, OSError, TimeoutError, ValueError) as exc:
        log.warning("dashboard.cache_unavailable", error_type=type(exc).__name__)
    result = await _compute(ctx, principal.tenant_id, window_hours)
    try:
        await ctx.redis.set(key, result.model_dump_json().encode(), ex=CACHE_TTL_S)
    except (RedisError, OSError, TimeoutError) as exc:
        log.warning("dashboard.cache_unavailable", error_type=type(exc).__name__)
    return result


@usage.get("/llm", response_model=UsageOut, summary="Daily LLM usage and cost")
async def llm_usage(
    request: Request,
    start: Optional[date] = Query(default=None, alias="from"),
    end: Optional[date] = Query(default=None, alias="to"),
    principal: Principal = Depends(require(ADMIN)),
) -> UsageOut:
    ctx = get_ctx(request)
    end = end or datetime.now(UTC).date()
    start = start or end - timedelta(days=DEFAULT_USAGE_DAYS - 1)
    if end < start:
        raise ApiError(400, "invalid_window", "'to' must not be before 'from'")
    if (end - start).days + 1 > MAX_USAGE_DAYS:
        raise ApiError(400, "invalid_window", f"at most {MAX_USAGE_DAYS} days per request")
    rows = await ctx.repos.llm_usage.list_range(principal.tenant_id, start, end)
    return UsageOut(
        start=start,
        end=end,
        days=[UsageDayOut.model_validate(r) for r in rows],
        total_calls=sum(r.calls for r in rows),
        total_input_tokens=sum(r.input_tokens for r in rows),
        total_output_tokens=sum(r.output_tokens for r in rows),
        total_cost_usd=sum((r.cost_usd for r in rows), Decimal(0)),
    )
