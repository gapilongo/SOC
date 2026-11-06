"""The SOC dashboard figures of one tenant over a recent window.

Every figure is read in one read-only ``db.tenant_tx``, so the counts,
response times, queue and LLM cost describe the same snapshot. Caching is the
caller's (``api.routers.dashboard``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Dict, Optional

from lg_sotf.db.repos import Repositories
from lg_sotf.services.reporting import hours_saved, ratio, resolve_reporting_policy


@dataclass(frozen=True)
class DashboardSummary:
    """The ``/dashboard/summary`` figures (field names are the response's)."""

    window_hours: int
    since: datetime
    generated_at: datetime
    alerts_total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_disposition: Dict[str, int]
    mtta_s: Optional[float]
    mttr_s: Optional[float]
    acknowledged: int
    resolved: int
    open_escalations: int
    runs_by_status: Dict[str, int]
    queue_depth: int
    llm_cost_usd: float
    llm_tokens: int
    handled_without_human: int
    needed_human: int
    handled_without_human_rate: Optional[float]
    analyst_hours_saved: float
    minutes_per_alert: int


async def summary(repos: Repositories, tenant_id: str, window_hours: int) -> DashboardSummary:
    """The figures of the last ``window_hours``, as of now."""
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_hours)
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        counts = await repos.alerts.dashboard_counts(tenant_id, since, conn=conn)
        times = await repos.alerts.response_times(tenant_id, since, conn=conn)
        open_escalations = await repos.escalations.count_active(tenant_id, conn=conn)
        runs = await repos.runs.counts_by_status(tenant_id, active_only=True, conn=conn)
        usage_rows = await repos.llm_usage.list_range(tenant_id, since.date(), now.date(), conn=conn)
        handled, needed = await repos.reports.automation_counts(tenant_id, since, now, conn=conn)
        tenant = await repos.tenants.get(tenant_id, conn=conn)
    minutes = resolve_reporting_policy(tenant.settings).minutes_per_alert
    return DashboardSummary(
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
        handled_without_human=handled,
        needed_human=needed,
        handled_without_human_rate=ratio(handled, handled + needed),
        analyst_hours_saved=hours_saved(handled, minutes),
        minutes_per_alert=minutes,
    )
