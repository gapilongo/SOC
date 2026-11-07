"""The SOC dashboard figures of one tenant over a recent window.

Every figure is read in one read-only ``db.tenant_tx``, so the counts,
response times, queue and LLM cost describe the same snapshot. Caching is the
caller's (``api.routers.dashboard``): :func:`summary` is the same for every
caller of a tenant, :func:`caller_figures` depends on who asks (their role and
their assignments) and is never cached across callers.

Escalation queue figures count active (open or claimed) escalations as of
``generated_at``: ``overdue_escalations`` have a deadline in the past,
``next_sla_deadline`` is the earliest deadline still ahead, and
``open_escalations_by_severity`` groups them by their alert's severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, Mapping, Optional
from uuid import UUID

from lg_sotf.db.repos import Repositories
from lg_sotf.domain.rates import ratio
from lg_sotf.models.vocabulary import RISK_LEVELS
from lg_sotf.services.reporting import hours_saved, resolve_reporting_policy
from lg_sotf.services.response import approval_allowed, resolve_autonomy
from lg_sotf.settings import Settings


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
    open_escalations_by_severity: Dict[str, int]
    overdue_escalations: int
    unassigned_escalations: int
    unassigned_breaching: int
    next_sla_deadline: Optional[datetime]
    pending_approvals_total: int
    pending_approvals_by_risk: Dict[str, int]
    llm_model: Optional[str]


@dataclass(frozen=True)
class CallerFigures:
    """The figures that depend on the caller: what they can approve and what they hold."""

    pending_approvals: int
    my_claimed: int


def llm_model(settings: Settings) -> Optional[str]:
    """The model that writes the analysis verdicts (the deep tier); ``None`` when LLM use is off."""
    return settings.llm.deep.model if settings.llm.enabled else None


async def summary(
    repos: Repositories, tenant_id: str, window_hours: int, *, model: Optional[str] = None
) -> DashboardSummary:
    """The figures of the last ``window_hours``, as of now; ``model`` is reported as ``llm_model``."""
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_hours)
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        counts = await repos.alerts.dashboard_counts(tenant_id, since, conn=conn)
        times = await repos.alerts.response_times(tenant_id, since, conn=conn)
        open_escalations = await repos.escalations.count_active(tenant_id, conn=conn)
        queue = await repos.views.escalation_queue(tenant_id, now, conn=conn)
        pending = await repos.views.pending_actions_by_risk(tenant_id, conn=conn)
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
        open_escalations_by_severity=queue.by_severity,
        overdue_escalations=queue.overdue,
        unassigned_escalations=queue.unassigned,
        unassigned_breaching=queue.unassigned_breaching,
        next_sla_deadline=queue.next_sla_deadline,
        pending_approvals_total=sum(pending.values()),
        pending_approvals_by_risk=pending,
        llm_model=model,
    )


def approvable(
    pending_by_risk: Mapping[str, int], role: Optional[str], tenant_settings: Mapping[str, Any], settings: Settings
) -> int:
    """How many of the pending actions ``role`` may approve (risk vs role, and not disabled by autonomy)."""
    return sum(
        n
        for risk, n in pending_by_risk.items()
        if risk in RISK_LEVELS and approval_allowed(risk, role, resolve_autonomy(risk, tenant_settings, settings))
    )


async def caller_figures(
    repos: Repositories,
    settings: Settings,
    tenant_id: str,
    *,
    role: Optional[str],
    user_id: Optional[UUID],
    pending_by_risk: Mapping[str, int],
) -> CallerFigures:
    """``pending_approvals``: of ``pending_by_risk``, what ``role`` may approve under the tenant's
    current autonomy policy. ``my_claimed``: active escalations assigned to ``user_id`` (0 without one)."""
    tenant = await repos.tenants.get(tenant_id)
    mine = await repos.views.assigned_active(tenant_id, user_id) if user_id is not None else 0
    return CallerFigures(
        pending_approvals=approvable(pending_by_risk, role, tenant.settings, settings), my_claimed=mine
    )
