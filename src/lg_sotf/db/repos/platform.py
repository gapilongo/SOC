"""Cross-tenant aggregates for platform admins (the ``lgsotf_platform_*`` functions, migration 0004).

Every method spans tenants. The functions are SECURITY DEFINER, so they work
for the least-privilege runtime role, which cannot read other tenants
itself; the API authorises (platform admins only) and audits every call.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import List, Optional
from uuid import UUID

from lg_sotf.db.pagination import Page, check_limit, decode_cursor_text, paginate
from lg_sotf.db.repos._base import Record, Repository, require_aware, to_models
from lg_sotf.db.tenancy import validate_tenant_id


class TenantStats(Record):
    tenant_id: str
    alerts_24h: int
    alerts_today: int
    last_ingest_at: Optional[datetime]
    open_escalations: int
    overdue_escalations: int
    sla_breaches_24h: int
    llm_cost_mtd: Decimal
    llm_tokens_mtd: int
    users: int
    sources: int


class PlatformEscalation(Record):
    id: str
    tenant_id: str
    tenant_name: str
    tenant_status: str
    alert_id: str
    alert_title: Optional[str]
    alert_severity: Optional[str]
    level: str
    status: str
    priority: int
    reason: str
    assigned_to: Optional[UUID]
    sla_deadline: Optional[datetime]
    sort_due: datetime
    created_at: datetime


class TenantUsage(Record):
    tenant_id: str
    tenant_name: str
    tenant_status: str
    alerts_ingested: int
    alerts_processed: int
    alerts_rejected_quota: int
    llm_calls: int
    llm_input_tokens: int
    llm_output_tokens: int
    llm_cost_usd: Decimal
    active_users: int
    users: int
    sources: int


class PlatformRepo(Repository):
    async def tenant_stats(self, *, now: Optional[datetime] = None) -> List[TenantStats]:
        """Per-tenant activity figures (see migration 0004 for the definitions), by tenant id."""
        require_aware(now, "now")
        async with self._lookup() as c:
            rows = await c.fetch("SELECT * FROM lgsotf_platform_tenant_stats($1)", now or datetime.now(UTC))
        return to_models(TenantStats, rows)

    async def open_escalations(
        self, *, limit: int = 50, cursor: Optional[str] = None, tenant_id: Optional[str] = None
    ) -> Page[PlatformEscalation]:
        """Open and claimed escalations of every tenant, soonest SLA deadline first (none last)."""
        check_limit(limit)
        if tenant_id is not None:
            validate_tenant_id(tenant_id)
        after_due: Optional[datetime] = None
        after_id: Optional[str] = None
        if cursor:
            after_due, after_id = decode_cursor_text(cursor)
        async with self._lookup() as c:
            rows = await c.fetch(
                "SELECT * FROM lgsotf_platform_escalations($1, $2, $3, $4)", limit + 1, after_due, after_id, tenant_id
            )
        return paginate(to_models(PlatformEscalation, rows), limit, lambda e: (e.sort_due, e.id))

    async def usage(self, start_day: date, end_day: date) -> List[TenantUsage]:
        """Invoicing figures per tenant for ``start_day..end_day`` (UTC, inclusive)."""
        if end_day < start_day:
            raise ValueError("end_day must not be before start_day")
        async with self._lookup() as c:
            rows = await c.fetch("SELECT * FROM lgsotf_platform_usage($1, $2)", start_day, end_day)
        return to_models(TenantUsage, rows)
