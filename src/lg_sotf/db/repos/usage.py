"""Per-tenant daily usage counters (``usage_daily``): invoicing and the daily alert quota.

Counters are written in the transaction that causes them (the alert insert,
the run's completion), so a counted alert always exists and a rolled-back
insert is never billed. Days are UTC. Built-in sample alerts
(:data:`SAMPLE_SOURCE_ID`) are never counted.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import List, Optional

from lg_sotf.db.repos._base import Connection, Record, Repository, to_model, to_models

SAMPLE_SOURCE_ID = "demo:samples"


def utc_day(now: Optional[datetime] = None) -> date:
    return (now or datetime.now(UTC)).astimezone(UTC).date()


class UsageDay(Record):
    tenant_id: str
    day: date
    alerts_ingested: int
    alerts_processed: int
    alerts_rejected_quota: int
    quota_exceeded_at: Optional[datetime]
    updated_at: datetime


class UsageRepo(Repository):
    async def add_ingested(
        self, tenant_id: str, count: int, *, day: Optional[date] = None, conn: Optional[Connection] = None
    ) -> None:
        """Count ``count`` newly stored alerts on ``day`` (default: today, UTC)."""
        if count < 0:
            raise ValueError("count must be >= 0")
        if count == 0:
            return
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                """
                INSERT INTO usage_daily AS u (tenant_id, day, alerts_ingested) VALUES ($1, $2, $3)
                ON CONFLICT (tenant_id, day) DO UPDATE SET alerts_ingested = u.alerts_ingested + EXCLUDED.alerts_ingested
                """,
                tenant_id,
                day or utc_day(),
                count,
            )

    async def add_processed(
        self, tenant_id: str, alert_id: str, *, day: Optional[date] = None, conn: Optional[Connection] = None
    ) -> bool:
        """Count one alert whose automated triage finished; sample alerts are skipped. Returns whether it counted."""
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                INSERT INTO usage_daily AS u (tenant_id, day, alerts_processed)
                SELECT $1, $2, 1 FROM alerts a WHERE a.tenant_id = $1 AND a.id = $3 AND a.source_id <> $4
                ON CONFLICT (tenant_id, day) DO UPDATE SET alerts_processed = u.alerts_processed + 1
                """,
                tenant_id,
                day or utc_day(),
                alert_id,
                SAMPLE_SOURCE_ID,
            )
        return status.endswith(" 1")

    async def record_quota_rejection(
        self, tenant_id: str, count: int, *, day: Optional[date] = None, conn: Optional[Connection] = None
    ) -> bool:
        """Count events refused over the daily quota; True for the first refusal of the day (audit once)."""
        async with self._tenant(tenant_id, conn) as c:
            first = await c.fetchval(
                """
                INSERT INTO usage_daily AS u (tenant_id, day, alerts_rejected_quota, quota_exceeded_at)
                VALUES ($1, $2, $3, now())
                ON CONFLICT (tenant_id, day) DO UPDATE SET
                    alerts_rejected_quota = u.alerts_rejected_quota + EXCLUDED.alerts_rejected_quota,
                    quota_exceeded_at = COALESCE(u.quota_exceeded_at, EXCLUDED.quota_exceeded_at)
                RETURNING quota_exceeded_at = now()
                """,
                tenant_id,
                day or utc_day(),
                max(count, 0),
            )
        return bool(first)

    async def get_day(self, tenant_id: str, day: Optional[date] = None, *, conn: Optional[Connection] = None) -> Optional[UsageDay]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM usage_daily WHERE tenant_id = $1 AND day = $2", tenant_id, day or utc_day()
            )
        return to_model(UsageDay, row)

    async def ingested_on(self, tenant_id: str, day: Optional[date] = None, *, conn: Optional[Connection] = None) -> int:
        usage = await self.get_day(tenant_id, day, conn=conn)
        return usage.alerts_ingested if usage is not None else 0

    async def list_range(
        self, tenant_id: str, start_day: date, end_day: date, *, conn: Optional[Connection] = None
    ) -> List[UsageDay]:
        """Rows with ``start_day <= day <= end_day``, oldest first."""
        if end_day < start_day:
            raise ValueError("end_day must not be before start_day")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT * FROM usage_daily WHERE tenant_id = $1 AND day BETWEEN $2 AND $3 ORDER BY day",
                tenant_id,
                start_day,
                end_day,
            )
        return to_models(UsageDay, rows)
