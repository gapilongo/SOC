"""Daily LLM usage and cost per (tenant, day, model, agent)."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal
from typing import Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.db.repos._base import Connection, Record, Repository, to_models
from lg_sotf.db.tenancy import validate_tenant_id

_COUNTERS = (
    "calls",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "refusals",
    "errors",
)


class LLMUsageDelta(BaseModel):
    """Usage to add to a day's totals."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    day: date
    model: str = Field(min_length=1, max_length=200)
    agent: str = Field(min_length=1, max_length=100)
    calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    cost_usd: Decimal = Field(default=Decimal(0), ge=0)
    refusals: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)


class LLMUsageDay(Record):
    tenant_id: str
    day: date
    model: str
    agent: str
    calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: Decimal
    refusals: int
    errors: int
    updated_at: datetime


class LLMUsageTotals(Record):
    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal


Key = Tuple[date, str, str]


class LLMUsageRepo(Repository):
    async def upsert_daily(self, rows: Sequence[LLMUsageDelta]) -> int:
        """Add usage deltas to the daily totals. Returns the number of rows written.

        All-or-nothing: every tenant's deltas are written in one transaction
        (re-scoped to each tenant in turn, so RLS still checks every row). If
        this raises, nothing was added and the caller can retry the whole
        buffer without double counting. Deltas for the same key are summed
        first, and rows are written in a fixed order so concurrent flushes
        cannot deadlock.
        """
        per_tenant: Dict[str, Dict[Key, Dict[str, object]]] = defaultdict(dict)
        for r in rows:
            validate_tenant_id(r.tenant_id)
            key = (r.day, r.model, r.agent)
            acc = per_tenant[r.tenant_id].setdefault(key, {**{c: 0 for c in _COUNTERS}, "cost_usd": Decimal(0)})
            for counter in _COUNTERS:
                acc[counter] = int(acc[counter]) + getattr(r, counter)  # type: ignore[call-overload]
            acc["cost_usd"] = Decimal(acc["cost_usd"]) + r.cost_usd  # type: ignore[arg-type]
        if not per_tenant:
            return 0
        tenants = sorted(per_tenant)
        written = 0
        async with self._tenant(tenants[0]) as c:
            for tenant_id in tenants:
                await self._switch_tenant(c, tenant_id)
                totals = per_tenant[tenant_id]
                keys = sorted(totals)
                cols = {col: [totals[k][col] for k in keys] for col in (*_COUNTERS, "cost_usd")}
                status = await c.execute(
                    """
                    INSERT INTO llm_usage_daily AS u (
                        tenant_id, day, model, agent, calls, input_tokens, output_tokens,
                        cache_read_tokens, cache_write_tokens, cost_usd, refusals, errors
                    )
                    SELECT $1, x.day, x.model, x.agent, x.calls, x.input_tokens, x.output_tokens,
                           x.cache_read_tokens, x.cache_write_tokens, x.cost_usd, x.refusals, x.errors
                    FROM unnest($2::date[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[],
                                $8::bigint[], $9::bigint[], $10::numeric[], $11::bigint[], $12::bigint[])
                         AS x(day, model, agent, calls, input_tokens, output_tokens, cache_read_tokens,
                              cache_write_tokens, cost_usd, refusals, errors)
                    ON CONFLICT (tenant_id, day, model, agent) DO UPDATE SET
                        calls = u.calls + EXCLUDED.calls,
                        input_tokens = u.input_tokens + EXCLUDED.input_tokens,
                        output_tokens = u.output_tokens + EXCLUDED.output_tokens,
                        cache_read_tokens = u.cache_read_tokens + EXCLUDED.cache_read_tokens,
                        cache_write_tokens = u.cache_write_tokens + EXCLUDED.cache_write_tokens,
                        cost_usd = u.cost_usd + EXCLUDED.cost_usd,
                        refusals = u.refusals + EXCLUDED.refusals,
                        errors = u.errors + EXCLUDED.errors
                    """,
                    tenant_id,
                    [k[0] for k in keys],
                    [k[1] for k in keys],
                    [k[2] for k in keys],
                    cols["calls"],
                    cols["input_tokens"],
                    cols["output_tokens"],
                    cols["cache_read_tokens"],
                    cols["cache_write_tokens"],
                    cols["cost_usd"],
                    cols["refusals"],
                    cols["errors"],
                )
                written += int(status.split()[-1])
        return written

    async def list_range(
        self,
        tenant_id: str,
        start_day: date,
        end_day: date,
        *,
        conn: Optional[Connection] = None,
    ) -> List[LLMUsageDay]:
        """Rows with ``start_day <= day <= end_day``, oldest first."""
        if end_day < start_day:
            raise ValueError("end_day must not be before start_day")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM llm_usage_daily
                WHERE tenant_id = $1 AND day BETWEEN $2 AND $3
                ORDER BY day, model, agent
                """,
                tenant_id,
                start_day,
                end_day,
            )
        return to_models(LLMUsageDay, rows)

    async def day_tokens(self, tenant_id: str, day: date, *, conn: Optional[Connection] = None) -> int:
        """All tokens recorded for the tenant on ``day`` (what the daily token budget counts)."""
        async with self._tenant(tenant_id, conn) as c:
            value = await c.fetchval(
                """
                SELECT COALESCE(sum(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens), 0)::bigint
                FROM llm_usage_daily WHERE tenant_id = $1 AND day = $2
                """,
                tenant_id,
                day,
            )
        return int(value or 0)

    async def day_totals(self, tenant_id: str, day: date, *, conn: Optional[Connection] = None) -> LLMUsageTotals:
        """Totals across models and agents for one day (daily token budget checks)."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                SELECT COALESCE(sum(calls), 0)::bigint AS calls,
                       COALESCE(sum(input_tokens), 0)::bigint AS input_tokens,
                       COALESCE(sum(output_tokens), 0)::bigint AS output_tokens,
                       COALESCE(sum(cost_usd), 0)::numeric(14, 6) AS cost_usd
                FROM llm_usage_daily
                WHERE tenant_id = $1 AND day = $2
                """,
                tenant_id,
                day,
            )
        return LLMUsageTotals.model_validate(dict(row))
