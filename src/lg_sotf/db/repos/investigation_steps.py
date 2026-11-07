"""The investigation trace store: one row per LLM call and tool call of a run (migration 0011).

Rows are append-only. :meth:`InvestigationStepsRepo.append` numbers a batch
after the steps the run already has, in one statement, so the nodes of a
run (which execute one at a time) get consecutive ``step_index`` values.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence
from uuid import UUID

from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import Connection, Record, Repository, require_aware, to_models
from lg_sotf.models.trace import NewTraceStep

MAX_STEPS_LISTED = 5_000

# Rows as ``NewTraceStep.model_dump(mode="json")`` plus their position ``ord`` in $4, numbered after the run's
# last step.
_APPEND_SQL = """
    INSERT INTO investigation_steps
        (tenant_id, alert_id, run_id, step_index, agent, kind, prompt_name, prompt_hash, provider, model, tool,
         input_hash, output_hash, result_digest, outcome, error_type, input_tokens, output_tokens,
         cache_read_tokens, cache_write_tokens, latency_ms, started_at)
    SELECT $1, $2, $3, base.first_index + s.ord, s.agent, s.kind, s.prompt_name, s.prompt_hash, s.provider, s.model,
           s.tool, s.input_hash, s.output_hash, s.result_digest, s.outcome, s.error_type, s.input_tokens,
           s.output_tokens, s.cache_read_tokens, s.cache_write_tokens, s.latency_ms, s.started_at
    FROM jsonb_to_recordset($4::jsonb) AS s(
        agent text, kind text, prompt_name text, prompt_hash text, provider text, model text, tool text,
        input_hash text, output_hash text, result_digest jsonb, outcome text, error_type text, input_tokens int,
        output_tokens int, cache_read_tokens int, cache_write_tokens int, latency_ms int, started_at timestamptz,
        ord int
    ),
    (SELECT COALESCE(max(step_index) + 1, 0) AS first_index FROM investigation_steps
     WHERE tenant_id = $1 AND alert_id = $2 AND run_id = $3) AS base
    ORDER BY s.ord
"""


class TraceStep(NewTraceStep, Record):
    """A stored step."""

    id: UUID
    tenant_id: str
    alert_id: str
    run_id: str
    step_index: int
    created_at: datetime


class InvestigationStepsRepo(Repository):
    async def append(
        self,
        tenant_id: str,
        alert_id: str,
        run_id: str,
        steps: Sequence[NewTraceStep],
        *,
        conn: Optional[Connection] = None,
    ) -> int:
        """Append ``steps`` (in order) after the run's existing steps. Returns rows inserted."""
        if not steps:
            return 0
        for step in steps:
            require_aware(step.started_at, "started_at")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                _APPEND_SQL, tenant_id, alert_id, run_id,
                [{**s.model_dump(mode="json"), "ord": i} for i, s in enumerate(steps)],
            )
        return int(str(status).split()[-1])

    async def list_for_alert(
        self, tenant_id: str, alert_id: str, *, limit: int = 1_000, conn: Optional[Connection] = None
    ) -> List[TraceStep]:
        """The alert's steps, oldest run first, each run in step order."""
        check_limit(limit, MAX_STEPS_LISTED)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM investigation_steps
                WHERE tenant_id = $1 AND alert_id = $2
                ORDER BY min(created_at) OVER (PARTITION BY run_id), run_id, step_index
                LIMIT $3
                """,
                tenant_id,
                alert_id,
                limit,
            )
        return to_models(TraceStep, rows)
