"""The shadow-mode sink: what each shadow run would have done (migration 0013).

Rows are append-only and written after the run has left shadow mode
(:class:`lg_sotf.core.shadow.ShadowRunner`); no API endpoint reads them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from lg_sotf.db.repos._base import Connection, Record, Repository, to_models
from lg_sotf.security.shadow import MAX_EFFECTS, SHADOW_RUN_PREFIX, EffectOutcome, ShadowEffect

_APPEND_SQL = """
    INSERT INTO shadow_effects (tenant_id, alert_id, run_id, seq, boundary, operation, outcome, detail)
    SELECT $1, $2, $3, e.seq, e.boundary, e.operation, e.outcome, e.detail
    FROM jsonb_to_recordset($4::jsonb) AS e(seq int, boundary text, operation text, outcome text, detail jsonb)
    ORDER BY e.seq
"""


class StoredShadowEffect(Record):
    id: UUID
    tenant_id: str
    alert_id: str
    run_id: str
    seq: int
    boundary: str
    operation: str
    outcome: EffectOutcome
    detail: Dict[str, Any]
    created_at: datetime


class ShadowEffectsRepo(Repository):
    async def append(
        self, tenant_id: str, alert_id: str, run_id: str, effects: Sequence[ShadowEffect], *,
        conn: Optional[Connection] = None,
    ) -> int:
        """Store a shadow run's effects (in ``seq`` order). Returns rows inserted."""
        if not run_id.startswith(SHADOW_RUN_PREFIX):
            raise ValueError("not a shadow run id")
        if not effects:
            return 0
        rows = [
            {"seq": e.seq, "boundary": e.boundary, "operation": e.operation, "outcome": e.outcome, "detail": e.detail}
            for e in effects
        ]
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(_APPEND_SQL, tenant_id, alert_id, run_id, rows)
        return int(str(status).split()[-1])

    async def list_for_run(
        self, tenant_id: str, alert_id: str, run_id: str, *, conn: Optional[Connection] = None
    ) -> List[StoredShadowEffect]:
        """One run's effects in call order (at most ``MAX_EFFECTS``: the sink keeps no more)."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT * FROM shadow_effects WHERE tenant_id = $1 AND alert_id = $2 AND run_id = $3 "
                "ORDER BY seq LIMIT $4",
                tenant_id, alert_id, run_id, MAX_EFFECTS,
            )
        return to_models(StoredShadowEffect, rows)
