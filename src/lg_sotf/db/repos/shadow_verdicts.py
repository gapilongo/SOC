"""Shadow agreement rows: production's verdict and a candidate's on the same alert (migration 0014).

One row per alert per report (:mod:`lg_sotf.domain.shadow_agreement`).
Rows are append-only, written by ``lg-sotf shadow-run`` after each shadow
run has left shadow mode, and read by ``GET /platform/shadow/reports/{id}``.

:meth:`ShadowVerdictsRepo.production_verdicts` reads what production
decided, from what the pipeline already stores: the first ``decide`` node
event (the routing decision before any analyst input), else ``close`` for
an alert closed without one (suppressed, or closed by triage); the
workflow's planned actions; the alert's LLM usage summary; and the model
and tool time of its stored trace.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from lg_sotf.db.repos._base import Connection, Record, Repository
from lg_sotf.domain.shadow_agreement import MAX_ACTIONS, Comparison, Verdict
from lg_sotf.models.vocabulary import DISPOSITIONS, REQUESTED_BY, ROUTES

REPORT_ID_PATTERN = r"^shr_[0-9a-f]{32}$"
REPORT_ID = re.compile(REPORT_ID_PATTERN)
MAX_REPORT_ALERTS = 2_000
MAX_CANDIDATE_CHARS = 128
MAX_ERROR_CHARS = 128
DECIDED_STATUSES = ("closed", "waiting_human", "waiting_approval")

_INSERT_SQL = """
    INSERT INTO shadow_verdicts (
        tenant_id, alert_id, report_id, run_id, candidate,
        prod_route, prod_disposition, prod_confidence, prod_actions, prod_tokens, prod_cost_usd, prod_latency_ms,
        cand_route, cand_disposition, cand_confidence, cand_actions, cand_tokens, cand_cost_usd, cand_latency_ms,
        cand_error
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
"""

_LIST_SQL = """
    SELECT v.*, a.severity FROM shadow_verdicts v
    JOIN alerts a ON a.tenant_id = v.tenant_id AND a.id = v.alert_id
    WHERE v.tenant_id = $1 AND v.report_id = $2
    ORDER BY v.created_at, v.alert_id
    LIMIT $3
"""

_REPLAYABLE_SQL = """
    SELECT id FROM alerts
    WHERE tenant_id = $1 AND ingested_at >= $2 AND status = ANY($3::text[])
    ORDER BY ingested_at DESC, id
    LIMIT $4
"""

_PRODUCTION_SQL = """
    SELECT a.id AS alert_id, a.severity, a.status, a.disposition, a.confidence,
           a.summary -> 'llm_usage' AS llm_usage, d.data AS decision,
           ARRAY(
               SELECT DISTINCT r.action_type || ':' || r.target FROM response_actions r
               WHERE r.tenant_id = a.tenant_id AND r.alert_id = a.id AND r.requested_by = $3
                 AND r.rollback_of IS NULL
               ORDER BY 1 LIMIT $4
           ) AS actions,
           (SELECT COALESCE(sum(s.latency_ms), 0) FROM investigation_steps s
            WHERE s.tenant_id = a.tenant_id AND s.alert_id = a.id) AS latency_ms
    FROM alerts a
    LEFT JOIN LATERAL (
        SELECT e.data FROM alert_events e
        WHERE e.tenant_id = a.tenant_id AND e.alert_id = a.id AND e.node = 'decide' AND e.event_type = 'node.completed'
        ORDER BY e.ts, e.id LIMIT 1
    ) d ON true
    WHERE a.tenant_id = $1 AND a.id = ANY($2::text[])
"""


class StoredVerdictRow(Record):
    id: UUID
    tenant_id: str
    alert_id: str
    report_id: str
    run_id: Optional[str]
    candidate: str
    severity: str
    prod_route: Optional[str]
    prod_disposition: Optional[str]
    prod_confidence: Optional[float]
    prod_actions: List[str]
    prod_tokens: int
    prod_cost_usd: Decimal
    prod_latency_ms: int
    cand_route: Optional[str]
    cand_disposition: Optional[str]
    cand_confidence: Optional[float]
    cand_actions: List[str]
    cand_tokens: int
    cand_cost_usd: Decimal
    cand_latency_ms: int
    cand_error: Optional[str]
    created_at: datetime

    def comparison(self) -> Comparison:
        return Comparison(
            alert_id=self.alert_id,
            severity=self.severity,
            production=Verdict(
                route=self.prod_route, disposition=self.prod_disposition, confidence=self.prod_confidence,
                actions=tuple(self.prod_actions), tokens=self.prod_tokens, cost_usd=self.prod_cost_usd,
                latency_ms=self.prod_latency_ms,
            ),
            candidate=Verdict(
                route=self.cand_route, disposition=self.cand_disposition, confidence=self.cand_confidence,
                actions=tuple(self.cand_actions), tokens=self.cand_tokens, cost_usd=self.cand_cost_usd,
                latency_ms=self.cand_latency_ms, error=self.cand_error,
            ),
        )


def check_report_id(report_id: str) -> str:
    if not REPORT_ID.fullmatch(report_id):
        raise ValueError("a shadow report id is 'shr_' followed by 32 lowercase hex digits")
    return report_id


def _choice(value: Any, allowed: Sequence[str]) -> Optional[str]:
    return value if isinstance(value, str) and value in allowed else None


def _number(value: Any) -> Decimal:
    """A stored count or amount; anything malformed, negative or not finite reads as 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return Decimal(0)
    try:
        amount = Decimal(str(value))
    except ArithmeticError:
        return Decimal(0)
    return amount if amount.is_finite() and amount > 0 else Decimal(0)


def production_verdict(row: Dict[str, Any]) -> Verdict:
    """What production decided, from one :data:`_PRODUCTION_SQL` row (malformed stored values read as none)."""
    decision, usage = row.get("decision"), row.get("llm_usage")
    if isinstance(decision, dict):
        route, disposition = _choice(decision.get("route"), ROUTES), decision.get("disposition")
    elif row.get("status") == "closed":
        route, disposition = "close", row.get("disposition")
    else:
        route, disposition = None, None
    if not isinstance(usage, dict):
        usage = {}
    return Verdict(
        route=route,
        disposition=_choice(disposition, DISPOSITIONS),
        confidence=row.get("confidence"),
        actions=tuple(row.get("actions") or ()),
        tokens=int(_number(usage.get("total_tokens"))),
        cost_usd=_number(usage.get("cost_usd")),
        latency_ms=int(row.get("latency_ms") or 0),
    )


class ShadowVerdictsRepo(Repository):
    async def append(
        self, tenant_id: str, report_id: str, candidate: str, comparison: Comparison, *,
        run_id: Optional[str] = None, conn: Optional[Connection] = None,
    ) -> None:
        """Store one alert's comparison in ``report_id``."""
        check_report_id(report_id)
        if not 1 <= len(candidate) <= MAX_CANDIDATE_CHARS:
            raise ValueError(f"the candidate label is 1 to {MAX_CANDIDATE_CHARS} characters")
        p, k = comparison.production, comparison.candidate
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                _INSERT_SQL, tenant_id, comparison.alert_id, report_id, run_id, candidate,
                p.route, p.disposition, p.confidence, list(p.actions[:MAX_ACTIONS]), p.tokens, p.cost_usd,
                p.latency_ms,
                k.route, k.disposition, k.confidence, list(k.actions[:MAX_ACTIONS]), k.tokens, k.cost_usd,
                k.latency_ms, (k.error or "")[:MAX_ERROR_CHARS] or None,
            )

    async def list_for_report(
        self, tenant_id: str, report_id: str, *, conn: Optional[Connection] = None
    ) -> List[StoredVerdictRow]:
        """One report's rows (at most :data:`MAX_REPORT_ALERTS`: the replay never stores more); empty if unknown."""
        check_report_id(report_id)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_LIST_SQL, tenant_id, report_id, MAX_REPORT_ALERTS)
        return [StoredVerdictRow.model_validate(dict(r)) for r in rows]

    async def replayable_alerts(
        self, tenant_id: str, since: datetime, *, limit: int, conn: Optional[Connection] = None
    ) -> List[str]:
        """Ids of alerts ingested since ``since`` that production has decided (newest first, at most ``limit``)."""
        if not 1 <= limit <= MAX_REPORT_ALERTS:
            raise ValueError(f"limit must be between 1 and {MAX_REPORT_ALERTS}")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_REPLAYABLE_SQL, tenant_id, since, list(DECIDED_STATUSES), limit)
        return [str(r["id"]) for r in rows]

    async def production_verdicts(
        self, tenant_id: str, alert_ids: Sequence[str], *, conn: Optional[Connection] = None
    ) -> Dict[str, Comparison]:
        """Production's verdict on each alert, by id, as a comparison with an empty candidate side."""
        if len(alert_ids) > MAX_REPORT_ALERTS:
            raise ValueError(f"at most {MAX_REPORT_ALERTS} alerts")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_PRODUCTION_SQL, tenant_id, list(alert_ids), REQUESTED_BY, MAX_ACTIONS)
        return {
            str(r["alert_id"]): Comparison(
                alert_id=str(r["alert_id"]), severity=str(r["severity"]),
                production=production_verdict(dict(r)), candidate=Verdict(),
            )
            for r in rows
        }
