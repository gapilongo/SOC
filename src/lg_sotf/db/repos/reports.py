"""Reporting aggregates: value (automation outcomes), accuracy (AI vs analyst) and detection tuning.

Every query aggregates in SQL over a bounded window and reads through the
tenant-scoped transaction (RLS) with an explicit ``tenant_id`` filter. Each
one is driven by an existing per-tenant time index:

* alerts by ``ingested_at`` (``ix_alerts_ingested``); the first triage verdict
  per alert through ``ix_alert_events_alert`` with partitions before the
  window pruned; human response decisions through
  ``ix_response_actions_created``;
* escalations by ``created_at`` (``ix_escalations_created``);
* SLA breaches from the audit log by ``ts`` (``ix_audit_log_ts``);
* analyst decisions from ``analyst_feedback`` by ``created_at``
  (``ix_analyst_feedback_created``);
* LLM cost from ``llm_usage_daily`` (primary key).

Built-in sample alerts (:data:`SAMPLE_SOURCE_ID`) are left out of every
alert-based figure, as they are out of usage and invoicing.

Alerts waiting for their blind-audit label are left out of the value,
automation and detection figures until they are labelled: per-day and per-rule
counts would otherwise reveal the verdict the blind audit hides.

Callers bound the window (the API allows at most 366 days) and cache the
results; see :mod:`lg_sotf.services.reporting` for the metric definitions.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

from lg_sotf.db.repos._base import Connection, Record, Repository, fetch_one, require_aware
from lg_sotf.db.repos.alerts import SEVERITIES, Alert
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.models.vocabulary import POLICY_APPROVER

# Human involvement in a response: an action that waited for (or got) a person's approval or
# rejection. Policy auto-approvals carry POLICY_APPROVER (lg_sotf.models.vocabulary).
SLA_BREACH_ACTIONS = ("escalation.sla_escalated", "escalation.sla_expired")
MAX_DETECTIONS = 500
MAX_HISTORY_ALERTS = 10_000

_VALUE_SQL = """
WITH human_actions AS (
    SELECT DISTINCT r.alert_id
    FROM response_actions r
    WHERE r.tenant_id = $1 AND r.created_at >= $2
      AND (r.status IN ('awaiting_approval', 'rejected')
           OR (r.approved_by IS NOT NULL AND r.approved_by <> $4))
),
flags AS (
    SELECT (a.ingested_at AT TIME ZONE 'UTC')::date AS day,
           a.status,
           a.disposition,
           a.ingested_at,
           a.closed_at,
           a.summary->>'analyst_decision' IS NOT NULL AS analyst_decided,
           h.alert_id IS NOT NULL AS human_action,
           a.summary->>'escalation_id' IS NOT NULL AS escalated,
           a.summary->>'close_reason' AS close_reason,
           COALESCE(a.summary->>'dry_run' = 'true', false) AS dry_run,
           a.summary->'suppressed_by'->>'type' AS suppressed_by,
           COALESCE(a.summary->>'escalation_attached' = 'true', false) AS grouped,
           v.ts AS triage_at
    FROM alerts a
    LEFT JOIN human_actions h ON h.alert_id = a.id
    LEFT JOIN LATERAL (
        SELECT min(e.ts) AS ts
        FROM alert_events e
        WHERE e.tenant_id = a.tenant_id AND e.alert_id = a.id AND e.ts >= $2
          AND e.event_type = 'node.completed' AND e.node = 'triage'
    ) v ON true
    WHERE a.tenant_id = $1 AND a.ingested_at >= $2 AND a.ingested_at < $3 AND a.source_id <> $5
      AND NOT EXISTS (SELECT 1 FROM blind_audit_items b WHERE b.tenant_id = a.tenant_id AND b.alert_id = a.id
                      AND b.label IS NULL)
),
classified AS (
    SELECT f.*,
           f.status = 'closed' AND NOT f.analyst_decided AND NOT f.human_action AS handled,
           f.analyst_decided OR f.human_action OR f.status IN ('waiting_human', 'waiting_approval')
               OR (f.escalated AND f.status <> 'closed') AS needed,
           LEAST(f.triage_at, f.closed_at) AS verdict_at
    FROM flags f
)
SELECT day,
       count(*) AS ingested,
       count(*) FILTER (WHERE handled) AS handled_without_human,
       count(*) FILTER (WHERE needed) AS needed_human,
       count(*) FILTER (WHERE handled AND disposition = 'benign') AS auto_closed_benign,
       count(*) FILTER (WHERE handled AND disposition = 'malicious' AND close_reason = 'policy:response'
                        AND NOT dry_run) AS auto_contained,
       count(*) FILTER (WHERE handled AND disposition = 'malicious' AND close_reason = 'policy:response'
                        AND dry_run) AS auto_contained_dry_run,
       count(*) FILTER (WHERE escalated) AS escalated,
       count(*) FILTER (WHERE analyst_decided) AS human_decided,
       count(*) FILTER (WHERE suppressed_by = 'suppression_rule') AS suppressed_by_rule,
       count(*) FILTER (WHERE suppressed_by = 'verdict_cache') AS verdict_cache_hits,
       count(*) FILTER (WHERE grouped) AS grouped_into_escalation,
       count(*) FILTER (WHERE status = 'closed') AS resolved,
       COALESCE(sum(GREATEST(extract(epoch FROM closed_at - ingested_at), 0))
                FILTER (WHERE status = 'closed'), 0)::float8 AS resolve_seconds,
       count(*) FILTER (WHERE handled) AS resolved_auto,
       COALESCE(sum(GREATEST(extract(epoch FROM closed_at - ingested_at), 0))
                FILTER (WHERE handled), 0)::float8 AS resolve_auto_seconds,
       count(*) FILTER (WHERE status = 'closed' AND analyst_decided) AS resolved_human,
       COALESCE(sum(GREATEST(extract(epoch FROM closed_at - ingested_at), 0))
                FILTER (WHERE status = 'closed' AND analyst_decided), 0)::float8 AS resolve_human_seconds,
       count(verdict_at) AS verdicts,
       COALESCE(sum(GREATEST(extract(epoch FROM verdict_at - ingested_at), 0))
                FILTER (WHERE verdict_at IS NOT NULL), 0)::float8 AS verdict_seconds
FROM classified
GROUP BY day
ORDER BY day
"""

# The dashboard's two automation tiles: the value report's handled/needed split without the
# per-day buckets and duration sums.
_AUTOMATION_SQL = """
WITH human_actions AS (
    SELECT DISTINCT r.alert_id
    FROM response_actions r
    WHERE r.tenant_id = $1 AND r.created_at >= $2
      AND (r.status IN ('awaiting_approval', 'rejected')
           OR (r.approved_by IS NOT NULL AND r.approved_by <> $4))
),
flags AS (
    SELECT a.status,
           a.summary->>'analyst_decision' IS NOT NULL AS analyst_decided,
           h.alert_id IS NOT NULL AS human_action,
           a.summary->>'escalation_id' IS NOT NULL AS escalated
    FROM alerts a
    LEFT JOIN human_actions h ON h.alert_id = a.id
    WHERE a.tenant_id = $1 AND a.ingested_at >= $2 AND a.ingested_at < $3 AND a.source_id <> $5
      AND NOT EXISTS (SELECT 1 FROM blind_audit_items b WHERE b.tenant_id = a.tenant_id AND b.alert_id = a.id
                      AND b.label IS NULL)
)
SELECT count(*) FILTER (WHERE status = 'closed' AND NOT analyst_decided AND NOT human_action) AS handled,
       count(*) FILTER (WHERE analyst_decided OR human_action OR status IN ('waiting_human', 'waiting_approval')
                        OR (escalated AND status <> 'closed')) AS needed
FROM flags
"""

_ESCALATIONS_SQL = """
SELECT (created_at AT TIME ZONE 'UTC')::date AS day,
       count(*) AS escalations,
       count(claimed_at) AS acknowledged,
       COALESCE(sum(GREATEST(extract(epoch FROM claimed_at - created_at), 0))
                FILTER (WHERE claimed_at IS NOT NULL), 0)::float8 AS ack_seconds
FROM escalations
WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
GROUP BY 1
ORDER BY 1
"""

_SLA_SQL = """
SELECT (ts AT TIME ZONE 'UTC')::date AS day, count(*) AS breaches
FROM audit_log
WHERE tenant_id = $1 AND ts >= $2 AND ts < $3 AND action = ANY($4::text[])
GROUP BY 1
ORDER BY 1
"""

_SLA_DISTINCT_SQL = """
SELECT count(DISTINCT resource_id)
FROM audit_log
WHERE tenant_id = $1 AND ts >= $2 AND ts < $3 AND action = ANY($4::text[])
"""

_COST_SQL = """
SELECT day, COALESCE(sum(cost_usd), 0) AS cost_usd
FROM llm_usage_daily
WHERE tenant_id = $1 AND day BETWEEN $2 AND $3
GROUP BY day
ORDER BY day
"""

# One row per group of (final decision, AI verdict at the first escalation, score band, model).
# The AI verdict is the analysis verdict the analyst saw on the alert's FIRST escalation (before
# any needs_more_info round), the decision the alert's latest one other than needs_more_info.
_ACCURACY_SQL = """
WITH final AS (
    SELECT DISTINCT ON (f.alert_id) f.alert_id, f.decision
    FROM analyst_feedback f
    WHERE f.tenant_id = $1 AND f.created_at >= $2 AND f.created_at < $3
      AND f.decision <> 'needs_more_info'
    ORDER BY f.alert_id, f.created_at DESC, f.id DESC
),
scored AS (
    SELECT fin.decision,
           a.severity,
           fe.summary->>'verdict' AS verdict,
           CASE WHEN jsonb_typeof(fe.summary->'threat_score') = 'number' THEN (fe.summary->>'threat_score')::float8
                WHEN jsonb_typeof(fe.summary->'confidence') = 'number' THEN (fe.summary->>'confidence')::float8
           END AS score,
           a.summary->'llm_usage'->'by_agent'->'analysis'->>'provider' AS analysis_provider,
           a.summary->'llm_usage'->'by_agent'->'analysis'->>'model' AS analysis_model,
           a.summary->'llm_usage'->'by_agent'->'triage'->>'provider' AS triage_provider,
           a.summary->'llm_usage'->'by_agent'->'triage'->>'model' AS triage_model,
           CASE WHEN jsonb_typeof(a.summary->'llm_usage'->'calls') = 'number'
                THEN (a.summary->'llm_usage'->>'calls')::float8 > 0 ELSE false END AS llm_used
    FROM final fin
    JOIN alerts a ON a.tenant_id = $1 AND a.id = fin.alert_id AND a.source_id <> $6
    CROSS JOIN LATERAL (
        SELECT e.summary FROM escalations e
        WHERE e.tenant_id = $1 AND e.alert_id = fin.alert_id
        ORDER BY e.created_at, e.id
        LIMIT 1
    ) fe
)
SELECT decision,
       CASE WHEN verdict IN ('malicious', 'benign', 'inconclusive') THEN verdict END AS verdict,
       CASE WHEN score IS NULL THEN NULL WHEN score >= $5 THEN 'high' WHEN score < $4 THEN 'low' ELSE 'mid' END
           AS score_band,
       left(analysis_provider, 64) AS analysis_provider,
       left(analysis_model, 128) AS analysis_model,
       left(triage_provider, 64) AS triage_provider,
       left(triage_model, 128) AS triage_model,
       llm_used,
       count(*) AS n
FROM scored
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
"""

_DETECTIONS_SQL = """
SELECT a.source_id,
       CASE WHEN NULLIF(a.normalized->>'rule_name', '') IS NOT NULL THEN 'rule_name' ELSE 'title' END AS rule_field,
       COALESCE(NULLIF(a.normalized->>'rule_name', ''), a.title) AS rule,
       count(*) AS volume,
       count(*) FILTER (WHERE a.disposition IS NOT NULL) AS decided,
       count(*) FILTER (WHERE a.disposition = 'benign') AS benign,
       count(*) FILTER (WHERE a.disposition = 'malicious') AS malicious,
       count(*) FILTER (WHERE a.status = 'closed' AND a.disposition = 'benign'
                        AND a.summary->>'analyst_decision' IS NULL) AS auto_closed,
       count(*) FILTER (WHERE a.summary->>'analyst_decision' = 'false_positive') AS analyst_false_positive,
       count(*) FILTER (WHERE a.summary->>'analyst_decision' = 'benign_positive') AS analyst_benign_positive,
       count(*) FILTER (WHERE a.summary->>'analyst_decision' = 'true_positive') AS analyst_true_positive,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY s.rank) AS median_severity_rank,
       max(s.rank) AS max_severity_rank,
       max(s.rank) FILTER (WHERE a.summary->>'analyst_decision' IN ('false_positive', 'benign_positive'))
           AS max_confirmed_benign_rank
FROM alerts a
CROSS JOIN LATERAL (SELECT array_position($4::text[], a.severity) - 1 AS rank) s
WHERE a.tenant_id = $1 AND a.ingested_at >= $2 AND a.ingested_at < $3 AND a.source_id <> $5
  AND NOT EXISTS (SELECT 1 FROM blind_audit_items b WHERE b.tenant_id = a.tenant_id AND b.alert_id = a.id
                  AND b.label IS NULL)
  {filter}
GROUP BY 1, 2, 3
ORDER BY volume DESC, a.source_id, rule
LIMIT {limit}
"""

_DETECTION_FILTER = """
  AND a.source_id = $6
  AND COALESCE(NULLIF(a.normalized->>'rule_name', ''), a.title) = $7
  AND (CASE WHEN NULLIF(a.normalized->>'rule_name', '') IS NOT NULL THEN 'rule_name' ELSE 'title' END) = $8
"""

# Same labelling as docs/tools/export_feedback.sql: the alert's latest decision other than needs_more_info.
_HISTORY_SQL = """
WITH final AS (
    SELECT DISTINCT ON (f.alert_id) f.alert_id, f.decision, f.created_at, f.id
    FROM analyst_feedback f
    WHERE f.tenant_id = $1 AND f.created_at >= $2
    ORDER BY f.alert_id, (f.decision = 'needs_more_info'), f.created_at DESC, f.id DESC
)
SELECT a.*, fin.decision AS analyst_decision, fin.created_at AS decided_at
FROM final fin
JOIN alerts a ON a.tenant_id = $1 AND a.id = fin.alert_id
WHERE fin.decision <> 'needs_more_info' AND a.source_id <> $4
ORDER BY fin.created_at, fin.id
LIMIT $3
"""


class ValueDayRow(Record):
    """Counts and duration sums for alerts ingested on ``day`` (UTC)."""

    day: date
    ingested: int = 0
    handled_without_human: int = 0
    needed_human: int = 0
    auto_closed_benign: int = 0
    auto_contained: int = 0
    auto_contained_dry_run: int = 0
    escalated: int = 0
    human_decided: int = 0
    suppressed_by_rule: int = 0
    verdict_cache_hits: int = 0
    grouped_into_escalation: int = 0
    resolved: int = 0
    resolve_seconds: float = 0.0
    resolved_auto: int = 0
    resolve_auto_seconds: float = 0.0
    resolved_human: int = 0
    resolve_human_seconds: float = 0.0
    verdicts: int = 0
    verdict_seconds: float = 0.0


class EscalationDayRow(Record):
    day: date
    escalations: int = 0
    acknowledged: int = 0
    ack_seconds: float = 0.0


class AccuracyGroupRow(Record):
    decision: str
    verdict: Optional[str]
    score_band: Optional[str]
    analysis_provider: Optional[str]
    analysis_model: Optional[str]
    triage_provider: Optional[str]
    triage_model: Optional[str]
    llm_used: bool
    n: int


class DetectionRow(Record):
    source_id: str
    rule_field: str
    rule: str
    volume: int
    decided: int
    benign: int
    malicious: int
    auto_closed: int
    analyst_false_positive: int
    analyst_benign_positive: int
    analyst_true_positive: int
    median_severity_rank: Optional[int]
    max_severity_rank: Optional[int]
    max_confirmed_benign_rank: Optional[int]


class DecidedAlert(Record):
    """An alert with the analyst's final decision (backtest input)."""

    alert: Alert
    decision: str
    decided_at: datetime


class ReportsRepo(Repository):
    async def value_daily(
        self, tenant_id: str, start: datetime, end: datetime, *, conn: Optional[Connection] = None
    ) -> List[ValueDayRow]:
        """Outcome counts per UTC ingestion day for alerts ingested in ``[start, end)``."""
        _window(start, end)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_VALUE_SQL, tenant_id, start, end, POLICY_APPROVER, SAMPLE_SOURCE_ID)
        return [ValueDayRow.model_validate(dict(r)) for r in rows]

    async def automation_counts(
        self, tenant_id: str, start: datetime, end: datetime, *, conn: Optional[Connection] = None
    ) -> Tuple[int, int]:
        """``(handled_without_human, needed_human)`` for alerts ingested in ``[start, end)``."""
        _window(start, end)
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(c, _AUTOMATION_SQL, tenant_id, start, end, POLICY_APPROVER, SAMPLE_SOURCE_ID)
        return int(row["handled"]), int(row["needed"])

    async def escalations_daily(
        self, tenant_id: str, start: datetime, end: datetime, *, conn: Optional[Connection] = None
    ) -> List[EscalationDayRow]:
        """Escalations created per UTC day in ``[start, end)`` and their time to acknowledge."""
        _window(start, end)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_ESCALATIONS_SQL, tenant_id, start, end)
        return [EscalationDayRow.model_validate(dict(r)) for r in rows]

    async def sla_breaches_daily(
        self, tenant_id: str, start: datetime, end: datetime, *, conn: Optional[Connection] = None
    ) -> Tuple[Dict[date, int], int]:
        """SLA sweep actions (level raised or expired) per UTC day, and distinct escalations breached."""
        _window(start, end)
        actions = list(SLA_BREACH_ACTIONS)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_SLA_SQL, tenant_id, start, end, actions)
            distinct = await c.fetchval(_SLA_DISTINCT_SQL, tenant_id, start, end, actions)
        return {r["day"]: int(r["breaches"]) for r in rows}, int(distinct or 0)

    async def llm_cost_daily(
        self, tenant_id: str, start_day: date, end_day: date, *, conn: Optional[Connection] = None
    ) -> Dict[date, Decimal]:
        """LLM cost per day for ``start_day <= day <= end_day`` (every model and agent)."""
        if end_day < start_day:
            raise ValueError("end_day must not be before start_day")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_COST_SQL, tenant_id, start_day, end_day)
        return {r["day"]: Decimal(r["cost_usd"]) for r in rows}

    async def accuracy_groups(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        low_score: float,
        high_score: float,
        conn: Optional[Connection] = None,
    ) -> List[AccuracyGroupRow]:
        """AI verdict against the analyst's final decision, grouped, for decisions made in ``[start, end)``.

        ``score_band`` classifies the escalation's threat score (or its
        confidence when no analysis ran): ``low`` below ``low_score``,
        ``high`` from ``high_score``, ``mid`` between.
        """
        _window(start, end)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                _ACCURACY_SQL, tenant_id, start, end, float(low_score), float(high_score), SAMPLE_SOURCE_ID
            )
        return [AccuracyGroupRow.model_validate(dict(r)) for r in rows]

    async def detections(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        limit: int = 200,
        conn: Optional[Connection] = None,
    ) -> List[DetectionRow]:
        """Per (source, rule) outcome counts for alerts ingested in ``[start, end)``, busiest first."""
        _window(start, end)
        if not 1 <= limit <= MAX_DETECTIONS:
            raise ValueError(f"limit must be between 1 and {MAX_DETECTIONS}")
        # ``filter`` and ``limit`` are fixed SQL text / a validated int, never caller strings.
        sql = _DETECTIONS_SQL.format(filter="", limit=int(limit))
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, tenant_id, start, end, list(SEVERITIES), SAMPLE_SOURCE_ID)
        return [DetectionRow.model_validate(dict(r)) for r in rows]

    async def detection(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        *,
        source_id: str,
        rule_field: str,
        rule: str,
        conn: Optional[Connection] = None,
    ) -> Optional[DetectionRow]:
        """One detection's row (same definitions as :meth:`detections`), or ``None`` without alerts."""
        _window(start, end)
        if rule_field not in ("rule_name", "title"):
            raise ValueError("rule_field must be 'rule_name' or 'title'")
        sql = _DETECTIONS_SQL.format(filter=_DETECTION_FILTER, limit=1)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                sql, tenant_id, start, end, list(SEVERITIES), SAMPLE_SOURCE_ID, source_id, rule, rule_field
            )
        return None if row is None else DetectionRow.model_validate(dict(row))

    async def decided_alerts(
        self, tenant_id: str, since: datetime, *, limit: int = 1_000, conn: Optional[Connection] = None
    ) -> List[DecidedAlert]:
        """Alerts analysts decided since ``since`` (final decision other than needs_more_info), oldest first."""
        require_aware(since, "since")
        if not 1 <= limit <= MAX_HISTORY_ALERTS:
            raise ValueError(f"limit must be between 1 and {MAX_HISTORY_ALERTS}")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_HISTORY_SQL, tenant_id, since, limit, SAMPLE_SOURCE_ID)
        out: List[DecidedAlert] = []
        for r in rows:
            data = dict(r)
            decision = data.pop("analyst_decision")
            decided_at = data.pop("decided_at")
            out.append(DecidedAlert(alert=Alert.model_validate(data), decision=decision, decided_at=decided_at))
        return out


def _window(start: datetime, end: datetime) -> None:
    require_aware(start, "start")
    require_aware(end, "end")
    if end <= start:
        raise ValueError("end must be after start")

