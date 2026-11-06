"""Analyst feedback on escalation decisions (one per escalation)."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    fetch_one,
    require_aware,
    to_model,
    to_models,
)
from lg_sotf.db.repos.escalations import DECISIONS


class Feedback(Record):
    id: str
    tenant_id: str
    escalation_id: str
    alert_id: str
    user_id: Optional[UUID]
    decision: str
    confidence: Optional[int]
    notes: Optional[str]
    triage_correct: Optional[bool]
    correlation_helpful: Optional[bool]
    analysis_accurate: Optional[bool]
    review_duration_s: Optional[int]
    created_at: datetime


class FeedbackStats(Record):
    total: int
    by_decision: Dict[str, int]
    triage_accuracy: Optional[float]
    correlation_helpful_rate: Optional[float]
    analysis_accuracy: Optional[float]
    avg_review_duration_s: Optional[float]
    # How many feedback rows answered each question (the rates' denominators).
    triage_rated: int = 0
    correlation_rated: int = 0
    analysis_rated: int = 0


class FeedbackRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        escalation_id: str,
        alert_id: str,
        decision: str,
        *,
        user_id: Optional[UUID] = None,
        confidence: Optional[int] = None,
        notes: Optional[str] = None,
        triage_correct: Optional[bool] = None,
        correlation_helpful: Optional[bool] = None,
        analysis_accurate: Optional[bool] = None,
        review_duration_s: Optional[int] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[Feedback, bool]:
        """Record feedback; idempotent per escalation. Returns ``(feedback, created)``."""
        check_choice(decision, DECISIONS, "decision")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO analyst_feedback (
                    tenant_id, escalation_id, alert_id, user_id, decision, confidence, notes,
                    triage_correct, correlation_helpful, analysis_accurate, review_duration_s
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (tenant_id, escalation_id) DO NOTHING
                RETURNING *
                """,
                tenant_id,
                escalation_id,
                alert_id,
                user_id,
                decision,
                confidence,
                notes,
                triage_correct,
                correlation_helpful,
                analysis_accurate,
                review_duration_s,
            )
            if row is not None:
                return Feedback.model_validate(dict(row)), True
            row = await fetch_one(
                c,
                "SELECT * FROM analyst_feedback WHERE tenant_id = $1 AND escalation_id = $2",
                tenant_id,
                escalation_id,
            )
        return Feedback.model_validate(dict(row)), False

    async def get_for_escalation(
        self, tenant_id: str, escalation_id: str, *, conn: Optional[Connection] = None
    ) -> Optional[Feedback]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM analyst_feedback WHERE tenant_id = $1 AND escalation_id = $2",
                tenant_id,
                escalation_id,
            )
        return to_model(Feedback, row)

    async def list_for_alert(
        self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None
    ) -> List[Feedback]:
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM analyst_feedback
                WHERE tenant_id = $1 AND alert_id = $2
                ORDER BY created_at, id
                """,
                tenant_id,
                alert_id,
            )
        return to_models(Feedback, rows)

    async def decision_stats(
        self,
        tenant_id: str,
        since: datetime,
        *,
        until: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> FeedbackStats:
        """Decision counts and agent-quality rates for feedback created in ``[since, until)``."""
        require_aware(since, "since")
        require_aware(until, "until")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                SELECT
                    count(*) AS total,
                    avg(triage_correct::int) AS triage_accuracy,
                    avg(correlation_helpful::int) AS correlation_helpful_rate,
                    avg(analysis_accurate::int) AS analysis_accuracy,
                    avg(review_duration_s) AS avg_review_duration_s,
                    count(triage_correct) AS triage_rated,
                    count(correlation_helpful) AS correlation_rated,
                    count(analysis_accurate) AS analysis_rated,
                    COALESCE(
                        (SELECT jsonb_object_agg(decision, n) FROM (
                            SELECT decision, count(*) AS n FROM analyst_feedback
                            WHERE tenant_id = $1 AND created_at >= $2
                              AND ($3::timestamptz IS NULL OR created_at < $3)
                            GROUP BY decision
                        ) d),
                        '{}'::jsonb
                    ) AS by_decision
                FROM analyst_feedback
                WHERE tenant_id = $1 AND created_at >= $2 AND ($3::timestamptz IS NULL OR created_at < $3)
                """,
                tenant_id,
                since,
                until,
            )

        def _f(value: object) -> Optional[float]:
            return None if value is None else float(value)  # type: ignore[arg-type]

        return FeedbackStats(
            total=row["total"],
            by_decision={k: int(v) for k, v in row["by_decision"].items()},
            triage_accuracy=_f(row["triage_accuracy"]),
            correlation_helpful_rate=_f(row["correlation_helpful_rate"]),
            analysis_accuracy=_f(row["analysis_accuracy"]),
            avg_review_duration_s=_f(row["avg_review_duration_s"]),
            triage_rated=row["triage_rated"],
            correlation_rated=row["correlation_rated"],
            analysis_rated=row["analysis_rated"],
        )
