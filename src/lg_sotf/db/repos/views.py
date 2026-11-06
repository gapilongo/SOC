"""Console read models: queue figures, view counts and the context an escalation row shows.

Small aggregates and lookups for the analyst console that do not belong to
one aggregate's repository: escalations joined with their alert, the
approval queue by risk, alert view counts, owner e-mail addresses. Every
query runs in the tenant-scoped transaction (RLS) with an explicit
``tenant_id`` filter, and every lookup is bounded by its input
(:data:`MAX_LOOKUP_IDS`).

Indexes: active escalations through ``ux_escalations_active_per_alert`` /
``ix_escalations_status``; pending actions through
``ix_response_actions_status``; alert status counts through
``ix_alerts_status`` (closed alerts are counted only inside a ``closed_at``
window, never all-time).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Sequence
from uuid import UUID

from lg_sotf.db.repos._base import Connection, Record, Repository, fetch_int, fetch_one, require_aware
from lg_sotf.models.vocabulary import ALERT_STATUSES

MAX_LOOKUP_IDS = 500
# Alert statuses counted all-time by alert_view_counts: every one but ``closed``.
OPEN_ALERT_STATUSES = tuple(s for s in ALERT_STATUSES if s != "closed")

_QUEUE_SQL = """
SELECT count(*) FILTER (WHERE sla_deadline < $2) AS overdue,
       count(*) FILTER (WHERE assigned_to IS NULL) AS unassigned,
       count(*) FILTER (WHERE assigned_to IS NULL AND sla_deadline < $2) AS unassigned_breaching,
       min(sla_deadline) FILTER (WHERE sla_deadline >= $2) AS next_sla_deadline
FROM escalations
WHERE tenant_id = $1 AND status IN ('open', 'claimed')
"""
_ACTIVE_BY_SEVERITY_SQL = """
SELECT a.severity, count(*)::int AS n
FROM escalations e
JOIN alerts a ON a.tenant_id = e.tenant_id AND a.id = e.alert_id
WHERE e.tenant_id = $1 AND e.status IN ('open', 'claimed')
GROUP BY a.severity
"""
_ASSIGNED_ACTIVE_SQL = """
SELECT count(*)::int FROM escalations
WHERE tenant_id = $1 AND status IN ('open', 'claimed') AND assigned_to = $2
"""
_PENDING_BY_RISK_SQL = """
SELECT risk_level, count(*)::int AS n FROM response_actions
WHERE tenant_id = $1 AND status = 'awaiting_approval'
GROUP BY risk_level
"""
_ALERT_VIEW_COUNTS_SQL = """
SELECT status, count(*)::int AS n FROM alerts
WHERE tenant_id = $1 AND status = ANY($2::text[])
GROUP BY status
UNION ALL
SELECT 'closed', count(*)::int FROM alerts
WHERE tenant_id = $1 AND status = 'closed' AND closed_at >= $3 AND ($4::timestamptz IS NULL OR closed_at < $4)
"""
_USER_EMAILS_SQL = "SELECT id, email FROM users WHERE tenant_id = $1 AND id = ANY($2::uuid[])"
_ALERT_DIGESTS_SQL = """
SELECT a.id, a.severity, a.title, a.fingerprint, a.source_id, s.name AS source_name,
       a.normalized->>'rule_name' AS rule_name,
       COALESCE(a.normalized->'entities', '{}'::jsonb) AS entities
FROM alerts a
LEFT JOIN sources s ON s.tenant_id = a.tenant_id AND s.id = a.source_id
WHERE a.tenant_id = $1 AND a.id = ANY($2::text[])
"""


class EscalationQueue(Record):
    """Tenant-wide figures of the active (open or claimed) escalations at ``now``."""

    overdue: int
    unassigned: int
    unassigned_breaching: int
    next_sla_deadline: Optional[datetime]
    by_severity: Dict[str, int]


class AlertDigest(Record):
    """What a list row shows about an escalation's alert: severity, rule, source and entities."""

    id: str
    severity: str
    title: str
    fingerprint: str
    source_id: str
    source_name: Optional[str]
    rule_name: Optional[str]
    entities: Dict[str, Any]

    @property
    def rule(self) -> str:
        """The detection rule name, or the title when the source has none (as the fingerprint does)."""
        return (self.rule_name or "").strip() or self.title


def _check_ids(ids: Sequence[Any]) -> None:
    if len(ids) > MAX_LOOKUP_IDS:
        raise ValueError(f"at most {MAX_LOOKUP_IDS} ids per lookup")


class ViewsRepo(Repository):
    async def escalation_queue(
        self, tenant_id: str, now: datetime, *, conn: Optional[Connection] = None
    ) -> EscalationQueue:
        """Overdue, unassigned and unassigned-overdue counts, the next upcoming deadline, and counts by
        the alert's severity. ``next_sla_deadline`` is the earliest deadline not yet passed."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(c, _QUEUE_SQL, tenant_id, now)
            rows = await c.fetch(_ACTIVE_BY_SEVERITY_SQL, tenant_id)
        return EscalationQueue(
            overdue=row["overdue"],
            unassigned=row["unassigned"],
            unassigned_breaching=row["unassigned_breaching"],
            next_sla_deadline=row["next_sla_deadline"],
            by_severity={str(r["severity"]): int(r["n"]) for r in rows},
        )

    async def assigned_active(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> int:
        """Active escalations assigned to ``user_id``."""
        async with self._tenant(tenant_id, conn) as c:
            return await fetch_int(c, _ASSIGNED_ACTIVE_SQL, tenant_id, user_id)

    async def pending_actions_by_risk(self, tenant_id: str, *, conn: Optional[Connection] = None) -> Dict[str, int]:
        """Actions awaiting approval, by risk level (levels without any are absent)."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_PENDING_BY_RISK_SQL, tenant_id)
        return {str(r["risk_level"]): int(r["n"]) for r in rows}

    async def alert_view_counts(
        self,
        tenant_id: str,
        closed_from: datetime,
        closed_to: Optional[datetime] = None,
        *,
        conn: Optional[Connection] = None,
    ) -> Dict[str, int]:
        """Alerts by status: every status but ``closed`` all-time, ``closed`` only with
        ``closed_from <= closed_at`` (and ``< closed_to`` when given). Every status is present (zero when none)."""
        require_aware(closed_from, "closed_from")
        require_aware(closed_to, "closed_to")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_ALERT_VIEW_COUNTS_SQL, tenant_id, list(OPEN_ALERT_STATUSES), closed_from, closed_to)
        counts: Dict[str, int] = {status: 0 for status in ALERT_STATUSES}
        for r in rows:
            counts[str(r["status"])] = int(r["n"])
        return counts

    async def user_emails(
        self, tenant_id: str, user_ids: Sequence[UUID], *, conn: Optional[Connection] = None
    ) -> Dict[UUID, str]:
        """E-mail address of each of the tenant's users among ``user_ids`` (unknown ids are absent)."""
        ids = list(dict.fromkeys(user_ids))
        _check_ids(ids)
        if not ids:
            return {}
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_USER_EMAILS_SQL, tenant_id, ids)
        return {r["id"]: str(r["email"]) for r in rows}

    async def alert_digests(
        self, tenant_id: str, alert_ids: Sequence[str], *, conn: Optional[Connection] = None
    ) -> Dict[str, AlertDigest]:
        """:class:`AlertDigest` of each of the tenant's alerts among ``alert_ids`` (unknown ids are absent)."""
        ids = list(dict.fromkeys(alert_ids))
        _check_ids(ids)
        if not ids:
            return {}
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(_ALERT_DIGESTS_SQL, tenant_id, ids)
        return {str(r["id"]): AlertDigest.model_validate(dict(r)) for r in rows}
