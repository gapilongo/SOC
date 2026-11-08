"""Alerts: idempotent ingestion, filtered keyset listing, lifecycle and dashboard aggregates."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Sequence, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.pagination import Page, Params, check_limit, decode_cursor_text, escape_like, paginate
from lg_sotf.db.pool import sanitize_text
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    fetch_one,
    require_aware,
    set_clauses,
    to_model,
    to_models,
    utcnow,
)
from lg_sotf.models.vocabulary import ALERT_STATUSES, DISPOSITIONS, SEVERITIES
from lg_sotf.security.shadow import egress, sink

if TYPE_CHECKING:
    from lg_sotf.core.state import AlertSummary

MAX_INSERT_BATCH = 5_000

# ILIKE is not leakproof, so under FORCE RLS PostgreSQL cannot use an index for
# ``q``; the (tenant_id, ingested_at) index bounds the scan to the time window.
DEFAULT_SEARCH_WINDOW = timedelta(days=30)
MAX_SEARCH_WINDOW = timedelta(days=93)
MAX_QUERY_CHARS = 200

# Contract section 6, plus the edges operations need: reprocess (closed/failed
# -> queued), queue retry after a failed run (failed -> processing) and
# dead-lettering before processing started (queued -> failed).
ALERT_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "new": frozenset({"queued"}),
    "queued": frozenset({"processing", "failed"}),
    "processing": frozenset({"waiting_human", "waiting_approval", "closed", "failed"}),
    "waiting_human": frozenset({"processing"}),
    "waiting_approval": frozenset({"processing"}),
    "closed": frozenset({"queued"}),
    "failed": frozenset({"processing", "queued"}),
}

_LIST_COLUMNS = (
    "tenant_id, id, source_id, source_alert_id, fingerprint, title, severity, category, status, "
    "disposition, confidence, threat_score, priority, assigned_to, occurred_at, ingested_at, "
    "updated_at, closed_at, summary, case_key"
)
# An alert's detection rule as console views group it: the normalized rule name, else the title
# (the fingerprint uses the same fallback). ``a`` is the alerts table alias.
ALERT_RULE_SQL = "COALESCE(NULLIF(btrim(a.normalized->>'rule_name'), ''), a.title)"
# What a list row shows besides its columns: the source's name (NULL once the source is deleted)
# and the normalized entities (``entities_preview``).
_ROW_EXTRAS = (
    "(SELECT s.name FROM sources s WHERE s.tenant_id = alerts.tenant_id AND s.id = alerts.source_id) AS source_name, "
    "COALESCE(normalized->'entities', '{}'::jsonb) AS entities"
)
_STRANDED_NEW_SQL = """
SELECT a.tenant_id, a.id AS alert_id, a.severity
FROM alerts a
WHERE a.status = 'new' AND a.ingested_at < now() - make_interval(secs => $1)
  AND a.tenant_id IN (SELECT id FROM tenants WHERE status = 'active')
  AND NOT EXISTS (SELECT 1 FROM workflow_runs r WHERE r.tenant_id = a.tenant_id AND r.alert_id = a.id)
ORDER BY a.ingested_at
LIMIT $2
"""
# The event summary columns of alerts ($2), excluding one source ($3; NULL excludes none: source_id is NOT NULL).
_EVENT_SUMMARIES_SQL = """
    SELECT id, title, severity, status, disposition, confidence, threat_score, category, source_id,
           summary, jsonb_build_object('entities', normalized->'entities') AS normalized
    FROM alerts WHERE tenant_id = $1 AND id = ANY($2::text[]) AND source_id IS DISTINCT FROM $3
"""


def can_transition(current: str, target: str) -> bool:
    return target in ALERT_TRANSITIONS.get(current, frozenset())


async def event_summaries(
    conn: Connection, tenant_id: str, ids: Sequence[str], exclude_source_id: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """The columns an integration event summarises, by alert id; ids not found (or from ``exclude_source_id``) are absent.

    Connection-level: the caller holds the tenant transaction, and driver errors are not translated.
    """
    rows = await conn.fetch(_EVENT_SUMMARIES_SQL, tenant_id, list(ids), exclude_source_id)
    return {str(r["id"]): dict(r) for r in rows}


class NewAlert(BaseModel):
    """An alert to insert. ``id`` is generated up front so callers can map results.

    Text that PostgreSQL cannot store (NUL, lone surrogates) is replaced, in
    these fields here and in ``raw``/``normalized``/``summary`` by the jsonb
    codec, so one crafted event cannot fail a whole ingestion batch.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str = Field(min_length=1, max_length=128)
    source_alert_id: str = Field(min_length=1, max_length=512)
    fingerprint: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=1024)
    severity: str
    category: Optional[str] = None
    occurred_at: datetime
    ingested_at: Optional[datetime] = None
    status: str = "new"
    raw: Dict[str, Any] = Field(default_factory=dict)
    normalized: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    case_key: Optional[str] = None

    @field_validator("id", "source_id", "source_alert_id", "fingerprint", "title", "category", "case_key")
    @classmethod
    def _storable(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else sanitize_text(v)

    @field_validator("severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        return check_choice(v, SEVERITIES, "severity")

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        return check_choice(v, ("new", "queued"), "initial status")

    @field_validator("occurred_at", "ingested_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return require_aware(v, "timestamp")


class AlertListItem(Record):
    tenant_id: str
    id: str
    source_id: str
    source_alert_id: str
    fingerprint: str
    title: str
    severity: str
    category: Optional[str]
    status: str
    disposition: Optional[str]
    confidence: Optional[float]
    threat_score: Optional[float]
    priority: Optional[int]
    assigned_to: Optional[UUID]
    occurred_at: datetime
    ingested_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    summary: Dict[str, Any]
    case_key: Optional[str]
    #: Read by ``list`` and ``get`` only (rows returned by writes leave them empty).
    source_name: Optional[str] = None
    entities: Dict[str, Any] = Field(default_factory=dict)


class Alert(AlertListItem):
    raw: Dict[str, Any]
    normalized: Dict[str, Any]


class StrandedAlertRef(Record):
    """An alert stored but never dispatched (:meth:`AlertsRepo.find_stranded_new_all_tenants`)."""

    tenant_id: str
    alert_id: str
    severity: str


class DashboardCounts(Record):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_disposition: Dict[str, int]


class ResponseTimes(Record):
    """MTTA: escalation created -> claimed. MTTR: alert ingested -> closed."""

    mtta_s: Optional[float]
    mttr_s: Optional[float]
    acknowledged: int
    resolved: int


class AlertsRepo(Repository):
    async def insert_many_if_absent(
        self, tenant_id: str, rows: Sequence[NewAlert], *, conn: Optional[Connection] = None
    ) -> List[str]:
        """Insert alerts, skipping any whose (source_id, source_alert_id) exists.

        Returns the ids of the rows actually inserted, in input order.
        """
        if not rows:
            return []
        if len(rows) > MAX_INSERT_BATCH:
            raise ValueError(f"at most {MAX_INSERT_BATCH} alerts per insert")
        payload = [r.model_dump(mode="json") for r in rows]
        async with self._tenant(tenant_id, conn) as c:
            inserted = await c.fetch(
                """
                INSERT INTO alerts (
                    tenant_id, id, source_id, source_alert_id, fingerprint, title, severity, category,
                    status, occurred_at, ingested_at, raw, normalized, summary, case_key
                )
                SELECT $1, r.id, r.source_id, r.source_alert_id, r.fingerprint, r.title, r.severity,
                       r.category, r.status, r.occurred_at, COALESCE(r.ingested_at, now()),
                       COALESCE(r.raw, '{}'::jsonb), COALESCE(r.normalized, '{}'::jsonb),
                       COALESCE(r.summary, '{}'::jsonb), r.case_key
                FROM jsonb_to_recordset($2::jsonb) AS r(
                    id text, source_id text, source_alert_id text, fingerprint text, title text,
                    severity text, category text, status text, occurred_at timestamptz,
                    ingested_at timestamptz, raw jsonb, normalized jsonb, summary jsonb, case_key text
                )
                ON CONFLICT (tenant_id, source_id, source_alert_id) DO NOTHING
                RETURNING id
                """,
                tenant_id,
                payload,
            )
        ids = {r["id"] for r in inserted}
        return [r.id for r in rows if r.id in ids]

    async def ids_by_source_keys(
        self,
        tenant_id: str,
        source_id: str,
        source_alert_ids: Sequence[str],
        *,
        conn: Optional[Connection] = None,
    ) -> Dict[str, str]:
        """Map ``source_alert_id -> alert id`` for alerts that already exist."""
        if not source_alert_ids:
            return {}
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT source_alert_id, id FROM alerts
                WHERE tenant_id = $1 AND source_id = $2 AND source_alert_id = ANY($3::text[])
                """,
                tenant_id,
                source_id,
                list(source_alert_ids),
            )
        return {r["source_alert_id"]: r["id"] for r in rows}

    async def get(self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None) -> Alert:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"SELECT *, {_ROW_EXTRAS} FROM alerts WHERE tenant_id = $1 AND id = $2",  # noqa: S608 (constants)
                tenant_id,
                alert_id,
            )
        alert = to_model(Alert, row)
        if alert is None:
            raise NotFound("alert", alert_id)
        return alert

    async def list(
        self,
        tenant_id: str,
        *,
        status: Union[str, Sequence[str], None] = None,
        severity: Union[str, Sequence[str], None] = None,
        disposition: Union[str, Sequence[str], None] = None,
        source_id: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
        q: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        closed_from: Optional[datetime] = None,
        closed_to: Optional[datetime] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[AlertListItem]:
        """Newest first by (ingested_at, id); ``since``/``until`` bound ``ingested_at``,
        ``closed_from``/``closed_to`` bound ``closed_at`` (so only closed alerts match them).

        ``q`` is a case-insensitive substring match on the title. A ``q``
        search always has a time window: without ``since`` it covers
        :data:`DEFAULT_SEARCH_WINDOW` before ``until`` (or now), and a window
        longer than :data:`MAX_SEARCH_WINDOW` raises ``ValueError``.
        """
        check_limit(limit)
        require_aware(since, "since")
        require_aware(until, "until")
        require_aware(closed_from, "closed_from")
        require_aware(closed_to, "closed_to")
        if q is not None:
            q = q.strip()[:MAX_QUERY_CHARS]
        if q:
            end = until or utcnow()
            if since is None:
                since = end - DEFAULT_SEARCH_WINDOW
            elif end - since > MAX_SEARCH_WINDOW:
                raise ValueError(f"a text search may span at most {MAX_SEARCH_WINDOW.days} days")
        params = Params(tenant_id)
        where = ["tenant_id = $1"]
        statuses = check_choices(status, ALERT_STATUSES, "status")
        if statuses:
            where.append(f"status = ANY({params.add(statuses)}::text[])")
        severities = check_choices(severity, SEVERITIES, "severity")
        if severities:
            where.append(f"severity = ANY({params.add(severities)}::text[])")
        dispositions = check_choices(disposition, DISPOSITIONS, "disposition")
        if dispositions:
            where.append(f"disposition = ANY({params.add(dispositions)}::text[])")
            # A sample waiting for its blind-audit label: filtering on its verdict would reveal it.
            where.append(
                "NOT EXISTS (SELECT 1 FROM blind_audit_items b WHERE b.tenant_id = alerts.tenant_id "
                "AND b.alert_id = alerts.id AND b.label IS NULL)"
            )
        if source_id is not None:
            where.append(f"source_id = {params.add(source_id)}")
        if assigned_to is not None:
            where.append(f"assigned_to = {params.add(assigned_to)}")
        if q:
            where.append(f"title ILIKE {params.add('%' + escape_like(sanitize_text(q)) + '%')}")
        if since is not None:
            where.append(f"ingested_at >= {params.add(since)}")
        if until is not None:
            where.append(f"ingested_at < {params.add(until)}")
        if closed_from is not None:
            where.append(f"closed_at >= {params.add(closed_from)}")
        if closed_to is not None:
            where.append(f"closed_at < {params.add(closed_to)}")
        if cursor:
            ts, key = decode_cursor_text(cursor)
            where.append(f"(ingested_at, id) < ({params.add(ts)}, {params.add(key)})")
        sql = (
            f"SELECT {_LIST_COLUMNS}, {_ROW_EXTRAS} FROM alerts WHERE {' AND '.join(where)} "  # noqa: S608
            f"ORDER BY ingested_at DESC, id DESC LIMIT {params.add(limit + 1)}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, *params.values)
        items = [AlertListItem.model_validate(dict(r)) for r in rows]
        return paginate(items, limit, lambda a: (a.ingested_at, a.id))

    @egress("alert", sink(detail=lambda a: {"to_status": a["to_status"]}))
    async def update_status(
        self,
        tenant_id: str,
        alert_id: str,
        to_status: str,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> Alert:
        """Move an alert along the lifecycle (contract section 6).

        Setting the current status again is a no-op. Closing sets
        ``closed_at``; leaving ``closed`` clears it.
        """
        check_choice(to_status, ALERT_STATUSES, "status")
        require_aware(now, "now")
        allowed_from = [s for s, targets in ALERT_TRANSITIONS.items() if to_status in targets]
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE alerts SET
                    status = $3,
                    closed_at = CASE WHEN $3 = 'closed' THEN COALESCE($5::timestamptz, now()) ELSE NULL END
                WHERE tenant_id = $1 AND id = $2 AND status = ANY($4::text[])
                RETURNING *
                """,
                tenant_id,
                alert_id,
                to_status,
                allowed_from,
                now,
            )
            if row is None:
                row = await c.fetchrow("SELECT * FROM alerts WHERE tenant_id = $1 AND id = $2", tenant_id, alert_id)
                if row is None:
                    raise NotFound("alert", alert_id)
                if row["status"] != to_status:
                    raise InvalidTransition("alert", alert_id, row["status"], to_status)
        return Alert.model_validate(dict(row))

    @egress("alert", sink())
    async def update(
        self,
        tenant_id: str,
        alert_id: str,
        *,
        confidence: Optional[float] = UNSET,
        threat_score: Optional[float] = UNSET,
        priority: Optional[int] = UNSET,
        disposition: Optional[str] = UNSET,
        category: Optional[str] = UNSET,
        assigned_to: Optional[UUID] = UNSET,
        case_key: Optional[str] = UNSET,
        closed_at: Optional[datetime] = UNSET,
        summary: AlertSummary = UNSET,
        conn: Optional[Connection] = None,
    ) -> Alert:
        """Update scores and verdict fields. ``summary`` is shallow-merged into the stored summary.

        Status is changed only through :meth:`update_status`.
        """
        if disposition not in (UNSET, None):
            check_choice(disposition, DISPOSITIONS, "disposition")
        if closed_at not in (UNSET, None):
            require_aware(closed_at, "closed_at")
        params = Params(tenant_id, alert_id)
        sets = set_clauses(
            {
                "confidence": confidence,
                "threat_score": threat_score,
                "priority": priority,
                "disposition": disposition,
                "category": category,
                "assigned_to": assigned_to,
                "case_key": case_key,
                "closed_at": closed_at,
            },
            params,
        )
        if summary is not UNSET:
            sets.append(f"summary = summary || {params.add(dict(summary))}::jsonb")
        if not sets:
            return await self.get(tenant_id, alert_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"UPDATE alerts SET {', '.join(sets)} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
                *params.values,
            )
        alert = to_model(Alert, row)
        if alert is None:
            raise NotFound("alert", alert_id)
        return alert

    async def dashboard_counts(
        self, tenant_id: str, since: datetime, *, conn: Optional[Connection] = None
    ) -> DashboardCounts:
        """Counts of alerts ingested since ``since`` by status, severity and disposition.

        Alerts without a disposition are counted under ``"undecided"``. Alerts waiting for their
        blind-audit label are left out: windows that differ by one hour would reveal their disposition.
        """
        require_aware(since, "since")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT GROUPING(status) AS g_status, GROUPING(severity) AS g_severity,
                       GROUPING(disposition) AS g_disposition,
                       status, severity, disposition, count(*) AS n
                FROM alerts
                WHERE tenant_id = $1 AND ingested_at >= $2
                  AND NOT EXISTS (SELECT 1 FROM blind_audit_items b WHERE b.tenant_id = alerts.tenant_id
                                  AND b.alert_id = alerts.id AND b.label IS NULL)
                GROUP BY GROUPING SETS ((status), (severity), (disposition), ())
                """,
                tenant_id,
                since,
            )
        total = 0
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_disposition: Dict[str, int] = {}
        for r in rows:
            if r["g_status"] == 0:
                by_status[r["status"]] = r["n"]
            elif r["g_severity"] == 0:
                by_severity[r["severity"]] = r["n"]
            elif r["g_disposition"] == 0:
                by_disposition[r["disposition"] or "undecided"] = r["n"]
            else:
                total = r["n"]
        return DashboardCounts(total=total, by_status=by_status, by_severity=by_severity, by_disposition=by_disposition)

    async def response_times(
        self, tenant_id: str, since: datetime, *, conn: Optional[Connection] = None
    ) -> ResponseTimes:
        """Mean time to acknowledge and to resolve over the window starting at ``since``."""
        require_aware(since, "since")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                SELECT
                    (SELECT extract(epoch FROM avg(e.claimed_at - e.created_at))
                     FROM escalations e
                     WHERE e.tenant_id = $1 AND e.claimed_at >= $2) AS mtta_s,
                    (SELECT count(*) FROM escalations e
                     WHERE e.tenant_id = $1 AND e.claimed_at >= $2) AS acknowledged,
                    (SELECT extract(epoch FROM avg(a.closed_at - a.ingested_at))
                     FROM alerts a
                     WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.closed_at >= $2) AS mttr_s,
                    (SELECT count(*) FROM alerts a
                     WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.closed_at >= $2) AS resolved
                """,
                tenant_id,
                since,
            )
        return ResponseTimes(
            mtta_s=None if row["mtta_s"] is None else float(row["mtta_s"]),
            mttr_s=None if row["mttr_s"] is None else float(row["mttr_s"]),
            acknowledged=row["acknowledged"],
            resolved=row["resolved"],
        )

    # -- recovery sweeps (runtime/orphans.py) ------------------------------------------------------

    async def find_stranded_new_all_tenants(self, *, older_than_s: float, limit: int) -> List[StrandedAlertRef]:
        """Alerts of active tenants still ``new`` and without a run after ``older_than_s``: a crash or
        cancel between insert and dispatch (schema owner, read-only ``system_tx``)."""
        async with self._system(readonly=True) as c:
            rows = await c.fetch(_STRANDED_NEW_SQL, float(older_than_s), limit)
        return to_models(StrandedAlertRef, rows)
