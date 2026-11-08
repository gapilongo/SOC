"""Blind audit runs and items (migration 0014; :mod:`lg_sotf.domain.blind_audit` defines the sampling).

The sampling frame and the draw run in one statement: every alert of the
frame is ranked by ``md5(seed || ':' || id)`` (ties by id) and the frame's
size is counted over the same rows, so the recorded frame is exactly the
population the sample was drawn from.

:class:`BlindAuditItem` is what an analyst's queue reads: the item, and of
its alert only what the source sent (title, severity, source, category,
times, raw and normalized event). The AI's verdict, confidence, scores,
routing and reasoning are read only by :meth:`BlindAuditRepo.reveal`, which
callers use once the item has a label.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from uuid import UUID

from pydantic import Field

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pagination import Page, check_limit, decode_cursor_uuid, paginate
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    fetch_bool,
    fetch_one,
    require_aware,
    to_model,
    to_models,
)
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.models.vocabulary import AUDIT_LABELS, AUDIT_TRIGGERS, DISPOSITIONS, POLICY_APPROVER, AuditTrigger

MAX_RUNS_IN_WINDOW = 1_000
MAX_FRAME_ROWS = 10_000

# Alerts closed in [$2, $3) with no person involved and an AI disposition other than malicious, never
# sampled before, built-in samples aside ($4); ranked by the seed's key ($5), the first $6 returned.
_FRAME_SQL = """
WITH frame AS (
    SELECT a.id, a.disposition
    FROM alerts a
    WHERE a.tenant_id = $1 AND a.status = 'closed' AND a.closed_at >= $2 AND a.closed_at < $3
      AND a.source_id <> $4
      AND a.disposition IS DISTINCT FROM 'malicious'
      AND a.summary->>'analyst_decision' IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM response_actions r
          WHERE r.tenant_id = a.tenant_id AND r.alert_id = a.id
            AND (r.status IN ('awaiting_approval', 'rejected')
                 OR (r.approved_by IS NOT NULL AND r.approved_by <> $7))
      )
      AND ($8 OR NOT EXISTS (SELECT 1 FROM blind_audit_items i WHERE i.tenant_id = a.tenant_id AND i.alert_id = a.id))
),
ranked AS (
    SELECT id, disposition,
           row_number() OVER (ORDER BY md5($5::bigint::text || ':' || id), id) AS rank,
           count(*) OVER () AS frame_size
    FROM frame
)
SELECT id AS alert_id, disposition, rank, frame_size FROM ranked WHERE rank <= $6 ORDER BY rank
"""

# What the queue may show of an alert: the source's data, never the AI's.
_ITEM_SELECT = """
SELECT i.id, i.tenant_id, i.run_id, i.alert_id, i.sample_rank, i.label, i.notes, i.labelled_by,
       i.labelled_by_actor, i.labelled_by_org, i.labelled_at, i.escalation_id, i.created_at,
       a.title, a.severity, a.source_id, s.name AS source_name, a.category, a.occurred_at, a.ingested_at,
       COALESCE(a.normalized->'entities', '{{}}'::jsonb) AS entities{detail}
FROM blind_audit_items i
JOIN alerts a ON a.tenant_id = i.tenant_id AND a.id = i.alert_id
LEFT JOIN sources s ON s.tenant_id = a.tenant_id AND s.id = a.source_id
"""
_DETAIL_COLUMNS = ", a.raw, a.normalized"

_RUN_COUNTS = """
SELECT r.*,
       count(i.id) AS sampled,
       count(i.id) FILTER (WHERE i.label = 'malicious') AS malicious,
       count(i.id) FILTER (WHERE i.label = 'benign') AS benign,
       count(i.id) FILTER (WHERE i.label = 'unsure') AS unsure,
       count(i.id) FILTER (WHERE i.agreement) AS agreed
FROM blind_audit_runs r
LEFT JOIN blind_audit_items i ON i.tenant_id = r.tenant_id AND i.run_id = r.id
WHERE r.tenant_id = $1 {where}
GROUP BY r.id
"""


class OrganisationLabels(Record):
    """Labels given by one organisation (``None``: the tenant's own people)."""

    organisation: Optional[str]
    labelled: int
    malicious: int
    benign: int
    unsure: int


class FrameAlert(Record):
    alert_id: str
    disposition: Optional[str]
    rank: int


class BlindAuditRun(Record):
    id: UUID
    tenant_id: str
    window_start: datetime
    window_end: datetime
    seed: int
    seed_source: str = "server"
    sample_rate: Optional[float]
    min_sample: int
    fixed_size: Optional[int]
    frame_size: int = Field(description="Alerts eligible in the window: the sampling frame.")
    sample_size: int
    trigger: AuditTrigger
    created_by: Optional[str]
    created_at: datetime


class BlindAuditRunSummary(BlindAuditRun):
    """A run with its label counts."""

    sampled: int = 0
    malicious: int = 0
    benign: int = 0
    unsure: int = 0
    agreed: int = 0


class BlindAuditItem(Record):
    """A sampled alert as the analyst sees it before labelling: no AI field. ``raw``/``normalized`` on ``get`` only."""

    id: UUID
    tenant_id: str
    run_id: UUID
    alert_id: str
    sample_rank: int
    label: Optional[str]
    notes: Optional[str]
    labelled_by: Optional[UUID]
    labelled_by_actor: Optional[str]
    labelled_by_org: Optional[str] = None
    labelled_at: Optional[datetime]
    escalation_id: Optional[str]
    created_at: datetime
    title: str
    severity: str
    source_id: str
    source_name: Optional[str]
    category: Optional[str]
    occurred_at: datetime
    ingested_at: datetime
    entities: Dict[str, Any] = {}
    raw: Optional[Dict[str, Any]] = None
    normalized: Optional[Dict[str, Any]] = None


class Reveal(Record):
    """The AI's side of a labelled item: its class when sampled and the alert's verdict fields now."""

    ai_class: str
    agreement: Optional[bool]
    disposition: Optional[str]
    confidence: Optional[float]
    threat_score: Optional[float]
    close_reason: Optional[str]
    conclusion: Optional[str]
    routing_code: Optional[str]


class BlindAuditRepo(Repository):
    async def overlaps(
        self, tenant_id: str, since: datetime, until: datetime, *, conn: Optional[Connection] = None
    ) -> bool:
        """Whether a run of the tenant already covers part of ``[since, until)``."""
        async with self._tenant(tenant_id, conn) as c:
            return await fetch_bool(
                c,
                "SELECT EXISTS (SELECT 1 FROM blind_audit_runs WHERE tenant_id = $1 AND window_start < $3 "
                "AND window_end > $2)",
                tenant_id,
                since,
                until,
            )

    async def latest_window_end(self, tenant_id: str, *, conn: Optional[Connection] = None) -> Optional[datetime]:
        async with self._tenant(tenant_id, conn) as c:
            value = await c.fetchval("SELECT max(window_end) FROM blind_audit_runs WHERE tenant_id = $1", tenant_id)
        return value if isinstance(value, datetime) else None

    async def frame(
        self, tenant_id: str, since: datetime, until: datetime, *, seed: int, limit: int,
        include_sampled: bool = False, conn: Optional[Connection] = None,
    ) -> Tuple[int, List[FrameAlert]]:
        """``(frame size, the first `limit` alerts of the draw)`` for a window and seed (``limit`` >= 1).

        ``include_sampled`` keeps alerts an earlier run sampled (a dry run re-drawing a recorded run's window).
        """
        require_aware(since, "since")
        require_aware(until, "until")
        check_limit(limit, MAX_FRAME_ROWS)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                _FRAME_SQL, tenant_id, since, until, SAMPLE_SOURCE_ID, seed, limit, POLICY_APPROVER, include_sampled
            )
        # The window count runs over the whole frame, so any returned row carries its size; no row: an empty frame.
        return (int(rows[0]["frame_size"]), to_models(FrameAlert, rows)) if rows else (0, [])

    async def create_run(
        self,
        tenant_id: str,
        *,
        since: datetime,
        until: datetime,
        seed: int,
        sample_rate: Optional[float],
        min_sample: int,
        fixed_size: Optional[int],
        frame_size: int,
        items: Sequence[Tuple[str, int, str]],
        trigger: str,
        created_by: Optional[str],
        conn: Optional[Connection] = None,
    ) -> BlindAuditRun:
        """Record a run and its items (``(alert_id, rank, ai_class)`` each)."""
        check_choice(trigger, AUDIT_TRIGGERS, "trigger")
        for _, _, ai in items:
            check_choice(ai, DISPOSITIONS, "AI class")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO blind_audit_runs (tenant_id, window_start, window_end, seed, sample_rate, min_sample,
                                              fixed_size, frame_size, sample_size, trigger, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING *
                """,
                tenant_id, since, until, seed, sample_rate, min_sample, fixed_size, frame_size, len(items), trigger,
                created_by,
            )
            run = BlindAuditRun.model_validate(dict(row))
            if items:
                await c.execute(
                    """
                    INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class)
                    SELECT $1, $2, x.alert_id, x.rank, x.ai_class
                    FROM unnest($3::text[], $4::int[], $5::text[]) AS x (alert_id, rank, ai_class)
                    """,
                    tenant_id,
                    run.id,
                    [i[0] for i in items],
                    [i[1] for i in items],
                    [i[2] for i in items],
                )
        return run

    async def list_items(
        self,
        tenant_id: str,
        *,
        labelled: Optional[bool] = False,
        limit: int = 50,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[BlindAuditItem]:
        """Pending items oldest first (``labelled=False``), labelled ones newest label first (``True``)."""
        check_limit(limit)
        sort = "i.labelled_at" if labelled else "i.created_at"
        args: List[Any] = [tenant_id]
        where = ["i.tenant_id = $1", "i.label IS NOT NULL" if labelled else "i.label IS NULL"]
        if cursor:
            ts, key = decode_cursor_uuid(cursor)
            args += [ts, key]
            where.append(f"({sort}, i.id) {'<' if labelled else '>'} ($2, $3)")
        direction = "DESC" if labelled else "ASC"
        query = (
            _ITEM_SELECT.format(detail="")
            + f"WHERE {' AND '.join(where)} ORDER BY {sort} {direction}, i.id {direction} LIMIT ${len(args) + 1}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(query, *args, limit + 1)
        items = to_models(BlindAuditItem, rows)
        return paginate(
            items, limit, lambda i: ((i.labelled_at if labelled else i.created_at), str(i.id))
        )

    async def get_item(
        self, tenant_id: str, item_id: UUID, *, for_update: bool = False, conn: Optional[Connection] = None
    ) -> BlindAuditItem:
        query = _ITEM_SELECT.format(detail=_DETAIL_COLUMNS) + "WHERE i.tenant_id = $1 AND i.id = $2"
        if for_update:
            query += " FOR UPDATE OF i"
        async with self._tenant(tenant_id, conn) as c:
            item = to_model(BlindAuditItem, await c.fetchrow(query, tenant_id, item_id))
        if item is None:
            raise NotFound("blind audit item", str(item_id))
        return item

    async def reveal(self, tenant_id: str, item_id: UUID, *, conn: Optional[Connection] = None) -> Reveal:
        """The AI's verdict fields of an item (callers check that the item is labelled)."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                SELECT i.ai_class, i.agreement, a.disposition, a.confidence, a.threat_score,
                       a.summary->>'close_reason' AS close_reason,
                       COALESCE(a.summary->'analysis'->>'conclusion', a.summary->'triage'->>'reasoning')
                           AS conclusion,
                       a.summary->'decision'->>'code' AS routing_code
                FROM blind_audit_items i JOIN alerts a ON a.tenant_id = i.tenant_id AND a.id = i.alert_id
                WHERE i.tenant_id = $1 AND i.id = $2
                """,
                tenant_id,
                item_id,
            )
        reveal = to_model(Reveal, row)
        if reveal is None:
            raise NotFound("blind audit item", str(item_id))
        return reveal

    async def label(
        self,
        tenant_id: str,
        item_id: UUID,
        *,
        label: str,
        notes: Optional[str],
        agreement: Optional[bool],
        labelled_by: Optional[UUID],
        labelled_by_actor: str,
        escalation_id: Optional[str],
        now: datetime,
        labelled_by_org: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Record the label of an unlabelled item; ``False`` when it already has one."""
        check_choice(label, AUDIT_LABELS, "label")
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE blind_audit_items
                SET label = $3, notes = $4, agreement = $5, labelled_by = $6, labelled_by_actor = $7,
                    labelled_at = $8, escalation_id = $9, labelled_by_org = $10
                WHERE tenant_id = $1 AND id = $2 AND label IS NULL
                """,
                tenant_id, item_id, label, notes, agreement, labelled_by, labelled_by_actor[:200], now, escalation_id,
                labelled_by_org,
            )
        return status.endswith(" 1")

    async def list_runs(
        self, tenant_id: str, *, limit: int = 50, cursor: Optional[str] = None, conn: Optional[Connection] = None
    ) -> Page[BlindAuditRunSummary]:
        """Runs with their label counts, newest window first."""
        check_limit(limit)
        args: List[Any] = [tenant_id]
        where = ""
        if cursor:
            ts, key = decode_cursor_uuid(cursor)
            args += [ts, key]
            where = "AND (r.window_start, r.id) < ($2, $3)"
        query = _RUN_COUNTS.format(where=where) + f"ORDER BY r.window_start DESC, r.id DESC LIMIT ${len(args) + 1}"
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(query, *args, limit + 1)
        return paginate(to_models(BlindAuditRunSummary, rows), limit, lambda r: (r.window_start, str(r.id)))

    async def runs_in_window(
        self, tenant_id: str, since: datetime, until: datetime, *, conn: Optional[Connection] = None
    ) -> List[BlindAuditRunSummary]:
        """Runs whose window overlaps ``[since, until)``, with their counts (at most :data:`MAX_RUNS_IN_WINDOW`)."""
        query = (
            _RUN_COUNTS.format(where="AND r.window_start < $3 AND r.window_end > $2")
            + f"ORDER BY r.window_start, r.id LIMIT {MAX_RUNS_IN_WINDOW}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(query, tenant_id, since, until)
        return to_models(BlindAuditRunSummary, rows)

    async def labels_by_organisation(
        self, tenant_id: str, run_ids: Sequence[UUID], *, conn: Optional[Connection] = None
    ) -> List[OrganisationLabels]:
        """Labels of these runs by who gave them: the tenant's own people (``organisation`` null) or an MSSP."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT labelled_by_org AS organisation, count(*) AS labelled,
                       count(*) FILTER (WHERE label = 'malicious') AS malicious,
                       count(*) FILTER (WHERE label = 'benign') AS benign,
                       count(*) FILTER (WHERE label = 'unsure') AS unsure
                FROM blind_audit_items
                WHERE tenant_id = $1 AND run_id = ANY($2::uuid[]) AND label IS NOT NULL
                GROUP BY labelled_by_org
                ORDER BY labelled_by_org NULLS FIRST
                """,
                tenant_id,
                list(run_ids),
            )
        return to_models(OrganisationLabels, rows)

    async def pending_alert_ids(
        self, tenant_id: str, alert_ids: Sequence[str], *, conn: Optional[Connection] = None
    ) -> Set[str]:
        """The alerts among ``alert_ids`` that wait for a blind-audit label (their AI side stays hidden)."""
        if not alert_ids:
            return set()
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT alert_id FROM blind_audit_items WHERE tenant_id = $1 AND label IS NULL "
                "AND alert_id = ANY($2::text[])",
                tenant_id,
                list(dict.fromkeys(alert_ids)),
            )
        return {str(r["alert_id"]) for r in rows}

    async def db_now(self, tenant_id: str, *, conn: Optional[Connection] = None) -> datetime:
        """The database's clock (windows end before closes that are still committing)."""
        async with self._tenant(tenant_id, conn) as c:
            value = await c.fetchval("SELECT now()")
        if not isinstance(value, datetime):
            raise RuntimeError("the database returned no time")
        return value
