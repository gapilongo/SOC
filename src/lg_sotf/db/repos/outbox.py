"""The integration delivery outbox.

The outbox is written by the services in the transaction of the state change
that raised the event (:func:`lg_sotf.integrations.outbox.enqueue_event`) and
drained by the scheduler (:mod:`lg_sotf.integrations.delivery`): a claim moves
``next_attempt_at`` one lease ahead and counts the attempt, so a delivery that
dies half way is retried once the lease ends (at-least-once), and each outcome
is written only by the claim that made the attempt (``attempts`` must still
match).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence
from uuid import UUID

from pydantic import Field

from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    fetch_one,
    to_models,
    truncate,
)

OUTBOX_STATUSES = ("pending", "sent", "failed", "dead")
OUTBOX_OPERATIONS = ("notify", "ticket_create", "ticket_update", "test")
MAX_ERROR_CHARS = 1_000
MAX_DELIVERY_LIST = 200
# Rows as ``NewOutboxEntry.model_dump(mode="json")`` in $2; an already queued (integration, dedupe_key) is skipped.
_ENQUEUE_SQL = """
    INSERT INTO notification_outbox
        (tenant_id, integration_id, event_id, event_type, operation, dedupe_key, alert_id, escalation_id, payload)
    SELECT $1, e.integration_id, e.event_id, e.event_type, e.operation, e.dedupe_key,
           e.alert_id, e.escalation_id, e.payload
    FROM jsonb_to_recordset($2::jsonb) AS e(
        integration_id uuid, event_id uuid, event_type text, operation text, dedupe_key text,
        alert_id text, escalation_id text, payload jsonb
    )
    ON CONFLICT (tenant_id, integration_id, dedupe_key) DO NOTHING
"""
# The tenant's enabled integrations subscribed to an event type ($2).
_INTEGRATIONS_SQL = """
    SELECT id, kind, events, min_severity, config FROM integrations
    WHERE tenant_id = $1 AND enabled AND $2 = ANY(events)
"""


class OutboxEntry(Record):
    id: UUID
    tenant_id: str
    integration_id: UUID
    event_id: UUID
    event_type: str
    operation: str
    dedupe_key: str
    alert_id: Optional[str]
    escalation_id: Optional[str]
    payload: Dict[str, Any]
    status: str
    attempts: int
    next_attempt_at: datetime
    last_error: Optional[str]
    result: Optional[Dict[str, Any]]
    sent_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class NewOutboxEntry(Record):
    integration_id: UUID
    event_id: UUID
    event_type: str
    operation: str
    dedupe_key: str
    alert_id: Optional[str] = None
    escalation_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


# Connection-level queries for writers that already hold the tenant transaction of the change
# (lg_sotf.integrations.outbox). Driver errors are not translated: they abort that transaction.


async def matching_enabled(conn: Connection, tenant_id: str, event_type: str) -> List[Dict[str, Any]]:
    """The tenant's enabled integrations subscribed to ``event_type`` (``id, kind, events, min_severity, config``)."""
    return [dict(r) for r in await conn.fetch(_INTEGRATIONS_SQL, tenant_id, event_type)]


async def enqueue_on(conn: Connection, tenant_id: str, entries: Sequence[NewOutboxEntry]) -> int:
    """Insert outbox rows on ``conn``; a (integration, ``dedupe_key``) already queued is skipped. Returns rows inserted."""
    if not entries:
        return 0
    status = await conn.execute(
        _ENQUEUE_SQL,
        tenant_id,
        [e.model_dump(mode="json") for e in entries],
    )
    return int(str(status).split()[-1]) if status else 0


class OutboxRepo(Repository):
    async def enqueue(
        self, tenant_id: str, entries: Sequence[NewOutboxEntry], *, conn: Optional[Connection] = None
    ) -> int:
        """Insert outbox rows; a (integration, ``dedupe_key``) already queued is skipped. Returns rows inserted."""
        if not entries:
            return 0
        async with self._tenant(tenant_id, conn) as c:
            return await enqueue_on(c, tenant_id, entries)

    async def record_test(
        self,
        tenant_id: str,
        entry: NewOutboxEntry,
        *,
        ok: bool,
        error: Optional[str],
        result: Optional[Mapping[str, Any]],
        conn: Optional[Connection] = None,
    ) -> OutboxEntry:
        """Log a synchronous test delivery in the outbox (already finished: ``sent`` or ``dead``)."""
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO notification_outbox
                    (tenant_id, integration_id, event_id, event_type, operation, dedupe_key, payload,
                     status, attempts, last_error, result, sent_at)
                VALUES ($1, $2, $3, $4, 'test', $5, $6, $7, 1, $8, $9, CASE WHEN $10 THEN now() END)
                RETURNING *
                """,
                tenant_id,
                entry.integration_id,
                entry.event_id,
                entry.event_type,
                entry.dedupe_key,
                entry.payload,
                "sent" if ok else "dead",
                truncate(error, MAX_ERROR_CHARS),
                dict(result or {}),
                ok,
            )
        return OutboxEntry.model_validate(dict(row))

    async def claim_due_all_tenants(self, *, limit: int, lease_s: float) -> List[OutboxEntry]:
        """Claim up to ``limit`` due rows of every tenant (scheduler, schema owner).

        ``FOR UPDATE SKIP LOCKED`` lets concurrent claimers split the backlog;
        the claim counts the attempt and moves ``next_attempt_at`` one lease
        ahead, so an attempt whose outcome is never recorded is retried later.
        """
        async with self._system() as c:
            rows = await c.fetch(
                """
                WITH due AS (
                    SELECT o.id FROM notification_outbox o
                    WHERE o.status IN ('pending', 'failed') AND o.next_attempt_at <= now()
                    ORDER BY o.next_attempt_at, o.id
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE notification_outbox o
                SET attempts = o.attempts + 1, next_attempt_at = now() + make_interval(secs => $2)
                FROM due WHERE o.id = due.id
                RETURNING o.*
                """,
                limit,
                float(lease_s),
            )
        return sorted(to_models(OutboxEntry, rows), key=lambda e: (e.created_at, str(e.id)))

    async def record_outcome(
        self,
        tenant_id: str,
        entry_id: UUID,
        *,
        claimed_attempts: int,
        status: str,
        retry_in_s: Optional[float] = None,
        error: Optional[str] = None,
        result: Optional[Mapping[str, Any]] = None,
        refund_attempt: bool = False,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Write the outcome of the attempt ``claimed_attempts``; False when another claim owns the row now.

        ``refund_attempt`` gives the attempt back (a delivery deferred by a
        rate limit or a dependency, which never reached the receiver).
        """
        check_choice(status, OUTBOX_STATUSES, "outbox status")
        async with self._tenant(tenant_id, conn) as c:
            outcome = await c.execute(
                """
                UPDATE notification_outbox SET
                    status = $4,
                    attempts = CASE WHEN $8 THEN GREATEST(attempts - 1, 0) ELSE attempts END,
                    next_attempt_at = CASE WHEN $5::double precision IS NULL THEN next_attempt_at
                                           ELSE now() + make_interval(secs => $5) END,
                    last_error = $6,
                    result = COALESCE($7::jsonb, result),
                    sent_at = CASE WHEN $4 = 'sent' THEN now() ELSE sent_at END
                WHERE tenant_id = $1 AND id = $2 AND attempts = $3 AND status IN ('pending', 'failed')
                """,
                tenant_id,
                entry_id,
                claimed_attempts,
                status,
                retry_in_s,
                truncate(error, MAX_ERROR_CHARS),
                dict(result) if result is not None else None,
                refund_attempt,
            )
        return outcome.endswith(" 1")

    async def deliveries(
        self,
        tenant_id: str,
        integration_id: UUID,
        *,
        status: Optional[Sequence[str]] = None,
        limit: int = 50,
        conn: Optional[Connection] = None,
    ) -> List[OutboxEntry]:
        """Most recent outbox rows of one integration (newest first)."""
        check_limit(limit, maximum=MAX_DELIVERY_LIST)
        statuses = check_choices(list(status) if status is not None else None, OUTBOX_STATUSES, "outbox status")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM notification_outbox
                WHERE tenant_id = $1 AND integration_id = $2 AND ($3::text[] IS NULL OR status = ANY($3::text[]))
                ORDER BY created_at DESC, id DESC
                LIMIT $4
                """,
                tenant_id,
                integration_id,
                statuses,
                limit,
            )
        return to_models(OutboxEntry, rows)

    async def has_pending(
        self,
        tenant_id: str,
        integration_id: UUID,
        operation: str,
        *,
        escalation_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Whether a not-yet-finished row of ``operation`` exists (e.g. the ticket a comment must wait for)."""
        async with self._tenant(tenant_id, conn) as c:
            found = await c.fetchval(
                """
                SELECT 1 FROM notification_outbox
                WHERE tenant_id = $1 AND integration_id = $2 AND operation = $3
                  AND ($4::text IS NULL OR escalation_id = $4) AND status IN ('pending', 'failed')
                LIMIT 1
                """,
                tenant_id,
                integration_id,
                operation,
                escalation_id,
            )
        return found is not None

    async def purge_finished_all_tenants(self, *, older_than: datetime, limit: int = 5_000) -> int:
        """Delete sent and dead rows last touched before ``older_than`` (one bounded batch)."""
        async with self._system() as c:
            status = await c.execute(
                """
                DELETE FROM notification_outbox WHERE id IN (
                    SELECT id FROM notification_outbox
                    WHERE status IN ('sent', 'dead') AND updated_at < $1
                    LIMIT $2
                )
                """,
                older_than,
                limit,
            )
        return int(status.split()[-1])
