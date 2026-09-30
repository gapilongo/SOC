"""Integrations (notification channels and ticketing), their delivery outbox and linked external tickets.

The outbox is written by the services in the transaction of the state change
that raised the event (:func:`lg_sotf.integrations.outbox.enqueue_event`) and
drained by the scheduler (:mod:`lg_sotf.integrations.delivery`): a claim moves
``next_attempt_at`` one lease ahead and counts the attempt, so a delivery that
dies half way is retried once the lease ends (at-least-once), and each outcome
is written only by the claim that made the attempt (``attempts`` must still
match).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence
from uuid import UUID

import asyncpg
from pydantic import Field

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.pagination import Params, check_limit
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    set_clauses,
    to_model,
    to_models,
    truncate,
)

INTEGRATION_KINDS = ("slack", "teams", "email", "webhook", "jira", "servicenow")
TICKETING_KINDS = ("jira", "servicenow")
OUTBOX_STATUSES = ("pending", "sent", "failed", "dead")
OUTBOX_OPERATIONS = ("notify", "ticket_create", "ticket_update", "test")
MAX_ERROR_CHARS = 1_000
MAX_DELIVERY_LIST = 200
# Rows as ``NewOutboxEntry.model_dump(mode="json")`` in $2; an already queued (integration, dedupe_key) is skipped.
ENQUEUE_SQL = """
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


class Integration(Record):
    id: UUID
    tenant_id: str
    kind: str
    name: str
    enabled: bool
    config: Dict[str, Any]
    secret_ciphertext: Optional[str] = Field(default=None, repr=False)
    events: List[str]
    min_severity: str
    created_by: Optional[UUID]
    created_at: datetime
    updated_at: datetime

    @property
    def is_ticketing(self) -> bool:
        return self.kind in TICKETING_KINDS


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


class ExternalTicket(Record):
    id: UUID
    tenant_id: str
    integration_id: UUID
    alert_id: str
    escalation_id: Optional[str]
    action_id: Optional[UUID]
    system: str
    external_key: str
    external_id: Optional[str]
    external_url: Optional[str]
    external_status: Optional[str]
    resolved: bool
    resolved_by: Optional[str]
    last_synced_at: Optional[datetime]
    sync_error: Optional[str]
    created_at: datetime
    updated_at: datetime


class IntegrationsRepo(Repository):
    # ------------------------------------------------------------ integrations

    async def create(
        self,
        tenant_id: str,
        kind: str,
        name: str,
        *,
        integration_id: Optional[UUID] = None,
        config: Optional[Mapping[str, Any]] = None,
        secret_ciphertext: Optional[str] = None,
        events: Sequence[str] = (),
        min_severity: str = "low",
        enabled: bool = True,
        created_by: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> Integration:
        """Create an integration. ``integration_id`` lets the caller bind an encrypted secret to the id first."""
        check_choice(kind, INTEGRATION_KINDS, "integration kind")
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    """
                    INSERT INTO integrations
                        (id, tenant_id, kind, name, enabled, config, secret_ciphertext, events, min_severity, created_by)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING *
                    """,
                    integration_id or uuid.uuid4(),
                    tenant_id,
                    kind,
                    name,
                    enabled,
                    dict(config or {}),
                    secret_ciphertext,
                    list(events),
                    min_severity,
                    created_by,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("this tenant already has an integration with this name") from exc
        return Integration.model_validate(dict(row))

    async def get(self, tenant_id: str, integration_id: UUID, *, conn: Optional[Connection] = None) -> Integration:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM integrations WHERE tenant_id = $1 AND id = $2", tenant_id, integration_id
            )
        found = to_model(Integration, row)
        if found is None:
            raise NotFound("integration", integration_id)
        return found

    async def list(
        self,
        tenant_id: str,
        *,
        enabled: Optional[bool] = None,
        kinds: Optional[Sequence[str]] = None,
        conn: Optional[Connection] = None,
    ) -> List[Integration]:
        kind_filter = check_choices(list(kinds) if kinds is not None else None, INTEGRATION_KINDS, "integration kind")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM integrations
                WHERE tenant_id = $1
                  AND ($2::boolean IS NULL OR enabled = $2)
                  AND ($3::text[] IS NULL OR kind = ANY($3::text[]))
                ORDER BY created_at, id
                """,
                tenant_id,
                enabled,
                kind_filter,
            )
        return to_models(Integration, rows)

    async def update(
        self,
        tenant_id: str,
        integration_id: UUID,
        *,
        name: str = UNSET,
        enabled: bool = UNSET,
        config: Mapping[str, Any] = UNSET,
        secret_ciphertext: Optional[str] = UNSET,
        events: Sequence[str] = UNSET,
        min_severity: str = UNSET,
        conn: Optional[Connection] = None,
    ) -> Integration:
        params = Params(tenant_id, integration_id)
        sets = set_clauses(
            {
                "name": name,
                "enabled": enabled,
                "config": dict(config) if config is not UNSET else UNSET,
                "secret_ciphertext": secret_ciphertext,
                "events": list(events) if events is not UNSET else UNSET,
                "min_severity": min_severity,
            },
            params,
        )
        if not sets:
            return await self.get(tenant_id, integration_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    f"UPDATE integrations SET {', '.join(sets)} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
                    *params.values,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("this tenant already has an integration with this name") from exc
        found = to_model(Integration, row)
        if found is None:
            raise NotFound("integration", integration_id)
        return found

    async def delete(self, tenant_id: str, integration_id: UUID, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                "DELETE FROM integrations WHERE tenant_id = $1 AND id = $2", tenant_id, integration_id
            )
        return status.endswith(" 1")

    # ------------------------------------------------------------------ outbox

    async def enqueue(
        self, tenant_id: str, entries: Sequence[NewOutboxEntry], *, conn: Optional[Connection] = None
    ) -> int:
        """Insert outbox rows; a (integration, ``dedupe_key``) already queued is skipped. Returns rows inserted."""
        if not entries:
            return 0
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                ENQUEUE_SQL,
                tenant_id,
                [e.model_dump(mode="json") for e in entries],
            )
        return int(status.split()[-1])

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
            row = await c.fetchrow(
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

    # ---------------------------------------------------------------- tickets

    async def find_ticket(
        self,
        tenant_id: str,
        integration_id: UUID,
        *,
        alert_id: str,
        escalation_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[ExternalTicket]:
        """The integration's ticket for this escalation, else one for the alert (a ticket is reused, not duplicated)."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                SELECT * FROM external_tickets
                WHERE tenant_id = $1 AND integration_id = $2
                  AND (($3::text IS NOT NULL AND escalation_id = $3) OR alert_id = $4)
                ORDER BY (escalation_id IS NOT DISTINCT FROM $3) DESC, created_at
                LIMIT 1
                """,
                tenant_id,
                integration_id,
                escalation_id,
                alert_id,
            )
        return to_model(ExternalTicket, row)

    async def get_ticket(self, tenant_id: str, ticket_id: UUID, *, conn: Optional[Connection] = None) -> ExternalTicket:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM external_tickets WHERE tenant_id = $1 AND id = $2", tenant_id, ticket_id)
        found = to_model(ExternalTicket, row)
        if found is None:
            raise NotFound("external ticket", ticket_id)
        return found

    async def add_ticket(
        self,
        tenant_id: str,
        integration_id: UUID,
        *,
        system: str,
        alert_id: str,
        external_key: str,
        escalation_id: Optional[str] = None,
        action_id: Optional[UUID] = None,
        external_id: Optional[str] = None,
        external_url: Optional[str] = None,
        external_status: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> ExternalTicket:
        """Link a ticket; an existing link for the same escalation, alert or key is returned instead."""
        check_choice(system, TICKETING_KINDS, "ticketing system")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO external_tickets
                    (tenant_id, integration_id, alert_id, escalation_id, action_id, system, external_key,
                     external_id, external_url, external_status, last_synced_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
                ON CONFLICT DO NOTHING
                RETURNING *
                """,
                tenant_id,
                integration_id,
                alert_id,
                escalation_id,
                action_id,
                system,
                external_key[:200],
                external_id[:200] if external_id else None,
                external_url[:2048] if external_url else None,
                external_status[:200] if external_status else None,
            )
            if row is None:
                row = await c.fetchrow(
                    """
                    SELECT * FROM external_tickets
                    WHERE tenant_id = $1 AND integration_id = $2
                      AND (external_key = $3 OR ($4::text IS NOT NULL AND escalation_id = $4)
                           OR ($4::text IS NULL AND escalation_id IS NULL AND alert_id = $5))
                    ORDER BY created_at LIMIT 1
                    """,
                    tenant_id,
                    integration_id,
                    external_key[:200],
                    escalation_id,
                    alert_id,
                )
        found = to_model(ExternalTicket, row)
        if found is None:
            raise Conflict("the ticket link conflicts with an existing one")
        return found

    async def link_escalation(
        self, tenant_id: str, ticket_id: UUID, escalation_id: str, *, conn: Optional[Connection] = None
    ) -> ExternalTicket:
        """Attach an alert's ticket to its escalation (when the escalation has none from this integration yet)."""
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    """
                    UPDATE external_tickets SET escalation_id = $3
                    WHERE tenant_id = $1 AND id = $2 AND escalation_id IS NULL
                    RETURNING *
                    """,
                    tenant_id,
                    ticket_id,
                    escalation_id,
                )
            except asyncpg.UniqueViolationError:
                row = None
            if row is None:
                row = await c.fetchrow(
                    "SELECT * FROM external_tickets WHERE tenant_id = $1 AND id = $2", tenant_id, ticket_id
                )
        found = to_model(ExternalTicket, row)
        if found is None:
            raise NotFound("external ticket", ticket_id)
        return found

    async def tickets(
        self,
        tenant_id: str,
        *,
        alert_id: Optional[str] = None,
        escalation_ids: Optional[Sequence[str]] = None,
        limit: int = 200,
        conn: Optional[Connection] = None,
    ) -> List[ExternalTicket]:
        check_limit(limit, maximum=MAX_DELIVERY_LIST)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM external_tickets
                WHERE tenant_id = $1
                  AND ($2::text IS NULL OR alert_id = $2)
                  AND ($3::text[] IS NULL OR escalation_id = ANY($3::text[]))
                ORDER BY created_at DESC, id
                LIMIT $4
                """,
                tenant_id,
                alert_id,
                list(escalation_ids) if escalation_ids is not None else None,
                limit,
            )
        return to_models(ExternalTicket, rows)

    async def tickets_due_for_sync_all_tenants(
        self, *, min_age_s: float, per_tenant: int, limit: int
    ) -> List[ExternalTicket]:
        """Open tickets of enabled integrations, least recently synced first, at most ``per_tenant`` per tenant."""
        async with self._system() as c:
            rows = await c.fetch(
                """
                SELECT * FROM (
                    SELECT t.*, row_number() OVER (
                        PARTITION BY t.tenant_id ORDER BY t.last_synced_at NULLS FIRST, t.created_at
                    ) AS rn
                    FROM external_tickets t
                    JOIN integrations i ON i.tenant_id = t.tenant_id AND i.id = t.integration_id
                    JOIN tenants tn ON tn.id = t.tenant_id
                    WHERE NOT t.resolved AND i.enabled AND tn.status = 'active'
                      AND (t.last_synced_at IS NULL OR t.last_synced_at < now() - make_interval(secs => $1))
                ) due
                WHERE due.rn <= $2
                ORDER BY due.last_synced_at NULLS FIRST, due.created_at
                LIMIT $3
                """,
                float(min_age_s),
                per_tenant,
                limit,
            )
        return to_models(ExternalTicket, rows)

    async def record_sync(
        self,
        tenant_id: str,
        ticket_id: UUID,
        *,
        external_status: Optional[str] = UNSET,
        resolved: bool = UNSET,
        resolved_by: Optional[str] = UNSET,
        sync_error: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[ExternalTicket]:
        """Store what the external system reported (or the sync error); returns the row before the change."""
        async with self._tenant(tenant_id, conn) as c:
            before = await c.fetchrow(
                "SELECT * FROM external_tickets WHERE tenant_id = $1 AND id = $2 FOR UPDATE", tenant_id, ticket_id
            )
            if before is None:
                return None
            await c.execute(
                """
                UPDATE external_tickets SET
                    external_status = CASE WHEN $3 THEN $4 ELSE external_status END,
                    resolved = CASE WHEN $5 THEN $6 ELSE resolved END,
                    resolved_by = CASE WHEN $7 THEN $8 ELSE resolved_by END,
                    sync_error = $9,
                    last_synced_at = now()
                WHERE tenant_id = $1 AND id = $2
                """,
                tenant_id,
                ticket_id,
                external_status is not UNSET,
                external_status[:200] if isinstance(external_status, str) else None,
                resolved is not UNSET,
                bool(resolved) if resolved is not UNSET else False,
                resolved_by is not UNSET,
                resolved_by[:200] if isinstance(resolved_by, str) else None,
                truncate(sync_error, MAX_ERROR_CHARS),
            )
        return to_model(ExternalTicket, before)
