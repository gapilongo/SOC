"""External tickets (Jira, ServiceNow) linked to alerts and escalations.

At most one ticket per escalation (or alert) and integration: an alert's
existing ticket is reused and linked to its escalation. The scheduler polls
open tickets (:func:`lg_sotf.integrations.delivery.sync_tickets`).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence
from uuid import UUID

import asyncpg

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    to_model,
    to_models,
    truncate,
)
from lg_sotf.db.repos.integrations import TICKETING_KINDS

MAX_ERROR_CHARS = 1_000
MAX_TICKET_LIST = 200


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


class TicketsRepo(Repository):
    async def find(
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

    async def get(self, tenant_id: str, ticket_id: UUID, *, conn: Optional[Connection] = None) -> ExternalTicket:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM external_tickets WHERE tenant_id = $1 AND id = $2", tenant_id, ticket_id)
        found = to_model(ExternalTicket, row)
        if found is None:
            raise NotFound("external ticket", ticket_id)
        return found

    async def add(
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

    async def list(
        self,
        tenant_id: str,
        *,
        alert_id: Optional[str] = None,
        escalation_ids: Optional[Sequence[str]] = None,
        limit: int = 200,
        conn: Optional[Connection] = None,
    ) -> List[ExternalTicket]:
        check_limit(limit, maximum=MAX_TICKET_LIST)
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

    async def due_for_sync_all_tenants(
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
