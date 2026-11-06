"""Integrations: the tenant's notification channels, ticketing systems and response connectors.

The outbox they deliver through is :mod:`lg_sotf.db.repos.outbox`; the external
tickets they open are :mod:`lg_sotf.db.repos.tickets`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence
from uuid import UUID

import asyncpg
from pydantic import Field

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.pagination import Params
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    check_choices,
    fetch_one,
    set_clauses,
    to_model,
    to_models,
)

INTEGRATION_KINDS = ("slack", "teams", "email", "webhook", "jira", "servicenow", "microsoft")
TICKETING_KINDS = ("jira", "servicenow")
MICROSOFT_UNIQUE_INDEX = "ux_integrations_microsoft"


class IntegrationExists(Conflict):
    """The tenant already has the one integration of this kind it may have (``microsoft``)."""


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


class IntegrationsRepo(Repository):
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
                row = await fetch_one(
                    c,
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
                if getattr(exc, "constraint_name", None) == MICROSOFT_UNIQUE_INDEX:
                    raise IntegrationExists("this tenant already has a Microsoft integration") from exc
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
