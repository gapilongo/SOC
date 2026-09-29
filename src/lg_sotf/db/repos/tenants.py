"""Tenants. Creation and listing are platform (system) operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

import asyncpg

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.repos._base import Connection, Record, Repository, check_choice, to_model, to_models
from lg_sotf.db.tenancy import validate_tenant_id

TENANT_STATUSES = ("active", "suspended")


class Tenant(Record):
    id: str
    name: str
    status: str
    settings: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class TenantsRepo(Repository):
    async def get(self, tenant_id: str, *, conn: Optional[Connection] = None) -> Tenant:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM tenants WHERE id = $1", tenant_id)
        tenant = to_model(Tenant, row)
        if tenant is None:
            raise NotFound("tenant", tenant_id)
        return tenant

    async def create(
        self,
        tenant_id: str,
        name: str,
        *,
        settings: Optional[Mapping[str, Any]] = None,
        status: str = "active",
    ) -> Tenant:
        """Create a tenant (platform operation); :class:`Conflict` if it exists."""
        validate_tenant_id(tenant_id)
        check_choice(status, TENANT_STATUSES, "tenant status")
        async with self._system() as c:
            try:
                row = await c.fetchrow(
                    "INSERT INTO tenants (id, name, status, settings) VALUES ($1, $2, $3, $4) RETURNING *",
                    tenant_id,
                    name,
                    status,
                    dict(settings or {}),
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict(f"tenant already exists: {tenant_id}") from exc
        return Tenant.model_validate(dict(row))

    async def ensure(self, tenant_id: str, name: str) -> Tenant:
        """Create the tenant if missing and return it (bootstrap, idempotent)."""
        validate_tenant_id(tenant_id)
        async with self._system() as c:
            await c.execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING", tenant_id, name
            )
            row = await c.fetchrow("SELECT * FROM tenants WHERE id = $1", tenant_id)
        return Tenant.model_validate(dict(row))

    async def update_settings(
        self,
        tenant_id: str,
        patch: Mapping[str, Any],
        *,
        replace: bool = False,
        conn: Optional[Connection] = None,
    ) -> Tenant:
        """Merge ``patch`` into the tenant settings (top-level JSON merge patch).

        Keys whose value is ``None`` are removed. With ``replace=True`` the
        settings become exactly ``patch`` (minus ``None`` values).
        """
        patch = dict(patch)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE tenants
                SET settings = (CASE WHEN $3 THEN '{}'::jsonb ELSE settings END || $2::jsonb)
                    - ARRAY(SELECT key FROM jsonb_each($2::jsonb) WHERE value = 'null'::jsonb)
                WHERE id = $1
                RETURNING *
                """,
                tenant_id,
                patch,
                replace,
            )
        tenant = to_model(Tenant, row)
        if tenant is None:
            raise NotFound("tenant", tenant_id)
        return tenant

    async def set_status(self, tenant_id: str, status: str) -> Tenant:
        """Suspend or reactivate a tenant (platform operation)."""
        validate_tenant_id(tenant_id)
        check_choice(status, TENANT_STATUSES, "tenant status")
        async with self._system() as c:
            row = await c.fetchrow("UPDATE tenants SET status = $2 WHERE id = $1 RETURNING *", tenant_id, status)
        tenant = to_model(Tenant, row)
        if tenant is None:
            raise NotFound("tenant", tenant_id)
        return tenant

    async def list_all_tenants(self, *, status: Optional[str] = None) -> List[Tenant]:
        if status is not None:
            check_choice(status, TENANT_STATUSES, "tenant status")
        async with self._system() as c:
            rows = await c.fetch("SELECT * FROM tenants WHERE ($1::text IS NULL OR status = $1) ORDER BY id", status)
        return to_models(Tenant, rows)
