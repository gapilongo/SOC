"""Tenants. Creation, listing, status and quotas are platform operations.

Listing goes through the ``lgsotf_platform_tenants`` function and updates run
in the target tenant's own scope, so both work for the least-privilege
runtime role (the API); the platform-admin check is the caller's.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

import asyncpg

from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.pagination import Params
from lg_sotf.db.repos._base import (
    UNSET,
    Connection,
    Record,
    Repository,
    check_choice,
    fetch_one,
    set_clauses,
    to_model,
    to_models,
)
from lg_sotf.db.tenancy import validate_tenant_id

TENANT_STATUSES = ("active", "suspended")
QUOTA_FIELDS = ("max_alerts_per_day", "max_sources", "max_users")
ONBOARDING_MARKS = ("dismissed_at", "autonomy_reviewed_at", "samples_sent_at")


class Tenant(Record):
    id: str
    name: str
    status: str
    settings: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    # Quotas (``None`` = unlimited) and first-run checklist state (migration 0004).
    max_alerts_per_day: Optional[int] = None
    max_sources: Optional[int] = None
    max_users: Optional[int] = None
    onboarding: Dict[str, Any] = {}

    @property
    def is_active(self) -> bool:
        return self.status == "active"


class TenantsRepo(Repository):
    async def get(self, tenant_id: str, *, for_update: bool = False, conn: Optional[Connection] = None) -> Tenant:
        """The tenant row; ``for_update`` locks it until the caller's transaction ends
        (read-modify-write of ``settings`` without lost updates)."""
        sql = "SELECT * FROM tenants WHERE id = $1 FOR UPDATE" if for_update else "SELECT * FROM tenants WHERE id = $1"
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(sql, tenant_id)
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
                row = await fetch_one(
                    c,
                    "INSERT INTO tenants (id, name, status, settings) VALUES ($1, $2, $3, $4) RETURNING *",
                    tenant_id,
                    name,
                    status,
                    dict(settings or {}),
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict(f"tenant already exists: {tenant_id}") from exc
        return Tenant.model_validate(dict(row))

    async def provision(self, tenant_id: str, name: str, *, conn: Optional[Connection] = None) -> Tenant:
        """Create a tenant through ``lgsotf_create_tenant`` (works for the runtime role); :class:`Conflict` if it exists.

        The function inserts only the id and name, so the runtime role can
        provision a tenant without INSERT on ``tenants`` or an RLS bypass.
        Callers authorise the request (platform admins only).

        With ``conn`` (a ``db.tenant_tx(tenant_id)`` transaction) the row is
        created in that transaction, so the tenant's settings, first user and
        audit entries commit with it. The function turns ``app.bypass_rls`` on
        only for its own insert and restores it, transaction-locally. A
        concurrent provisioning of the same id waits for this transaction and
        then gets :class:`Conflict` if it committed.
        """
        validate_tenant_id(tenant_id)
        if conn is None:
            async with self._lookup() as c:
                row = await c.fetchrow("SELECT * FROM lgsotf_create_tenant($1, $2)", tenant_id, name)
        else:
            async with self._tenant(tenant_id, conn) as c:
                row = await c.fetchrow("SELECT * FROM lgsotf_create_tenant($1, $2)", tenant_id, name)
        if row is None:
            raise Conflict(f"tenant already exists: {tenant_id}")
        return Tenant.model_validate(dict(row))

    async def ensure(self, tenant_id: str, name: str) -> Tenant:
        """Create the tenant if missing and return it (bootstrap, idempotent)."""
        validate_tenant_id(tenant_id)
        async with self._system() as c:
            await c.execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING", tenant_id, name
            )
            row = await fetch_one(c, "SELECT * FROM tenants WHERE id = $1", tenant_id)
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

    async def set_status(self, tenant_id: str, status: str, *, conn: Optional[Connection] = None) -> Tenant:
        """Suspend or reactivate a tenant (platform operation)."""
        return await self.update_admin(tenant_id, status=status, conn=conn)

    async def update_admin(
        self,
        tenant_id: str,
        *,
        name: str = UNSET,
        status: str = UNSET,
        max_alerts_per_day: Optional[int] = UNSET,
        max_sources: Optional[int] = UNSET,
        max_users: Optional[int] = UNSET,
        conn: Optional[Connection] = None,
    ) -> Tenant:
        """Change name, status or quotas (platform operation; ``None`` quota = unlimited)."""
        if status is not UNSET:
            check_choice(status, TENANT_STATUSES, "tenant status")
        for label, value in (
            ("max_alerts_per_day", max_alerts_per_day),
            ("max_sources", max_sources),
            ("max_users", max_users),
        ):
            if value is not UNSET and value is not None and (isinstance(value, bool) or value < 0):
                raise ValueError(f"{label} must be a non-negative integer or None")
        params = Params(tenant_id)
        sets = set_clauses(
            {
                "name": name,
                "status": status,
                "max_alerts_per_day": max_alerts_per_day,
                "max_sources": max_sources,
                "max_users": max_users,
            },
            params,
        )
        if not sets:
            return await self.get(tenant_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"UPDATE tenants SET {', '.join(sets)} WHERE id = $1 RETURNING *",  # noqa: S608
                *params.values,
            )
        tenant = to_model(Tenant, row)
        if tenant is None:
            raise NotFound("tenant", tenant_id)
        return tenant

    async def mark_onboarding(
        self, tenant_id: str, mark: str, *, overwrite: bool = False, conn: Optional[Connection] = None
    ) -> Tenant:
        """Record a first-run checklist timestamp (``onboarding.<mark>``); kept as is when set unless ``overwrite``."""
        check_choice(mark, ONBOARDING_MARKS, "onboarding mark")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE tenants
                SET onboarding = CASE WHEN $3 OR NOT onboarding ? $2
                                      THEN onboarding || jsonb_build_object($2::text, now())
                                      ELSE onboarding END
                WHERE id = $1
                RETURNING *
                """,
                tenant_id,
                mark,
                overwrite,
            )
        tenant = to_model(Tenant, row)
        if tenant is None:
            raise NotFound("tenant", tenant_id)
        return tenant

    async def list_all_tenants(self, *, status: Optional[str] = None) -> List[Tenant]:
        """Every tenant, by id (``lgsotf_platform_tenants``; platform callers only)."""
        if status is not None:
            check_choice(status, TENANT_STATUSES, "tenant status")
        async with self._lookup() as c:
            rows = await c.fetch("SELECT * FROM lgsotf_platform_tenants()")
        return [t for t in to_models(Tenant, rows) if status is None or t.status == status]
