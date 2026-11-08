"""MSSP organisations, their members and the grants customer tenants give them (migration 0012).

An organisation is keyed by its home tenant id (``organisations.tenant_id``).
Grant rows belong to the customer tenant (``tenant_id``), which alone writes
them; the organisation reads its own grants inside its home tenant's
transaction (the ``org_read`` policy).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
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
from lg_sotf.models.vocabulary import ROLE_RANK, ROLES


class Organisation(Record):
    tenant_id: str
    name: str
    created_at: datetime


class OrganisationMember(Record):
    tenant_id: str
    user_id: UUID
    added_by: Optional[str]
    created_at: datetime


class TenantGrant(Record):
    id: UUID
    tenant_id: str
    organisation_id: str
    user_id: Optional[UUID]
    role: str
    allow_api_keys: bool
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime]
    revoked_by: Optional[str]

    def is_active(self, now: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > now


class OrganisationsRepo(Repository):
    async def upsert(self, tenant_id: str, name: str, *, conn: Optional[Connection] = None) -> Organisation:
        """Make ``tenant_id`` an organisation (or rename it), through ``lgsotf_save_organisation``."""
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(c, "SELECT * FROM lgsotf_save_organisation($1, $2)", tenant_id, name)
        return Organisation.model_validate(dict(row))

    async def get(self, tenant_id: str, *, conn: Optional[Connection] = None) -> Optional[Organisation]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM organisations WHERE tenant_id = $1", tenant_id)
        return to_model(Organisation, row)

    async def is_member(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            return bool(
                await c.fetchval(
                    "SELECT 1 FROM organisation_members WHERE tenant_id = $1 AND user_id = $2", tenant_id, user_id
                )
            )

    async def add_member(
        self, tenant_id: str, user_id: UUID, *, added_by: Optional[str] = None, conn: Optional[Connection] = None
    ) -> OrganisationMember:
        """Add a staff account of the home tenant (idempotent: an existing membership is returned as is)."""
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                WITH added AS (
                    INSERT INTO organisation_members (tenant_id, user_id, added_by) VALUES ($1, $2, $3)
                    ON CONFLICT (tenant_id, user_id) DO NOTHING
                    RETURNING *
                )
                SELECT * FROM added
                UNION ALL SELECT * FROM organisation_members WHERE tenant_id = $1 AND user_id = $2
                LIMIT 1
                """,
                tenant_id,
                user_id,
                added_by,
            )
        return OrganisationMember.model_validate(dict(row))

    async def remove_member(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> bool:
        """Remove a member; the customers' grant rows naming them stay (as records), but no longer work."""
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                "DELETE FROM organisation_members WHERE tenant_id = $1 AND user_id = $2", tenant_id, user_id
            )
        return status.endswith(" 1")

    async def list_members(self, tenant_id: str, *, conn: Optional[Connection] = None) -> List[OrganisationMember]:
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT * FROM organisation_members WHERE tenant_id = $1 ORDER BY created_at, user_id", tenant_id
            )
        return to_models(OrganisationMember, rows)


class GrantsRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        organisation_id: str,
        role: str,
        *,
        reason: str,
        created_by: str,
        expires_at: datetime,
        user_id: Optional[UUID] = None,
        allow_api_keys: bool = False,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> TenantGrant:
        """Open ``tenant_id`` (the customer) to ``organisation_id``, or to one of its members (``user_id``)."""
        check_choice(role, ROLES, "role")
        require_aware(expires_at, "expires_at")
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO tenant_grants
                    (tenant_id, organisation_id, user_id, role, reason, created_by, created_at, expires_at, allow_api_keys)
                VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()), $8, $9)
                RETURNING *
                """,
                tenant_id,
                organisation_id,
                user_id,
                role,
                reason,
                created_by,
                now,
                expires_at,
                allow_api_keys,
            )
        return TenantGrant.model_validate(dict(row))

    async def get(self, tenant_id: str, grant_id: UUID, *, conn: Optional[Connection] = None) -> Optional[TenantGrant]:
        """A grant of the customer tenant ``tenant_id``."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM tenant_grants WHERE tenant_id = $1 AND id = $2", tenant_id, grant_id)
        return to_model(TenantGrant, row)

    async def list_for_tenant(self, tenant_id: str, *, conn: Optional[Connection] = None) -> List[TenantGrant]:
        """Every grant the customer tenant gave, revoked and expired ones included, newest first."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT * FROM tenant_grants WHERE tenant_id = $1 ORDER BY created_at DESC, id", tenant_id
            )
        return to_models(TenantGrant, rows)

    async def list_for_organisation(
        self, organisation_id: str, *, conn: Optional[Connection] = None
    ) -> List[TenantGrant]:
        """The organisation's grants that are neither revoked nor expired, read in its home tenant."""
        async with self._tenant(organisation_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM tenant_grants
                WHERE organisation_id = $1 AND revoked_at IS NULL AND expires_at > now()
                ORDER BY tenant_id, expires_at DESC, id
                """,
                organisation_id,
            )
        return to_models(TenantGrant, rows)

    async def active_for(
        self,
        organisation_id: str,
        tenant_id: str,
        user_id: UUID,
        *,
        api_key: bool = False,
        conn: Optional[Connection] = None,
    ) -> Optional[TenantGrant]:
        """The strongest live grant letting member ``user_id`` of the organisation act in ``tenant_id``.

        Read in the organisation's home tenant; ``None`` unless the user is a
        member and a grant to the organisation (or to that user) is neither
        revoked nor expired at this transaction's ``now()``. For an API key
        (``api_key``; ``user_id`` is the member who created it) only grants to
        the whole organisation that allow API keys count.
        """
        async with self._tenant(organisation_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT g.* FROM tenant_grants g
                WHERE g.organisation_id = $1 AND g.tenant_id = $2
                  AND g.revoked_at IS NULL AND g.expires_at > now()
                  AND (g.user_id IS NULL OR (NOT $4 AND g.user_id = $3))
                  AND (NOT $4 OR g.allow_api_keys)
                  AND EXISTS (
                      SELECT 1 FROM organisation_members m WHERE m.tenant_id = g.organisation_id AND m.user_id = $3
                  )
                """,
                organisation_id,
                tenant_id,
                user_id,
                api_key,
            )
        grants = to_models(TenantGrant, rows)
        return max(grants, key=lambda g: (ROLE_RANK[g.role], g.expires_at), default=None)

    async def revoke(
        self, tenant_id: str, grant_id: UUID, *, revoked_by: str, conn: Optional[Connection] = None
    ) -> Optional[TenantGrant]:
        """Revoke a live grant of the customer tenant; ``None`` when there is none to revoke."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE tenant_grants SET revoked_at = now(), revoked_by = $3
                WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
                RETURNING *
                """,
                tenant_id,
                grant_id,
                revoked_by,
            )
        return to_model(TenantGrant, row)
