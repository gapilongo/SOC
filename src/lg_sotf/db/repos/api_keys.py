"""API keys. Only the sha256 hex digest of the secret is stored."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence
from uuid import UUID

import asyncpg
from pydantic import Field

from lg_sotf.db.errors import Conflict
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_choice,
    check_sha256_hex,
    require_aware,
    to_model,
    to_models,
)
from lg_sotf.models.vocabulary import SCOPES as API_KEY_SCOPES


class ApiKey(Record):
    id: UUID
    tenant_id: str
    name: str
    prefix: str
    key_hash: str = Field(repr=False)
    scopes: List[str]
    created_by: Optional[UUID]
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class ApiKeysRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        name: str,
        prefix: str,
        key_hash: str,
        scopes: Sequence[str],
        *,
        created_by: Optional[UUID] = None,
        key_id: Optional[UUID] = None,
        conn: Optional[Connection] = None,
    ) -> ApiKey:
        """Store a new key. Pass ``key_id`` when the id is embedded in the key string."""
        check_sha256_hex(key_hash, "key_hash")
        scopes = sorted(set(scopes))
        if not scopes:
            raise ValueError("an API key needs at least one scope")
        for scope in scopes:
            check_choice(scope, API_KEY_SCOPES, "scope")
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    """
                    INSERT INTO api_keys (id, tenant_id, name, prefix, key_hash, scopes, created_by)
                    VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7)
                    RETURNING *
                    """,
                    key_id,
                    tenant_id,
                    name,
                    prefix,
                    key_hash,
                    scopes,
                    created_by,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("API key id or hash already exists") from exc
        return ApiKey.model_validate(dict(row))

    async def get_by_id(self, tenant_id: str, key_id: UUID, *, conn: Optional[Connection] = None) -> Optional[ApiKey]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM api_keys WHERE tenant_id = $1 AND id = $2", tenant_id, key_id)
        return to_model(ApiKey, row)

    async def get_by_id_all_tenants(self, key_id: UUID) -> Optional[ApiKey]:
        """Look up a presented key by id before the tenant is known (authentication).

        Uses the ``lgsotf_auth_api_key`` lookup function, so it works for the
        runtime role, which cannot read other tenants itself.
        """
        async with self._lookup() as c:
            row = await c.fetchrow("SELECT * FROM lgsotf_auth_api_key($1)", key_id)
        return to_model(ApiKey, row)

    async def list(
        self, tenant_id: str, *, include_revoked: bool = False, conn: Optional[Connection] = None
    ) -> List[ApiKey]:
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM api_keys
                WHERE tenant_id = $1 AND ($2 OR revoked_at IS NULL)
                ORDER BY created_at DESC, id
                """,
                tenant_id,
                include_revoked,
            )
        return to_models(ApiKey, rows)

    async def revoke(
        self,
        tenant_id: str,
        key_id: UUID,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> bool:
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE api_keys SET revoked_at = COALESCE($3::timestamptz, now())
                WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
                """,
                tenant_id,
                key_id,
                now,
            )
        return status.endswith(" 1")

    async def touch_last_used(
        self,
        tenant_id: str,
        key_id: UUID,
        *,
        now: Optional[datetime] = None,
        min_interval_s: int = 60,
        conn: Optional[Connection] = None,
    ) -> bool:
        """Record use at most once per ``min_interval_s``; True if a write happened."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE api_keys SET last_used_at = COALESCE($3::timestamptz, now())
                WHERE tenant_id = $1 AND id = $2
                  AND (last_used_at IS NULL
                       OR last_used_at < COALESCE($3::timestamptz, now()) - make_interval(secs => $4))
                """,
                tenant_id,
                key_id,
                now,
                float(min_interval_s),
            )
        return status.endswith(" 1")
