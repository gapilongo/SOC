"""Rotating refresh tokens with reuse detection.

Only the sha256 hex digest of a token is stored. Rotating a token revokes it
and links it to its replacement; presenting a rotated token again means it
leaked, so every token of that user is revoked.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import Field

from lg_sotf.db.errors import RefreshTokenInvalid, RefreshTokenReuse
from lg_sotf.db.repos._base import (
    Connection,
    Record,
    Repository,
    check_sha256_hex,
    require_aware,
    to_model,
    utcnow,
)


class RefreshToken(Record):
    id: UUID
    tenant_id: str
    user_id: UUID
    token_hash: str = Field(repr=False)
    expires_at: datetime
    revoked_at: Optional[datetime]
    replaced_by: Optional[UUID]
    created_at: datetime

    def is_active(self, now: Optional[datetime] = None) -> bool:
        return self.revoked_at is None and self.expires_at > (now or utcnow())


class RefreshTokensRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        *,
        conn: Optional[Connection] = None,
    ) -> RefreshToken:
        require_aware(expires_at, "expires_at")
        check_sha256_hex(token_hash, "token_hash")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                INSERT INTO refresh_tokens (tenant_id, user_id, token_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING *
                """,
                tenant_id,
                user_id,
                token_hash,
                expires_at,
            )
        return RefreshToken.model_validate(dict(row))

    async def get_by_hash(
        self, tenant_id: str, token_hash: str, *, conn: Optional[Connection] = None
    ) -> Optional[RefreshToken]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2", tenant_id, token_hash
            )
        return to_model(RefreshToken, row)

    async def get_by_hash_all_tenants(self, token_hash: str) -> Optional[RefreshToken]:
        """Resolve a presented cookie to its tenant before a tenant scope exists.

        Uses the ``lgsotf_auth_refresh_token`` lookup function, so it works for
        the runtime role, which cannot read other tenants itself.
        """
        check_sha256_hex(token_hash, "token_hash")
        async with self._lookup() as c:
            row = await c.fetchrow("SELECT * FROM lgsotf_auth_refresh_token($1)", token_hash)
        return to_model(RefreshToken, row)

    async def rotate(
        self,
        tenant_id: str,
        token_hash: str,
        new_token_hash: str,
        new_expires_at: datetime,
        *,
        now: Optional[datetime] = None,
    ) -> RefreshToken:
        """Exchange a valid token for a new one.

        Raises :class:`RefreshTokenInvalid` for unknown, expired or logged-out
        tokens and :class:`RefreshTokenReuse` (after revoking and committing
        every token of the user) when an already-rotated token is presented.
        """
        require_aware(new_expires_at, "new_expires_at")
        require_aware(now, "now")
        check_sha256_hex(new_token_hash, "new_token_hash")
        at = now or utcnow()
        reuse_user: Optional[UUID] = None
        revoked = 0
        async with self._tenant(tenant_id) as c:
            old = await c.fetchrow(
                "SELECT * FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE",
                tenant_id,
                token_hash,
            )
            if old is None:
                raise RefreshTokenInvalid("not_found")
            if old["revoked_at"] is not None:
                if old["replaced_by"] is None:
                    raise RefreshTokenInvalid("revoked")
                reuse_user = old["user_id"]
                revoked = await self._revoke_all(c, tenant_id, reuse_user, at)
            elif old["expires_at"] <= at:
                raise RefreshTokenInvalid("expired")
            else:
                new = await c.fetchrow(
                    """
                    INSERT INTO refresh_tokens (tenant_id, user_id, token_hash, expires_at, created_at)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING *
                    """,
                    tenant_id,
                    old["user_id"],
                    new_token_hash,
                    new_expires_at,
                    at,
                )
                await c.execute(
                    "UPDATE refresh_tokens SET revoked_at = $3, replaced_by = $4 WHERE tenant_id = $1 AND id = $2",
                    tenant_id,
                    old["id"],
                    at,
                    new["id"],
                )
                return RefreshToken.model_validate(dict(new))
        raise RefreshTokenReuse(reuse_user, revoked)

    async def revoke(
        self,
        tenant_id: str,
        token_hash: str,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> bool:
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                """
                UPDATE refresh_tokens SET revoked_at = COALESCE($3::timestamptz, now())
                WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL
                """,
                tenant_id,
                token_hash,
                now,
            )
        return status.endswith(" 1")

    async def revoke_lineage(
        self,
        tenant_id: str,
        token_hash: str,
        *,
        now: Optional[datetime] = None,
    ) -> int:
        """Revoke a token and every token it was rotated into (logout).

        A refresh that rotates the presented token while the logout runs
        would otherwise leave its replacement valid: ``revoke`` skips a token
        that is already revoked, and the browser now holds the replacement.
        Each link is locked before it is read, so a rotation in progress
        commits first and its replacement is seen and revoked; a rotation
        that starts later finds its token revoked. Returns the number of
        tokens revoked here.
        """
        require_aware(now, "now")
        check_sha256_hex(token_hash, "token_hash")
        at = now or utcnow()
        revoked = 0
        seen: set[UUID] = set()
        async with self._tenant(tenant_id) as c:
            row = await c.fetchrow(
                "SELECT id, revoked_at, replaced_by FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE",
                tenant_id,
                token_hash,
            )
            while row is not None and row["id"] not in seen:
                seen.add(row["id"])
                if row["revoked_at"] is None:
                    await c.execute(
                        "UPDATE refresh_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2",
                        tenant_id,
                        row["id"],
                        at,
                    )
                    revoked += 1
                if row["replaced_by"] is None:
                    break
                row = await c.fetchrow(
                    "SELECT id, revoked_at, replaced_by FROM refresh_tokens WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
                    tenant_id,
                    row["replaced_by"],
                )
        return revoked

    async def revoke_all_for_user(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> int:
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            return await self._revoke_all(c, tenant_id, user_id, now or utcnow())

    @staticmethod
    async def _revoke_all(c: Connection, tenant_id: str, user_id: UUID, at: datetime) -> int:
        status = await c.execute(
            """
            UPDATE refresh_tokens SET revoked_at = $3
            WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
            """,
            tenant_id,
            user_id,
            at,
        )
        return int(status.split()[-1])
