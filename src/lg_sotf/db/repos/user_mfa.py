"""TOTP enrollment state per local user (``user_mfa``).

The secret is stored only as ``SecretBox`` ciphertext bound to the tenant
and user; recovery codes only as keyed hashes. Every state change that must
not happen twice is a single conditional ``UPDATE``: a time step is consumed
only when it is newer than the last one used, a recovery code only while its
hash is still in the set, and a pending secret is activated only if it is
still the one the caller verified. Concurrent requests with the same code
therefore cannot both succeed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Sequence
from uuid import UUID

from pydantic import Field

from lg_sotf.db.repos._base import Connection, Record, Repository, fetch_one, to_model

MAX_RECOVERY_CODES = 20


class UserMfa(Record):
    tenant_id: str
    user_id: UUID
    secret_ciphertext: Optional[str] = Field(default=None, repr=False)
    pending_secret_ciphertext: Optional[str] = Field(default=None, repr=False)
    pending_created_at: Optional[datetime] = None
    enabled_at: Optional[datetime] = None
    last_used_step: Optional[int] = None
    recovery_code_hashes: List[str] = Field(default_factory=list, repr=False)
    recovery_codes_generated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    @property
    def enabled(self) -> bool:
        return self.enabled_at is not None and self.secret_ciphertext is not None

    @property
    def recovery_codes_remaining(self) -> int:
        return len(self.recovery_code_hashes)


def _check_hashes(hashes: Sequence[str]) -> List[str]:
    if len(hashes) > MAX_RECOVERY_CODES or len(set(hashes)) != len(hashes):
        raise ValueError(f"expected at most {MAX_RECOVERY_CODES} distinct recovery code hashes")
    return list(hashes)


class UserMfaRepo(Repository):
    async def get(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> Optional[UserMfa]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM user_mfa WHERE tenant_id = $1 AND user_id = $2", tenant_id, user_id)
        return to_model(UserMfa, row)

    async def enabled_since(self, tenant_id: str, *, conn: Optional[Connection] = None) -> Dict[UUID, datetime]:
        """``user_id -> enabled_at`` for every user of the tenant with MFA active."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT user_id, enabled_at FROM user_mfa WHERE tenant_id = $1 AND enabled_at IS NOT NULL",
                tenant_id,
            )
        return {r["user_id"]: r["enabled_at"] for r in rows}

    async def set_pending(
        self, tenant_id: str, user_id: UUID, ciphertext: str, *, conn: Optional[Connection] = None
    ) -> UserMfa:
        """Store a new, not yet confirmed secret; an active secret stays in force until confirmation."""
        async with self._tenant(tenant_id, conn) as c:
            row = await fetch_one(
                c,
                """
                INSERT INTO user_mfa (tenant_id, user_id, pending_secret_ciphertext, pending_created_at)
                VALUES ($1, $2, $3, now())
                ON CONFLICT (tenant_id, user_id) DO UPDATE
                SET pending_secret_ciphertext = EXCLUDED.pending_secret_ciphertext,
                    pending_created_at = EXCLUDED.pending_created_at
                RETURNING *
                """,
                tenant_id,
                user_id,
                ciphertext,
            )
        return UserMfa.model_validate(dict(row))

    async def activate(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        pending_ciphertext: str,
        step: int,
        recovery_code_hashes: Sequence[str],
        conn: Optional[Connection] = None,
    ) -> Optional[UserMfa]:
        """Promote the pending secret the caller verified; ``None`` when it changed meanwhile."""
        hashes = _check_hashes(recovery_code_hashes)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE user_mfa
                SET secret_ciphertext = pending_secret_ciphertext,
                    pending_secret_ciphertext = NULL,
                    pending_created_at = NULL,
                    enabled_at = now(),
                    last_used_step = $4,
                    recovery_code_hashes = $5::text[],
                    recovery_codes_generated_at = now()
                WHERE tenant_id = $1 AND user_id = $2 AND pending_secret_ciphertext = $3
                RETURNING *
                """,
                tenant_id,
                user_id,
                pending_ciphertext,
                step,
                hashes,
            )
        return to_model(UserMfa, row)

    async def consume_step(
        self, tenant_id: str, user_id: UUID, step: int, *, conn: Optional[Connection] = None
    ) -> bool:
        """Record ``step`` as used; ``False`` when it (or a later one) was used already."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE user_mfa SET last_used_step = $3
                WHERE tenant_id = $1 AND user_id = $2 AND enabled_at IS NOT NULL
                  AND (last_used_step IS NULL OR last_used_step < $3)
                RETURNING 1
                """,
                tenant_id,
                user_id,
                step,
            )
        return row is not None

    async def consume_recovery_code(
        self, tenant_id: str, user_id: UUID, code_hash: str, *, conn: Optional[Connection] = None
    ) -> Optional[int]:
        """Remove one stored recovery code; the number left, or ``None`` when it was not there."""
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE user_mfa SET recovery_code_hashes = array_remove(recovery_code_hashes, $3)
                WHERE tenant_id = $1 AND user_id = $2 AND enabled_at IS NOT NULL
                  AND $3 = ANY (recovery_code_hashes)
                RETURNING cardinality(recovery_code_hashes) AS remaining
                """,
                tenant_id,
                user_id,
                code_hash,
            )
        return None if row is None else int(row["remaining"])

    async def replace_recovery_codes(
        self, tenant_id: str, user_id: UUID, hashes: Sequence[str], *, conn: Optional[Connection] = None
    ) -> Optional[UserMfa]:
        checked = _check_hashes(hashes)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE user_mfa SET recovery_code_hashes = $3::text[], recovery_codes_generated_at = now()
                WHERE tenant_id = $1 AND user_id = $2 AND enabled_at IS NOT NULL
                RETURNING *
                """,
                tenant_id,
                user_id,
                checked,
            )
        return to_model(UserMfa, row)

    async def rewrap_secret(
        self, tenant_id: str, user_id: UUID, old: str, new: str, *, conn: Optional[Connection] = None
    ) -> bool:
        """Replace the active ciphertext (same secret, new encryption key) if it is still ``old``."""
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute(
                "UPDATE user_mfa SET secret_ciphertext = $4 WHERE tenant_id = $1 AND user_id = $2 AND secret_ciphertext = $3",
                tenant_id,
                user_id,
                old,
                new,
            )
        return status.endswith(" 1")

    async def delete(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute("DELETE FROM user_mfa WHERE tenant_id = $1 AND user_id = $2", tenant_id, user_id)
        return status.endswith(" 1")
