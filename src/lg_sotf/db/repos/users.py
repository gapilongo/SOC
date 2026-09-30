"""Local users, login bookkeeping and lockout."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
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
    require_aware,
    set_clauses,
    to_model,
    to_models,
    utcnow,
)
from lg_sotf.settings import get_settings

ROLES = ("admin", "analyst", "viewer")


class User(Record):
    id: UUID
    tenant_id: str
    email: str
    password_hash: Optional[str] = Field(default=None, repr=False)
    role: str
    is_platform_admin: bool
    is_active: bool
    failed_logins: int
    locked_until: Optional[datetime]
    last_login_at: Optional[datetime]
    #: IdP ``sub`` of an account created or linked by OIDC just-in-time provisioning.
    oidc_subject: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    def is_locked(self, now: Optional[datetime] = None) -> bool:
        return self.locked_until is not None and self.locked_until > (now or utcnow())


def normalize_email(email: str) -> str:
    value = email.strip().lower()
    local, sep, domain = value.partition("@")
    if not sep or not local or not domain or len(value) > 320:
        raise ValueError("invalid email address")
    return value


class UsersRepo(Repository):
    async def create(
        self,
        tenant_id: str,
        email: str,
        role: str,
        *,
        password_hash: Optional[str] = None,
        is_platform_admin: bool = False,
        is_active: bool = True,
        oidc_subject: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> User:
        check_choice(role, ROLES, "role")
        email = normalize_email(email)
        async with self._tenant(tenant_id, conn) as c:
            try:
                row = await c.fetchrow(
                    """
                    INSERT INTO users (tenant_id, email, password_hash, role, is_platform_admin, is_active, oidc_subject)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING *
                    """,
                    tenant_id,
                    email,
                    password_hash,
                    role,
                    is_platform_admin,
                    is_active,
                    oidc_subject,
                )
            except asyncpg.UniqueViolationError as exc:
                raise Conflict("a user with this email already exists in the tenant") from exc
        return User.model_validate(dict(row))

    async def get(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> User:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM users WHERE tenant_id = $1 AND id = $2", tenant_id, user_id)
        user = to_model(User, row)
        if user is None:
            raise NotFound("user", user_id)
        return user

    async def get_by_email(self, tenant_id: str, email: str, *, conn: Optional[Connection] = None) -> Optional[User]:
        email = normalize_email(email)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow("SELECT * FROM users WHERE tenant_id = $1 AND email = $2", tenant_id, email)
        return to_model(User, row)

    async def get_by_oidc_subject(
        self, tenant_id: str, subject: str, *, conn: Optional[Connection] = None
    ) -> Optional[User]:
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                "SELECT * FROM users WHERE tenant_id = $1 AND oidc_subject = $2", tenant_id, subject
            )
        return to_model(User, row)

    async def find_by_email_all_tenants(self, email: str) -> List[User]:
        """Every account with this email across tenants (login without a tenant hint).

        Uses the ``lgsotf_auth_users_by_email`` lookup function, so it works
        for the runtime role, which cannot read other tenants itself.
        """
        email = normalize_email(email)
        async with self._lookup() as c:
            rows = await c.fetch("SELECT * FROM lgsotf_auth_users_by_email($1)", email)
        return to_models(User, rows)

    async def list(
        self,
        tenant_id: str,
        *,
        include_inactive: bool = True,
        limit: int = 500,
        offset: int = 0,
        conn: Optional[Connection] = None,
    ) -> List[User]:
        if limit < 1 or limit > 1000 or offset < 0:
            raise ValueError("limit must be 1..1000 and offset >= 0")
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM users
                WHERE tenant_id = $1 AND ($2 OR is_active)
                ORDER BY email
                LIMIT $3 OFFSET $4
                """,
                tenant_id,
                include_inactive,
                limit,
                offset,
            )
        return to_models(User, rows)

    async def update(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        role: str = UNSET,
        is_active: bool = UNSET,
        password_hash: Optional[str] = UNSET,
        is_platform_admin: bool = UNSET,
        oidc_subject: Optional[str] = UNSET,
        conn: Optional[Connection] = None,
    ) -> User:
        if role is not UNSET:
            check_choice(role, ROLES, "role")
        params = Params(tenant_id, user_id)
        sets = set_clauses(
            {
                "role": role,
                "is_active": is_active,
                "password_hash": password_hash,
                "is_platform_admin": is_platform_admin,
                "oidc_subject": oidc_subject,
            },
            params,
        )
        if password_hash is not UNSET:
            sets += ["failed_logins = 0", "locked_until = NULL"]
        if not sets:
            return await self.get(tenant_id, user_id, conn=conn)
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                f"UPDATE users SET {', '.join(sets)} WHERE tenant_id = $1 AND id = $2 RETURNING *",  # noqa: S608
                *params.values,
            )
        user = to_model(User, row)
        if user is None:
            raise NotFound("user", user_id)
        return user

    async def delete(self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None) -> bool:
        async with self._tenant(tenant_id, conn) as c:
            status = await c.execute("DELETE FROM users WHERE tenant_id = $1 AND id = $2", tenant_id, user_id)
        return status.endswith(" 1")

    async def count_active_admins(self, tenant_id: str, *, conn: Optional[Connection] = None) -> int:
        async with self._tenant(tenant_id, conn) as c:
            return await c.fetchval(
                "SELECT count(*) FROM users WHERE tenant_id = $1 AND role = 'admin' AND is_active",
                tenant_id,
            )

    async def reserve_login_attempt(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        max_attempts: Optional[int] = None,
        lockout_minutes: Optional[int] = None,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[User]:
        """Count a login attempt *before* the password is checked.

        Returns the updated user, or ``None`` when the account is locked or
        already has ``max_attempts`` attempts counted (failed or still in
        flight): the caller must then refuse without checking the password.
        Counting first makes the lockout hold under concurrent requests: at
        most ``max_attempts`` password checks run per lockout window,
        however many requests arrive at once. An expired lock restarts the
        count. A successful check clears the count
        (:meth:`record_login_success`); a failed one may lock the account
        (:meth:`record_login_failure`).

        A refused attempt on an account whose count is spent but that is not
        locked (a burst still in flight, or reservations a crashed request
        never settled) locks it for ``lockout_minutes``, so the refusal
        always ends when that lock expires.
        """
        require_aware(now, "now")
        auth = get_settings().auth
        max_attempts = auth.max_login_attempts if max_attempts is None else max_attempts
        lockout_minutes = auth.lockout_minutes if lockout_minutes is None else lockout_minutes
        if max_attempts < 1 or lockout_minutes < 1:
            raise ValueError("max_attempts and lockout_minutes must be >= 1")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                WITH cur AS (
                    SELECT id, at,
                           (locked_until IS NOT NULL AND locked_until <= at) AS expired,
                           (locked_until IS NOT NULL AND locked_until <= at)
                               OR (locked_until IS NULL AND failed_logins < $4) AS reserved
                    FROM users, (SELECT COALESCE($3::timestamptz, now()) AS at) p
                    WHERE tenant_id = $1 AND id = $2
                    FOR UPDATE OF users
                )
                UPDATE users u
                SET failed_logins = CASE WHEN cur.expired THEN 1
                                         WHEN cur.reserved THEN u.failed_logins + 1
                                         ELSE u.failed_logins END,
                    locked_until = CASE WHEN cur.expired THEN NULL
                                        WHEN NOT cur.reserved AND u.locked_until IS NULL
                                        THEN cur.at + make_interval(mins => $5)
                                        ELSE u.locked_until END
                FROM cur
                WHERE u.tenant_id = $1 AND u.id = cur.id
                RETURNING u.*, cur.reserved AS lgsotf_reserved
                """,
                tenant_id,
                user_id,
                now,
                max_attempts,
                lockout_minutes,
            )
        if row is None:
            return None
        values = dict(row)
        if not values.pop("lgsotf_reserved"):
            return None
        return User.model_validate(values)

    async def release_login_attempt(
        self, tenant_id: str, user_id: UUID, *, conn: Optional[Connection] = None
    ) -> None:
        """Give back an attempt reserved by a request whose password verified but that
        did not sign in (e.g. an ambiguous tenant-less login). Never touches a lock."""
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                """
                UPDATE users SET failed_logins = GREATEST(failed_logins - 1, 0)
                WHERE tenant_id = $1 AND id = $2 AND (locked_until IS NULL OR locked_until <= now())
                """,
                tenant_id,
                user_id,
            )

    async def record_sign_in(
        self, tenant_id: str, user_id: UUID, *, now: Optional[datetime] = None, conn: Optional[Connection] = None
    ) -> None:
        """Set ``last_login_at`` for a sign-in that is not a password check (an accepted OIDC token)."""
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            await c.execute(
                "UPDATE users SET last_login_at = COALESCE($3::timestamptz, now()) WHERE tenant_id = $1 AND id = $2",
                tenant_id,
                user_id,
                now,
            )

    async def record_login_success(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        now: Optional[datetime] = None,
        conn: Optional[Connection] = None,
    ) -> Optional[User]:
        """Clear the attempt count after a verified password.

        Only an account that is not locked is updated: a lock set by
        concurrent failures while this password was being checked is kept,
        and ``None`` is returned (the caller refuses the login).
        """
        require_aware(now, "now")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                UPDATE users
                SET failed_logins = 0, locked_until = NULL, last_login_at = COALESCE($3::timestamptz, now())
                WHERE tenant_id = $1 AND id = $2
                  AND (locked_until IS NULL OR locked_until <= COALESCE($3::timestamptz, now()))
                RETURNING *
                """,
                tenant_id,
                user_id,
                now,
            )
        return to_model(User, row)

    async def record_login_failure(
        self,
        tenant_id: str,
        user_id: UUID,
        *,
        max_attempts: Optional[int] = None,
        lockout_minutes: Optional[int] = None,
        now: Optional[datetime] = None,
        counted: bool = False,
        conn: Optional[Connection] = None,
    ) -> User:
        """Count a failed login; lock the account once ``max_attempts`` is reached.

        An expired lock resets the counter. Locking resets the counter so the
        user gets a full set of attempts after the lock expires. With
        ``counted=True`` the attempt was already counted by
        :meth:`reserve_login_attempt` and only the lock decision is made.
        """
        require_aware(now, "now")
        auth = get_settings().auth
        max_attempts = auth.max_login_attempts if max_attempts is None else max_attempts
        lockout_minutes = auth.lockout_minutes if lockout_minutes is None else lockout_minutes
        if max_attempts < 1 or lockout_minutes < 1:
            raise ValueError("max_attempts and lockout_minutes must be >= 1")
        async with self._tenant(tenant_id, conn) as c:
            row = await c.fetchrow(
                """
                WITH cur AS (
                    SELECT id,
                           COALESCE($3::timestamptz, now()) AS at,
                           CASE WHEN locked_until IS NOT NULL AND locked_until <= COALESCE($3::timestamptz, now())
                                THEN 1 ELSE failed_logins + $6::int END AS attempts,
                           CASE WHEN locked_until IS NOT NULL AND locked_until <= COALESCE($3::timestamptz, now())
                                THEN NULL ELSE locked_until END AS lock
                    FROM users
                    WHERE tenant_id = $1 AND id = $2
                    FOR UPDATE
                )
                UPDATE users u
                SET failed_logins = CASE WHEN cur.attempts >= $4 THEN 0 ELSE cur.attempts END,
                    locked_until = CASE WHEN cur.attempts >= $4
                                        THEN cur.at + make_interval(mins => $5)
                                        ELSE cur.lock END
                FROM cur
                WHERE u.tenant_id = $1 AND u.id = cur.id
                RETURNING u.*
                """,
                tenant_id,
                user_id,
                now,
                max_attempts,
                lockout_minutes,
                0 if counted else 1,
            )
        user = to_model(User, row)
        if user is None:
            raise NotFound("user", user_id)
        return user
