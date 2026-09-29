"""Local login, refresh-token rotation and logout.

* Unknown emails, wrong passwords, disabled, locked and SSO-only accounts all
  get the same answer after the same amount of argon2 work, so responses do
  not reveal which accounts exist.
* ``auth.max_login_attempts`` consecutive failures lock the account for
  ``auth.lockout_minutes``; while locked even the right password fails.
* Refresh tokens rotate on every use. Presenting a rotated token again means
  it leaked: every refresh token of that user is revoked (the whole family)
  and the attempt is audited.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from lg_sotf.api.auth.tokens import IssuedToken, RefreshToken
from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import NotFound, RefreshTokenInvalid, RefreshTokenReuse
from lg_sotf.db.repos import User
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.hashing import (
    aburn_password_check,
    ahash_password,
    averify_password,
    password_needs_rehash,
    sha256_hex,
)

log = get_logger(__name__)

MAX_PASSWORD_CHARS = 1_024
INVALID_CREDENTIALS = "invalid email, password or tenant"


def invalid_credentials() -> ApiError:
    return ApiError(401, "invalid_credentials", INVALID_CREDENTIALS)


def invalid_session() -> ApiError:
    return ApiError(401, "invalid_session", "session expired or revoked; sign in again")


@dataclass(frozen=True)
class Session:
    user: User
    access: IssuedToken
    refresh: RefreshToken


class AuthService:
    def __init__(self, ctx: ApiContext) -> None:
        self._ctx = ctx
        self._audit = AuditLogger(ctx.repos)

    async def _candidates(self, email: str, tenant_id: Optional[str]) -> List[User]:
        repos = self._ctx.repos
        try:
            if tenant_id is not None:
                if not is_valid_tenant_id(tenant_id):
                    return []
                user = await repos.users.get_by_email(tenant_id, email)
                return [user] if user is not None else []
            return await repos.users.find_by_email_all_tenants(email)
        except ValueError:
            return []

    async def login(self, email: str, password: str, tenant_id: Optional[str], *, client_ip: str) -> Session:
        if len(password) > MAX_PASSWORD_CHARS:
            raise invalid_credentials()
        candidates = await self._candidates(email, tenant_id)
        # Without a tenant hint an email registered in several tenants is ambiguous: refuse it
        # the same way as an unknown one (the client must name the tenant).
        user = candidates[0] if len(candidates) == 1 else None
        if user is None or user.password_hash is None or not user.is_active or user.is_locked():
            await aburn_password_check(password)
            if user is not None:
                reason = "locked" if user.is_locked() else "disabled" if not user.is_active else "no_password"
                await self._audit_failure(user, reason, client_ip)
            else:
                log.info("auth.login_failed", reason="unknown_or_ambiguous", client_ip=client_ip)
            raise invalid_credentials()
        if not await averify_password(user.password_hash, password):
            auth = self._ctx.settings.auth
            updated = await self._ctx.repos.users.record_login_failure(
                user.tenant_id, user.id, max_attempts=auth.max_login_attempts, lockout_minutes=auth.lockout_minutes
            )
            await self._audit_failure(user, "locked_now" if updated.is_locked() else "bad_password", client_ip)
            raise invalid_credentials()
        tenant = await self._ctx.tenants.get(user.tenant_id)
        if tenant is None or tenant.status != "active":
            await self._audit_failure(user, "tenant_suspended", client_ip)
            raise ApiError(403, "forbidden", "tenant is suspended")
        user = await self._ctx.repos.users.record_login_success(user.tenant_id, user.id)
        if password_needs_rehash(user.password_hash or ""):
            user = await self._ctx.repos.users.update(
                user.tenant_id, user.id, password_hash=await ahash_password(password)
            )
        session = await self._new_session(user)
        await self._audit.record(
            user.tenant_id,
            "auth.login",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"client_ip": client_ip, "method": "password"},
        )
        return session

    async def _audit_failure(self, user: User, reason: str, client_ip: str) -> None:
        await self._audit.record(
            user.tenant_id,
            "auth.login_failed",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"reason": reason, "client_ip": client_ip},
        )

    async def _new_session(self, user: User) -> Session:
        refresh = self._ctx.tokens.new_refresh()
        await self._ctx.repos.refresh_tokens.create(user.tenant_id, user.id, refresh.token_hash, refresh.expires_at)
        return Session(user=user, access=self._ctx.tokens.issue_access(user), refresh=refresh)

    async def refresh(self, presented: str, *, client_ip: str) -> Session:
        token_hash = sha256_hex(presented)
        record = await self._ctx.repos.refresh_tokens.get_by_hash_all_tenants(token_hash)
        if record is None:
            raise invalid_session()
        new = self._ctx.tokens.new_refresh()
        try:
            rotated = await self._ctx.repos.refresh_tokens.rotate(
                record.tenant_id, token_hash, new.token_hash, new.expires_at
            )
        except RefreshTokenReuse as exc:
            await self._audit.record(
                record.tenant_id,
                "auth.refresh_reuse_detected",
                "user",
                str(record.user_id),
                actor_type="user",
                actor_id=str(record.user_id),
                details={"revoked_tokens": exc.revoked, "client_ip": client_ip},
            )
            log.warning("auth.refresh_reuse_detected", tenant_id=record.tenant_id, revoked=exc.revoked)
            raise invalid_session() from exc
        except RefreshTokenInvalid as exc:
            raise invalid_session() from exc
        try:
            user = await self._ctx.repos.users.get(rotated.tenant_id, rotated.user_id)
        except NotFound as exc:
            raise invalid_session() from exc
        tenant = await self._ctx.tenants.get(user.tenant_id)
        if not user.is_active or tenant is None or tenant.status != "active":
            await self._ctx.repos.refresh_tokens.revoke(user.tenant_id, new.token_hash)
            raise invalid_session()
        return Session(user=user, access=self._ctx.tokens.issue_access(user), refresh=new)

    async def logout(self, presented: Optional[str]) -> Optional[User]:
        """Revoke the refresh token (if any); returns its user when it was known."""
        if not presented:
            return None
        token_hash = sha256_hex(presented)
        record = await self._ctx.repos.refresh_tokens.get_by_hash_all_tenants(token_hash)
        if record is None:
            return None
        await self._ctx.repos.refresh_tokens.revoke(record.tenant_id, token_hash)
        await self._audit.record(
            record.tenant_id,
            "auth.logout",
            "user",
            str(record.user_id),
            actor_type="user",
            actor_id=str(record.user_id),
        )
        try:
            return await self._ctx.repos.users.get(record.tenant_id, record.user_id)
        except NotFound:
            return None
