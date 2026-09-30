"""Local login, refresh-token rotation and logout.

* Unknown emails, wrong passwords, disabled, locked and SSO-only accounts all
  get the same answer after the same amount of argon2 work, so responses do
  not reveal which accounts exist.
* ``auth.max_login_attempts`` consecutive failures lock the account for
  ``auth.lockout_minutes``; while locked even the right password fails. The
  attempt is counted *before* the password is checked, so concurrent requests
  cannot run more checks than that per lockout window, and a correct password
  that was in flight while the account locked is refused.
* Without a tenant hint, an email registered in several tenants is resolved by
  the password: the account whose password verifies signs in; when several
  verify, the answer is ``401 tenant_required``.
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
        usable = [u for u in candidates if u.password_hash is not None and u.is_active]
        for other in candidates:
            if other not in usable:
                await self._audit_failure(other, "disabled" if not other.is_active else "no_password", client_ip)
        if not usable:
            await aburn_password_check(password)
            if not candidates:
                log.info("auth.login_failed", reason="unknown", client_ip=client_ip)
            raise invalid_credentials()
        # Without a tenant hint the same email may exist in several tenants (an admin of
        # another tenant can register any address). The password decides which account is
        # meant; each check is counted against that account's own lockout.
        matched: List[User] = []
        for candidate in usable:
            if await self._check_password(candidate, password, client_ip):
                matched.append(candidate)
        if not matched:
            raise invalid_credentials()
        if len(matched) > 1:
            for candidate in matched:
                await self._ctx.repos.users.release_login_attempt(candidate.tenant_id, candidate.id)
            log.info("auth.login_failed", reason="ambiguous_tenant", client_ip=client_ip)
            raise ApiError(401, "tenant_required", "this account exists in several tenants; enter the tenant")
        user = matched[0]
        tenant = await self._ctx.tenants.get(user.tenant_id)
        if tenant is None or tenant.status != "active":
            await self._ctx.repos.users.release_login_attempt(user.tenant_id, user.id)
            await self._audit_failure(user, "tenant_suspended", client_ip)
            raise ApiError(403, "tenant_suspended", "tenant is suspended")
        succeeded = await self._ctx.repos.users.record_login_success(user.tenant_id, user.id)
        if succeeded is None:
            # Concurrent failures locked the account while this password was being checked.
            await self._audit_failure(user, "locked", client_ip)
            raise invalid_credentials()
        user = succeeded
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

    async def _check_password(self, user: User, password: str, client_ip: str) -> bool:
        """Verify ``password`` for ``user`` under the lockout; the attempt is counted first."""
        auth = self._ctx.settings.auth
        reserved = await self._ctx.repos.users.reserve_login_attempt(
            user.tenant_id, user.id, max_attempts=auth.max_login_attempts, lockout_minutes=auth.lockout_minutes
        )
        if reserved is None or reserved.password_hash is None or not reserved.is_active:
            await aburn_password_check(password)
            await self._audit_failure(user, "locked" if reserved is None else "disabled", client_ip)
            return False
        if await averify_password(reserved.password_hash, password):
            return True
        updated = await self._ctx.repos.users.record_login_failure(
            user.tenant_id,
            user.id,
            max_attempts=auth.max_login_attempts,
            lockout_minutes=auth.lockout_minutes,
            counted=True,
        )
        await self._audit_failure(user, "locked_now" if updated.is_locked() else "bad_password", client_ip)
        return False

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
