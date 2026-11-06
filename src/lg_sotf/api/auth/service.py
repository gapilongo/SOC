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
* With MFA enabled (or required by policy) the right password yields only an
  MFA challenge token (see :mod:`lg_sotf.api.auth.mfa`). The password step
  gives its reserved attempt back *without* clearing earlier failures, and
  every code check reserves an attempt of its own, so wrong codes count
  toward the same lockout and re-entering the password never resets it.
  A refresh is refused for an account that policy now requires to use MFA
  but that has not enrolled, so the user signs in again and enrolls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID

from redis.exceptions import RedisError

from lg_sotf.api.auth.mfa import CodeCheck, MfaService, invalid_code
from lg_sotf.api.auth.tokens import (
    MFA_ENROLL_TOKEN_TYPE,
    MFA_TOKEN_TYPE,
    InvalidToken,
    IssuedToken,
    RefreshToken,
    password_fingerprint,
)
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


def invalid_challenge() -> ApiError:
    return ApiError(401, "invalid_mfa_token", "the sign-in step expired or is not valid; sign in again")


def used_challenge_key(ctx: ApiContext, jti: str) -> str:
    return f"{ctx.prefix}:auth:mfa-used:{jti}"


@dataclass(frozen=True)
class Session:
    user: User
    access: IssuedToken
    refresh: RefreshToken


@dataclass(frozen=True)
class MfaChallenge:
    """The password was right; a second factor (or enrollment, when ``enrollment_required``) must follow."""

    user: User
    token: IssuedToken
    enrollment_required: bool


LoginResult = Union[Session, MfaChallenge]


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

    async def login(self, email: str, password: str, tenant_id: Optional[str], *, client_ip: str) -> LoginResult:
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
        mfa = MfaService(self._ctx)
        state = await mfa.state(user)
        enrolled = state is not None and state.enabled
        if enrolled or await mfa.required_for(user):
            return await self._challenge(user, password, enrolled=enrolled, client_ip=client_ip)
        succeeded = await self._ctx.repos.users.record_login_success(user.tenant_id, user.id)
        if succeeded is None:
            # Concurrent failures locked the account while this password was being checked.
            await self._audit_failure(user, "locked", client_ip)
            raise invalid_credentials()
        user = await self._rehash_if_needed(succeeded, password)
        session = await self._new_session(user)
        await self._audit_login(user, "password", client_ip)
        return session

    async def _rehash_if_needed(self, user: User, password: str) -> User:
        if password_needs_rehash(user.password_hash or ""):
            return await self._ctx.repos.users.update(
                user.tenant_id, user.id, password_hash=await ahash_password(password)
            )
        return user

    async def _audit_login(self, user: User, method: str, client_ip: str) -> None:
        await self._audit.record_event(
            user.tenant_id,
            "auth.login",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"client_ip": client_ip, "method": method},
        )

    async def _challenge(self, user: User, password: str, *, enrolled: bool, client_ip: str) -> MfaChallenge:
        """Password verified for an MFA account: hand out a challenge token, not a session.

        The attempt reserved for the password check is given back without
        clearing earlier failures; only a verified second factor does that.
        """
        users = self._ctx.repos.users
        await users.release_login_attempt(user.tenant_id, user.id)
        current = await users.get(user.tenant_id, user.id)
        if current.is_locked():
            await self._audit_failure(user, "locked", client_ip)
            raise invalid_credentials()
        current = await self._rehash_if_needed(current, password)
        purpose = MFA_TOKEN_TYPE if enrolled else MFA_ENROLL_TOKEN_TYPE
        issued = self._ctx.tokens.issue_mfa_challenge(current, purpose)
        log.info("auth.mfa_challenge", tenant_id=current.tenant_id, purpose=purpose, client_ip=client_ip)
        return MfaChallenge(user=current, token=issued, enrollment_required=not enrolled)

    # ------------------------------------------------------------------ MFA

    async def challenge_user(self, token: str, purpose: str) -> Tuple[User, Dict[str, Any]]:
        """The user a valid, unused challenge token of ``purpose`` was issued to."""
        try:
            claims = self._ctx.tokens.verify_mfa_challenge(token)
        except InvalidToken as exc:
            raise invalid_challenge() from exc
        if claims["typ"] != purpose:
            raise invalid_challenge()
        tenant_id = claims["tenant"]
        if not is_valid_tenant_id(tenant_id):
            raise invalid_challenge()
        try:
            used = await self._ctx.redis.exists(used_challenge_key(self._ctx, claims["jti"]))
        except (RedisError, OSError, TimeoutError) as exc:
            # Codes stay single-use in the database; the token itself expires within minutes.
            log.warning("auth.mfa_challenge_check_unavailable", error_type=type(exc).__name__)
            used = 0
        if used:
            raise invalid_challenge()
        try:
            user = await self._ctx.repos.users.get(tenant_id, UUID(claims["sub"]))
        except (NotFound, ValueError) as exc:
            raise invalid_challenge() from exc
        if (
            not user.is_active
            or user.password_hash is None
            or password_fingerprint(user.password_hash) != claims["pwf"]
        ):
            raise invalid_challenge()
        tenant = await self._ctx.tenants.get(tenant_id)
        if tenant is None or tenant.status != "active":
            raise ApiError(403, "forbidden", "tenant is suspended")
        return user, claims

    async def _spend_challenge(self, claims: Dict[str, Any]) -> None:
        """Mark the challenge used; a second use (a concurrent request) is refused."""
        ttl = max(int(claims["exp"]) - int(claims["iat"]), 1) + 60
        try:
            first = await self._ctx.redis.set(used_challenge_key(self._ctx, claims["jti"]), b"1", ex=ttl, nx=True)
        except (RedisError, OSError, TimeoutError) as exc:
            log.warning("auth.mfa_challenge_spend_unavailable", error_type=type(exc).__name__)
            return
        if not first:
            raise invalid_challenge()

    async def reserve_attempt(self, user: User, client_ip: str, *, status: int = 401) -> User:
        """Count a second-factor attempt against the lockout before checking it."""
        auth = self._ctx.settings.auth
        reserved = await self._ctx.repos.users.reserve_login_attempt(
            user.tenant_id, user.id, max_attempts=auth.max_login_attempts, lockout_minutes=auth.lockout_minutes
        )
        if reserved is None or not reserved.is_active:
            reason = "locked" if reserved is None else "disabled"
            await MfaService(self._ctx).audit_failure(user, reason, client_ip=client_ip)
            raise invalid_code(status)
        return reserved

    async def record_factor_failure(self, user: User, reason: str, client_ip: str) -> None:
        """A reserved attempt failed: it stays counted and may lock the account."""
        auth = self._ctx.settings.auth
        updated = await self._ctx.repos.users.record_login_failure(
            user.tenant_id,
            user.id,
            max_attempts=auth.max_login_attempts,
            lockout_minutes=auth.lockout_minutes,
            counted=True,
        )
        await MfaService(self._ctx).audit_failure(
            user, "locked_now" if updated.is_locked() else reason, client_ip=client_ip
        )

    async def complete_mfa(self, token: str, code: str, *, client_ip: str) -> Tuple[Session, CodeCheck]:
        """Second step of a password login: a TOTP or recovery code turns the challenge into a session."""
        user, claims = await self.challenge_user(token, MFA_TOKEN_TYPE)
        await self.reserve_attempt(user, client_ip)
        check = await MfaService(self._ctx).check_code(user, code)
        if check is None:
            await self.record_factor_failure(user, "bad_code", client_ip)
            raise invalid_code()
        await self._spend_challenge(claims)
        session = await self._finish_login(user, f"password+{check.method}", client_ip)
        return session, check

    async def begin_forced_enrollment(self, token: str) -> User:
        user, _ = await self.challenge_user(token, MFA_ENROLL_TOKEN_TYPE)
        if user.is_locked():
            raise invalid_challenge()
        return user

    async def complete_forced_enrollment(
        self, token: str, code: str, *, client_ip: str
    ) -> Tuple[Session, List[str]]:
        """Forced enrollment: confirming the new authenticator also completes the sign-in."""
        user, claims = await self.challenge_user(token, MFA_ENROLL_TOKEN_TYPE)
        if user.is_locked():
            raise invalid_challenge()
        codes = await MfaService(self._ctx).confirm_enrollment(
            user, code, actor_type="user", actor_id=str(user.id), failure_status=401
        )
        await self._spend_challenge(claims)
        session = await self._finish_login(user, "password+mfa_enrollment", client_ip)
        return session, codes

    async def _finish_login(self, user: User, method: str, client_ip: str) -> Session:
        succeeded = await self._ctx.repos.users.record_login_success(user.tenant_id, user.id)
        if succeeded is None:
            await self._audit_failure(user, "locked", client_ip)
            raise invalid_credentials()
        session = await self._new_session(succeeded)
        await self._audit_login(succeeded, method, client_ip)
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
        await self._audit.record_event(
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
            await self._audit.record_event(
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
        if not user.is_active or tenant is None or tenant.status != "active" or await self._must_enroll(user):
            await self._ctx.repos.refresh_tokens.revoke(user.tenant_id, new.token_hash)
            raise invalid_session()
        return Session(user=user, access=self._ctx.tokens.issue_access(user), refresh=new)

    async def _must_enroll(self, user: User) -> bool:
        """Policy now requires MFA but the account has none: end the session so sign-in enrolls it."""
        if user.password_hash is None:
            return False
        mfa = MfaService(self._ctx)
        state = await mfa.state(user)
        if state is not None and state.enabled:
            return False
        if await mfa.required_for(user):
            log.info("auth.refresh_refused_mfa_required", tenant_id=user.tenant_id)
            return True
        return False

    async def logout(self, presented: Optional[str]) -> Optional[User]:
        """Revoke the refresh token (if any); returns its user when it was known."""
        if not presented:
            return None
        token_hash = sha256_hex(presented)
        record = await self._ctx.repos.refresh_tokens.get_by_hash_all_tenants(token_hash)
        if record is None:
            return None
        await self._ctx.repos.refresh_tokens.revoke(record.tenant_id, token_hash)
        await self._audit.record_event(
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
