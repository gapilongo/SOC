# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/auth/mfa``: TOTP enrollment, the second sign-in step and self-service management.

* ``POST /auth/mfa/verify`` finishes a password login that answered
  ``mfa_required: true``: the challenge token plus a TOTP or recovery code
  yields the normal session (access token and refresh cookie).
* ``POST /auth/mfa/enroll`` and ``/confirm`` work with a session *or*, for
  forced enrollment, with the ``mfa_token`` from login (``enrollment_required:
  true``); confirming then also signs the user in. A challenge token permits
  nothing else.
* ``/disable`` needs the password and a current code; ``/recovery-codes``
  needs a current TOTP code. Failed checks count toward the account lockout.
* Limited per client address and challenge (or user) at the login rate;
  failures also count toward the per-address cap on failed logins.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response

from lg_sotf.api.auth.authenticate import authenticate, client_ip, credential_fingerprint
from lg_sotf.api.auth.deps import Access, require
from lg_sotf.api.auth.mfa import PENDING_TTL_S, MfaService, invalid_code
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.auth.service import AuthService, Session
from lg_sotf.api.common import LOGIN_IP_BUCKET, count_failed_login, login_ip_limit, set_refresh_cookie
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.ratelimit import rate_limited
from lg_sotf.api.schemas import (
    MfaCodeIn,
    MfaConfirmIn,
    MfaConfirmOut,
    MfaDisableIn,
    MfaEnrollIn,
    MfaEnrollOut,
    MfaStatusOut,
    MfaVerifyIn,
    RecoveryCodesOut,
    TokenOut,
    UserOut,
)
from lg_sotf.db.repos import User
from lg_sotf.security.hashing import averify_password

MFA_BUCKET = "mfa"

#: A signed-in person acting on their own account (no API keys, no X-Tenant-ID override).
SELF = Access(role="viewer", user_account=True, home_tenant_only=True)

router = APIRouter(prefix="/auth/mfa", tags=["auth"])


async def _limit(ctx: ApiContext, request: Request, identity: str) -> None:
    ip = client_ip(request)
    await ctx.limiter.enforce(MFA_BUCKET, f"{ip}:{identity}", ctx.settings.api.login_rate_limit_per_minute)
    blocked = await ctx.limiter.blocked(LOGIN_IP_BUCKET, ip, login_ip_limit(ctx))
    if blocked is not None:
        raise rate_limited(blocked)


async def _counting_failures(ctx: ApiContext, request: Request, exc: ApiError) -> None:
    if exc.status_code in (400, 401):
        await count_failed_login(ctx, request)


def _session_out(ctx: ApiContext, response: Response, session: Session, **extra: object) -> TokenOut:
    set_refresh_cookie(ctx, response, session.refresh.token)
    user = UserOut.model_validate(session.user).model_copy(update={"mfa_enabled": True})
    return TokenOut(access_token=session.access.token, expires_in=session.access.expires_in, user=user, **extra)


async def _local_user(ctx: ApiContext, principal: Principal) -> User:
    """The caller's own local account; MFA does not apply to SSO sign-ins."""
    if principal.auth_method != "password" or principal.user_id is None:
        raise ApiError(403, "forbidden", "MFA applies to local accounts; SSO sign-in uses your identity provider's MFA")
    user = await ctx.repos.users.get(principal.tenant_id, principal.user_id)
    if user.password_hash is None:
        raise ApiError(403, "forbidden", "this account signs in through SSO and has no local password")
    return user


async def _self(request: Request) -> Principal:
    """``require(SELF)`` for endpoints that alternatively accept a challenge token in the body."""
    principal = await authenticate(get_ctx(request), request)
    SELF.check(principal)
    return principal


@router.get("", response_model=MfaStatusOut, summary="MFA status of the signed-in account")
async def status(request: Request, principal: Principal = Depends(require(SELF))) -> MfaStatusOut:
    ctx = get_ctx(request)
    if principal.auth_method != "password" or principal.user_id is None:
        return MfaStatusOut(available=False, enabled=False, required=False)
    user = await ctx.repos.users.get(principal.tenant_id, principal.user_id)
    mfa = MfaService(ctx)
    state = await mfa.state(user)
    return MfaStatusOut(
        available=user.password_hash is not None,
        enabled=state is not None and state.enabled,
        enabled_at=state.enabled_at if state is not None else None,
        pending=state is not None and state.pending_secret_ciphertext is not None,
        recovery_codes_remaining=state.recovery_codes_remaining if state is not None and state.enabled else 0,
        required=await mfa.required_for(user),
    )


@router.post("/verify", response_model=TokenOut, summary="Finish signing in with a TOTP or recovery code")
async def verify(body: MfaVerifyIn, request: Request, response: Response) -> TokenOut:
    ctx = get_ctx(request)
    await _limit(ctx, request, credential_fingerprint(body.mfa_token))
    try:
        session, check = await AuthService(ctx).complete_mfa(body.mfa_token, body.code, client_ip=client_ip(request))
    except ApiError as exc:
        await _counting_failures(ctx, request, exc)
        raise
    return _session_out(ctx, response, session, recovery_codes_remaining=check.recovery_codes_remaining)


@router.post("/enroll", response_model=MfaEnrollOut, summary="Start TOTP enrollment (secret shown once)")
async def enroll(body: MfaEnrollIn, request: Request) -> MfaEnrollOut:
    ctx = get_ctx(request)
    if body.mfa_token is not None:
        await _limit(ctx, request, credential_fingerprint(body.mfa_token))
        try:
            user = await AuthService(ctx).begin_forced_enrollment(body.mfa_token)
        except ApiError as exc:
            await _counting_failures(ctx, request, exc)
            raise
    else:
        principal = await _self(request)
        await _limit(ctx, request, principal.id)
        user = await _local_user(ctx, principal)
    enrollment = await MfaService(ctx).begin_enrollment(user)
    return MfaEnrollOut(
        secret=enrollment.secret, otpauth_uri=enrollment.otpauth_uri, qr=enrollment.qr, expires_in=PENDING_TTL_S
    )


@router.post("/confirm", response_model=MfaConfirmOut, summary="Activate MFA with a code; returns recovery codes once")
async def confirm(body: MfaConfirmIn, request: Request, response: Response) -> MfaConfirmOut:
    ctx = get_ctx(request)
    if body.mfa_token is not None:
        await _limit(ctx, request, credential_fingerprint(body.mfa_token))
        try:
            session, codes = await AuthService(ctx).complete_forced_enrollment(
                body.mfa_token, body.code, client_ip=client_ip(request)
            )
        except ApiError as exc:
            await _counting_failures(ctx, request, exc)
            raise
        return MfaConfirmOut(recovery_codes=codes, session=_session_out(ctx, response, session))
    principal = await _self(request)
    await _limit(ctx, request, principal.id)
    user = await _local_user(ctx, principal)
    codes = await MfaService(ctx).confirm_enrollment(user, body.code, actor_type="user", actor_id=str(user.id))
    return MfaConfirmOut(recovery_codes=codes)


@router.post("/disable", status_code=204, summary="Turn MFA off (password and a current code)")
async def disable(body: MfaDisableIn, request: Request, principal: Principal = Depends(require(SELF))) -> Response:
    ctx = get_ctx(request)
    await _limit(ctx, request, principal.id)
    user = await _local_user(ctx, principal)
    await _check_factors(ctx, request, user, code=body.code, password=body.password)
    await MfaService(ctx).disable(user)
    return Response(status_code=204)


@router.post(
    "/recovery-codes", response_model=RecoveryCodesOut, summary="Replace the recovery codes (needs a TOTP code)"
)
async def regenerate(
    body: MfaCodeIn, request: Request, principal: Principal = Depends(require(SELF))
) -> RecoveryCodesOut:
    ctx = get_ctx(request)
    await _limit(ctx, request, principal.id)
    user = await _local_user(ctx, principal)
    await _check_factors(ctx, request, user, code=body.code, allow_recovery=False)
    return RecoveryCodesOut(recovery_codes=await MfaService(ctx).regenerate_recovery_codes(user))


async def _check_factors(
    ctx: ApiContext,
    request: Request,
    user: User,
    *,
    code: str,
    password: Optional[str] = None,
    allow_recovery: bool = True,
) -> None:
    """Verify the password (optional) and a code under the account lockout; 400 on failure."""
    state = await MfaService(ctx).state(user)
    if state is None or not state.enabled:
        raise ApiError(409, "mfa_not_enabled", "MFA is not enabled")
    service = AuthService(ctx)
    ip = client_ip(request)
    reserved = await service.reserve_attempt(user, ip, status=400)
    try:
        if password is not None and not (
            reserved.password_hash is not None and await averify_password(reserved.password_hash, password)
        ):
            await service.record_factor_failure(user, "bad_password", ip)
            raise ApiError(400, "invalid_credentials", "the password is not correct")
        if await MfaService(ctx).check_code(user, code, allow_recovery=allow_recovery) is None:
            await service.record_factor_failure(user, "bad_code", ip)
            raise invalid_code(400)
    except ApiError as exc:
        await _counting_failures(ctx, request, exc)
        raise
    await ctx.repos.users.release_login_attempt(user.tenant_id, user.id)
