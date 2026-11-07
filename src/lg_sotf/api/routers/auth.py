# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/auth``: login, refresh-token rotation, logout and the current principal.

For an account with MFA (or one that policy requires to enroll) a correct
password answers ``mfa_required: true`` with a short-lived challenge token
instead of a session; ``/auth/mfa`` (:mod:`lg_sotf.api.routers.mfa`) finishes it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Optional, Union
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request, Response
from redis.exceptions import RedisError

from lg_sotf.api.auth.authenticate import (
    authenticate,
    bearer_principal,
    client_ip,
    credential_fingerprint,
    failure_blocked,
    record_failure,
    revoked_key,
)
from lg_sotf.api.auth.deps import ANY, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.auth.service import AuthService, MfaChallenge, invalid_session
from lg_sotf.api.common import (
    LOGIN_IP_BUCKET,
    REFRESH_COOKIE,
    REFRESH_COOKIE_PATH,
    count_failed_login,
    login_ip_limit,
    set_refresh_cookie,
)
from lg_sotf.api.context import ApiContext, allowed_origins, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.ratelimit import rate_limited
from lg_sotf.api.schemas import LoginIn, MeOut, MfaChallengeOut, TokenOut, UserOut
from lg_sotf.observability.logging import get_logger, log_failure

log = get_logger(__name__)

LOGIN_BUCKET = "login"
REFRESH_BUCKET = "refresh"

router = APIRouter(prefix="/auth", tags=["auth"])


def _clear_refresh_cookie(ctx: ApiContext, response: Response) -> None:
    auth = ctx.settings.auth
    response.delete_cookie(
        REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        domain=auth.cookie_domain,
        secure=auth.cookie_secure,
        httponly=True,
        samesite="strict",
    )


async def _limit_login(ctx: ApiContext, request: Request, email: str) -> None:
    """Per (address, account) limit plus a looser per-address cap on *failed* logins.

    Keying by account keeps one client's failed attempts from locking out
    everyone else behind the same proxy address. The address cap counts only
    failures (see :func:`count_failed_login`), so many people signing in
    correctly through one address are never refused by it, while password
    hashing work from a single failing source stays bounded. Per-account brute
    force is bounded by lockout as well.
    """
    ip = client_ip(request)
    limit = ctx.settings.api.login_rate_limit_per_minute
    account = credential_fingerprint(email.strip().lower())
    await ctx.limiter.enforce(LOGIN_BUCKET, f"{ip}:{account}", limit)
    blocked = await ctx.limiter.blocked(LOGIN_IP_BUCKET, ip, login_ip_limit(ctx))
    if blocked is not None:
        raise rate_limited(blocked)


def _origin_host(value: str) -> str:
    try:
        return (urlsplit(value.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _check_cookie_origin(ctx: ApiContext, request: Request) -> None:
    """CSRF guard for the cookie-authenticated endpoints (refresh, logout).

    SameSite=Strict stops other *sites*, not other origins of the same site
    (a sibling subdomain). Browsers send ``Origin`` on every POST, so a
    browser request is accepted only from this API's own host, ``api.public_url``
    or an ``api.cors_origins`` entry; ``Sec-Fetch-Site: cross-site`` is always
    refused. Non-browser clients send neither header and are unaffected.
    """
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise ApiError(403, "forbidden", "cross-site request refused")
    origin = request.headers.get("origin")
    if origin is None:
        return
    allowed = {o.lower() for o in allowed_origins(ctx.settings)}
    allowed.add(ctx.settings.api.public_url.strip().rstrip("/").lower())
    host = _origin_host(origin)
    # The host the request was sent to (a proxy may drop the port from Host).
    own_host = _origin_host("//" + request.headers.get("host", ""))
    if origin.strip().rstrip("/").lower() in allowed or (host and host == own_host):
        return
    log.warning("auth.cookie_request_bad_origin", path=request.url.path)
    raise ApiError(403, "forbidden", "request origin is not allowed")


async def _limit_session(ctx: ApiContext, request: Request, bucket: str, presented: Optional[str]) -> None:
    """Refresh/logout are limited per refresh token, never per address, so a
    shared ingress address does not cap the whole deployment's sessions."""
    identity = credential_fingerprint(presented) if presented else f"ip:{client_ip(request)}"
    await ctx.limiter.enforce(bucket, identity, ctx.settings.api.login_rate_limit_per_minute)


@router.post(
    "/login",
    response_model=Union[TokenOut, MfaChallengeOut],
    summary="Sign in with email and password (answers mfa_required when a second factor must follow)",
)
async def login(body: LoginIn, request: Request, response: Response) -> Union[TokenOut, MfaChallengeOut]:
    ctx = get_ctx(request)
    await _limit_login(ctx, request, body.email)
    try:
        session = await AuthService(ctx).login(body.email, body.password, body.tenant, client_ip=client_ip(request))
    except ApiError as exc:
        if exc.status_code == 401:
            await count_failed_login(ctx, request)
        raise
    if isinstance(session, MfaChallenge):
        return MfaChallengeOut(
            mfa_token=session.token.token,
            expires_in=session.token.expires_in,
            enrollment_required=session.enrollment_required,
            methods=[] if session.enrollment_required else ["totp", "recovery_code"],
        )
    set_refresh_cookie(ctx, response, session.refresh.token)
    return TokenOut(
        access_token=session.access.token,
        expires_in=session.access.expires_in,
        user=UserOut.model_validate(session.user),
    )


@router.post("/refresh", response_model=TokenOut, summary="Rotate the refresh cookie and get a new access token")
async def refresh(request: Request, response: Response) -> TokenOut:
    ctx = get_ctx(request)
    _check_cookie_origin(ctx, request)
    presented = request.cookies.get(REFRESH_COOKIE)
    await _limit_session(ctx, request, REFRESH_BUCKET, presented)
    if not presented:
        raise invalid_session()
    ip = client_ip(request)
    blocked = await failure_blocked(ctx, ip, presented)
    if blocked is not None:
        raise rate_limited(blocked)
    try:
        session = await AuthService(ctx).refresh(presented, client_ip=ip)
    except ApiError as exc:
        if exc.status_code == 401:
            # Only failing refreshes count against the address: valid sessions are never throttled by it.
            decision = await record_failure(ctx, ip, presented)
            if not decision.allowed:
                exc = rate_limited(decision)
        # The failure response must also clear the cookie, so it cannot be raised as-is.
        failure = Response(status_code=exc.status_code)
        _clear_refresh_cookie(ctx, failure)
        exc.headers = {**(exc.headers or {}), "set-cookie": failure.headers["set-cookie"]}
        raise exc from None
    set_refresh_cookie(ctx, response, session.refresh.token)
    return TokenOut(
        access_token=session.access.token,
        expires_in=session.access.expires_in,
        user=UserOut.model_validate(session.user),
    )


@router.post("/logout", status_code=204, summary="Revoke the refresh cookie (and the presented access token)")
async def logout(request: Request) -> Response:
    ctx = get_ctx(request)
    _check_cookie_origin(ctx, request)
    presented = request.cookies.get(REFRESH_COOKIE)
    await _limit_session(ctx, request, REFRESH_BUCKET, presented)
    await AuthService(ctx).logout(presented)
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        try:
            principal = await bearer_principal(ctx, token.strip())
        except ApiError:
            principal = None
        if principal is not None and principal.token_id and principal.expires_at is not None:
            ttl = int((principal.expires_at - datetime.now(UTC)).total_seconds()) + 60
            try:
                await ctx.redis.set(revoked_key(ctx, principal.token_id), b"1", ex=max(ttl, 1))
            except (RedisError, OSError, TimeoutError) as exc:
                log_failure(log, "auth.revoke_access_failed", exc, level="warning", error_type=type(exc).__name__)
    response = Response(status_code=204)
    _clear_refresh_cookie(ctx, response)
    return response


@router.get("/me", response_model=MeOut, summary="The authenticated principal")
async def me(request: Request, principal: Principal = Depends(require(ANY))) -> MeOut:
    tenant = await get_ctx(request).tenants.get(principal.tenant_id)
    return MeOut(
        kind=principal.kind,
        tenant_id=principal.tenant_id,
        tenant_name=tenant.name if tenant is not None else None,
        home_tenant_id=principal.home_tenant_id,
        auth_method=principal.auth_method,
        role=principal.role,
        scopes=sorted(principal.scopes),
        user_id=principal.user_id,
        api_key_id=principal.api_key_id,
        email=principal.email,
        is_platform_admin=principal.is_platform_admin,
        expires_at=principal.expires_at,
        grant_id=principal.grant_id,
    )


__all__ = ["REFRESH_COOKIE", "REFRESH_COOKIE_PATH", "authenticate", "router"]
