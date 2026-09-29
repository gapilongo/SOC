# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/auth``: login, refresh-token rotation, logout and the current principal."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Optional

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
from lg_sotf.api.auth.service import AuthService, invalid_session
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.ratelimit import rate_limited
from lg_sotf.api.schemas import LoginIn, MeOut, TokenOut, UserOut
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

REFRESH_COOKIE = "lgsotf_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"
LOGIN_BUCKET = "login"
LOGIN_IP_BUCKET = "login-ip"
LOGIN_IP_MULTIPLIER = 10
REFRESH_BUCKET = "refresh"

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh_cookie(ctx: ApiContext, response: Response, token: str) -> None:
    auth = ctx.settings.auth
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=int(auth.refresh_token_ttl_s),
        path=REFRESH_COOKIE_PATH,
        domain=auth.cookie_domain,
        secure=auth.cookie_secure,
        httponly=True,
        samesite="strict",
    )


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


def _login_ip_limit(ctx: ApiContext) -> int:
    return ctx.settings.api.login_rate_limit_per_minute * LOGIN_IP_MULTIPLIER


async def _limit_login(ctx: ApiContext, request: Request, email: str) -> None:
    """Per (address, account) limit plus a looser per-address cap.

    Keying by account keeps one client's failed attempts from locking out
    everyone else behind the same proxy address; the address cap still bounds
    password hashing work from a single source. Per-account brute force is
    bounded by lockout as well.
    """
    ip = client_ip(request)
    limit = ctx.settings.api.login_rate_limit_per_minute
    account = credential_fingerprint(email.strip().lower())
    await ctx.limiter.enforce(LOGIN_BUCKET, f"{ip}:{account}", limit)
    await ctx.limiter.enforce(LOGIN_IP_BUCKET, ip, _login_ip_limit(ctx))


async def _limit_session(ctx: ApiContext, request: Request, bucket: str, presented: Optional[str]) -> None:
    """Refresh/logout are limited per refresh token, never per address, so a
    shared ingress address does not cap the whole deployment's sessions."""
    identity = credential_fingerprint(presented) if presented else f"ip:{client_ip(request)}"
    await ctx.limiter.enforce(bucket, identity, ctx.settings.api.login_rate_limit_per_minute)


@router.post("/login", response_model=TokenOut, summary="Sign in with email and password")
async def login(body: LoginIn, request: Request, response: Response) -> TokenOut:
    ctx = get_ctx(request)
    await _limit_login(ctx, request, body.email)
    session = await AuthService(ctx).login(body.email, body.password, body.tenant, client_ip=client_ip(request))
    _set_refresh_cookie(ctx, response, session.refresh.token)
    return TokenOut(
        access_token=session.access.token,
        expires_in=session.access.expires_in,
        user=UserOut.model_validate(session.user),
    )


@router.post("/refresh", response_model=TokenOut, summary="Rotate the refresh cookie and get a new access token")
async def refresh(request: Request, response: Response) -> TokenOut:
    ctx = get_ctx(request)
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
    _set_refresh_cookie(ctx, response, session.refresh.token)
    return TokenOut(
        access_token=session.access.token,
        expires_in=session.access.expires_in,
        user=UserOut.model_validate(session.user),
    )


@router.post("/logout", status_code=204, summary="Revoke the refresh cookie (and the presented access token)")
async def logout(request: Request) -> Response:
    ctx = get_ctx(request)
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
                log.warning("auth.revoke_access_failed", error_type=type(exc).__name__)
    response = Response(status_code=204)
    _clear_refresh_cookie(ctx, response)
    return response


@router.get("/me", response_model=MeOut, summary="The authenticated principal")
async def me(principal: Principal = Depends(require(ANY))) -> MeOut:
    return MeOut(
        kind=principal.kind,
        tenant_id=principal.tenant_id,
        home_tenant_id=principal.home_tenant_id,
        auth_method=principal.auth_method,
        role=principal.role,
        scopes=sorted(principal.scopes),
        user_id=principal.user_id,
        api_key_id=principal.api_key_id,
        email=principal.email,
        is_platform_admin=principal.is_platform_admin,
        expires_at=principal.expires_at,
    )


__all__ = ["REFRESH_COOKIE", "REFRESH_COOKIE_PATH", "authenticate", "router"]
