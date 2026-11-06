"""Turning request credentials into a :class:`Principal`.

Accepted credentials, checked in this order:

* ``X-API-Key: lgk_<id>_<secret>`` or ``Authorization: Bearer lgk_...``;
* ``Authorization: Bearer <access JWT>`` issued by ``POST /auth/login``
  (HS256); the user row is re-read on every request, so deactivation and
  role changes apply immediately, and logged-out tokens are refused;
* ``Authorization: Bearer <OIDC JWT>`` from ``auth.oidc_issuer``. The role
  comes from the ``auth.oidc_role_claim`` values through
  ``auth.oidc_role_map`` (highest mapped role wins; ``auth.oidc_default_role``
  when nothing maps; refused when that is unset too). With
  ``auth.oidc_jit_provisioning`` a verified identity without a local account
  gets one (linked by the IdP subject), and a provisioned account's stored
  role follows the IdP on later sign-ins. OIDC never grants platform admin.

Failed authentications are counted per client address and per (address,
credential fingerprint). A credential that verifies is always accepted, so
clients sharing a proxy address cannot lock each other out; a failing request
from an address over its failure budget gets 429 instead of 401, and a
credential that keeps failing is refused before it is checked again.
A platform admin may act on another tenant with ``X-Tenant-ID``; every such
request is written to that tenant's audit log.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from redis.exceptions import RedisError
from starlette.requests import HTTPConnection

from lg_sotf.api.auth.oidc import OIDCError, OIDCIdentity, OIDCUnavailable
from lg_sotf.api.auth.principal import ROLE_RANK, ROLES, Principal
from lg_sotf.api.auth.tokens import InvalidToken, is_local_token
from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.api.middleware import mark_principal
from lg_sotf.api.quotas import quota_conflict
from lg_sotf.api.ratelimit import RateDecision, rate_limited
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.repos import User
from lg_sotf.db.tenancy import is_valid_tenant_id
from lg_sotf.observability.logging import bind_context, get_logger
from lg_sotf.security.hashing import InvalidApiKey, looks_like_api_key, parse_api_key, sha256_hex, verify_api_key
from lg_sotf.services import accounts
from lg_sotf.services.tenancy import QuotaExceeded, ensure_capacity
from lg_sotf.settings import AuthSettings

log = get_logger(__name__)

TENANT_HEADER = "x-tenant-id"
API_KEY_HEADER = "x-api-key"
AUTH_FAILURE_BUCKET = "authfail"
MIN_AUTH_FAILURES_PER_MINUTE = 20
_DUMMY_KEY_HASH = "0" * 64
MAX_CREDENTIAL_CHARS = 8_192
MAX_OIDC_SUBJECT_CHARS = 255
# A provisioned account's last_login_at is refreshed by accepted OIDC tokens at most this often.
OIDC_SIGN_IN_RECORD_S = 300


def unauthorized(message: str = "authentication required") -> ApiError:
    return ApiError(401, "unauthorized", message, headers={"WWW-Authenticate": "Bearer"})


def forbidden(message: str) -> ApiError:
    return ApiError(403, "forbidden", message)


def tenant_suspended() -> ApiError:
    return ApiError(403, "tenant_suspended", "tenant is suspended")


def client_ip(conn: HTTPConnection) -> str:
    return conn.client.host if conn.client else "unknown"


def revoked_key(ctx: ApiContext, jti: str) -> str:
    return f"{ctx.prefix}:auth:revoked:{jti}"


def _credentials(conn: HTTPConnection) -> Tuple[Optional[str], Optional[str]]:
    """``(api_key, bearer_token)`` from the request headers."""
    header_key = conn.headers.get(API_KEY_HEADER)
    api_key: Optional[str] = header_key.strip() if header_key is not None else None
    bearer: Optional[str] = None
    header = conn.headers.get("authorization")
    if header:
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            raise unauthorized("unsupported authorization scheme")
        bearer = value.strip()
    if bearer is not None and looks_like_api_key(bearer):
        if api_key is not None and api_key != bearer:
            raise unauthorized("conflicting credentials")
        api_key, bearer = bearer, None
    for credential in (api_key, bearer):
        if credential is not None and len(credential) > MAX_CREDENTIAL_CHARS:
            raise unauthorized("credential too long")
    return api_key, bearer


def failure_limit(ctx: ApiContext) -> int:
    return max(MIN_AUTH_FAILURES_PER_MINUTE, ctx.settings.api.login_rate_limit_per_minute)


def credential_fingerprint(credential: str) -> str:
    """Stable, non-reversible identifier for a presented credential (rate-limit keys only)."""
    return sha256_hex(credential)[:32]


async def failure_blocked(ctx: ApiContext, ip: str, credential: str) -> Optional[RateDecision]:
    """Refusal when this exact credential kept failing from this address, else ``None``.

    The pre-check is keyed by address *and* credential fingerprint, so many
    clients behind one proxy address are never blocked by someone else's bad
    tokens: a credential that verifies is always accepted.
    """
    identity = f"{ip}:{credential_fingerprint(credential)}"
    limit = failure_limit(ctx)
    if await ctx.limiter.peek(AUTH_FAILURE_BUCKET, identity) >= limit:
        return await ctx.limiter.hit(AUTH_FAILURE_BUCKET, identity, limit, cost=0)
    return None


async def record_failure(ctx: ApiContext, ip: str, credential: Optional[str]) -> RateDecision:
    """Count a failed authentication; the result is the per-address decision.

    Callers turn a refused decision into 429 *for the failing request only*.
    """
    limit = failure_limit(ctx)
    if credential is not None:
        await ctx.limiter.hit(AUTH_FAILURE_BUCKET, f"{ip}:{credential_fingerprint(credential)}", limit)
    return await ctx.limiter.hit(AUTH_FAILURE_BUCKET, ip, limit)


async def authenticate(ctx: ApiContext, conn: HTTPConnection, *, allow_api_key: bool = True) -> Principal:
    """Authenticate the request and apply tenant checks and the ``X-Tenant-ID`` override."""
    ip = client_ip(conn)
    api_key, bearer = _credentials(conn)
    credential = api_key if api_key is not None else bearer
    if credential is None:
        raise unauthorized()
    blocked = await failure_blocked(ctx, ip, credential)
    if blocked is not None:
        raise rate_limited(blocked)
    try:
        if api_key is not None:
            if not allow_api_key:
                raise unauthorized("API keys are not accepted here")
            principal = await _api_key_principal(ctx, api_key)
        else:
            assert bearer is not None
            principal = await bearer_principal(ctx, bearer)
        await _require_active_tenant(ctx, principal.home_tenant_id)
    except ApiError as exc:
        if exc.status_code == 401:
            decision = await record_failure(ctx, ip, credential)
            log.info("auth.rejected", client_ip=ip, reason=exc.detail)
            if not decision.allowed:
                raise rate_limited(decision) from exc
        raise
    principal = await _apply_tenant_override(ctx, conn, principal)
    mark_principal(conn.scope, principal.tenant_id, principal.id)
    bind_context(tenant_id=principal.tenant_id)
    return principal


async def bearer_principal(ctx: ApiContext, token: str) -> Principal:
    """Principal for an access JWT (local) or an OIDC token."""
    if is_local_token(token):
        return await _local_principal(ctx, token)
    if ctx.oidc is not None and ctx.oidc.accepts(token):
        return await _oidc_principal(ctx, token)
    raise unauthorized("invalid token")


async def _local_principal(ctx: ApiContext, token: str) -> Principal:
    try:
        claims = ctx.tokens.verify_access(token)
    except InvalidToken as exc:
        raise unauthorized("invalid or expired token") from exc
    try:
        if await ctx.redis.exists(revoked_key(ctx, claims["jti"])):
            raise unauthorized("token has been revoked")
    except (RedisError, OSError, TimeoutError) as exc:
        # Access tokens are short-lived; an unreachable Redis must not lock every user out.
        log.warning("auth.revocation_check_unavailable", error_type=type(exc).__name__)
    tenant_id = claims["tenant"]
    if not is_valid_tenant_id(tenant_id):
        raise unauthorized("invalid token")
    try:
        user_id = UUID(claims["sub"])
    except ValueError as exc:
        raise unauthorized("invalid token") from exc
    try:
        user = await ctx.repos.users.get(tenant_id, user_id)
    except NotFound as exc:
        raise unauthorized("account no longer exists") from exc
    if not user.is_active:
        raise unauthorized("account is disabled")
    return Principal(
        kind="user",
        tenant_id=tenant_id,
        home_tenant_id=tenant_id,
        auth_method="password",
        role=user.role,
        user_id=user.id,
        email=user.email,
        subject=str(user.id),
        is_platform_admin=user.is_platform_admin,
        expires_at=datetime.fromtimestamp(int(claims["exp"]), UTC),
        token_id=claims["jti"],
    )


async def _oidc_principal(ctx: ApiContext, token: str) -> Principal:
    assert ctx.oidc is not None
    try:
        identity = await ctx.oidc.verify(token)
    except OIDCUnavailable as exc:
        log.warning("auth.oidc_unavailable", reason=str(exc))
        raise ApiError(503, "service_unavailable", "identity provider keys are unavailable; retry later") from exc
    except OIDCError as exc:
        log.info("auth.oidc_rejected", reason=str(exc))
        raise unauthorized("invalid or expired token") from exc
    tenant_id = identity.tenant_id
    if not tenant_id or not is_valid_tenant_id(tenant_id):
        raise unauthorized("token carries no valid tenant")
    # Before anything below writes (role sync, JIT provisioning): a suspended
    # or erased tenant must not gain accounts or audit rows through SSO.
    await _require_active_tenant(ctx, tenant_id)
    role = map_oidc_role(ctx.settings.auth, identity.roles)
    if role is None:
        raise forbidden("this identity has no LG-SOTF role")
    provisioned = await _provisioned_user(ctx, tenant_id, identity, role)
    if provisioned is not None:
        await _record_oidc_sign_in(ctx, provisioned)
        return _oidc_user_principal(identity, tenant_id, role, provisioned)
    # Blocking and linking are separate. A disabled local account with the
    # token's email blocks the token whether or not the IdP marks the email
    # verified (blocking can only hurt the token holder; IdPs such as Entra ID
    # omit email_verified). The identity is *linked* to that account (for
    # attribution) only through a verified email. The platform-admin flag is
    # never inherited over OIDC: platform admins use local login, so an IdP
    # account that can present an admin's email gains no cross-tenant access.
    user_id: Optional[UUID] = None
    email = identity.email if identity.email_verified else None
    if identity.email:
        try:
            user = await ctx.repos.users.get_by_email(tenant_id, identity.email)
        except ValueError:
            user = None
        if user is not None:
            if not user.is_active:
                raise unauthorized("account is disabled")
            # An account provisioned for another IdP subject is never linked by email.
            if identity.email_verified and user.oidc_subject is None:
                user_id = user.id
        elif ctx.settings.auth.oidc_jit_provisioning and identity.email_verified:
            created = await _provision(ctx, tenant_id, identity, role)
            if created is not None:
                await _record_oidc_sign_in(ctx, created)
                return _oidc_user_principal(identity, tenant_id, role, created)
    return Principal(
        kind="user",
        tenant_id=tenant_id,
        home_tenant_id=tenant_id,
        auth_method="oidc",
        role=role,
        user_id=user_id,
        email=email,
        subject=identity.subject,
        is_platform_admin=False,
        expires_at=datetime.fromtimestamp(identity.expires_at, UTC),
    )


def map_oidc_role(auth: AuthSettings, values: List[str]) -> Optional[str]:
    """The LG-SOTF role for these role-claim values (highest match), else ``auth.oidc_default_role``.

    Without ``auth.oidc_role_map`` the claim must carry the role names themselves.
    """
    mapping: Dict[str, str] = dict(auth.oidc_role_map) if auth.oidc_role_map else {r: r for r in ROLES}
    mapped = [mapping[v] for v in values if v in mapping and mapping[v] in ROLE_RANK]
    if mapped:
        return max(mapped, key=lambda r: ROLE_RANK[r])
    return auth.oidc_default_role


async def _record_oidc_sign_in(ctx: ApiContext, user: User) -> None:
    """Keep ``last_login_at`` of a provisioned account current (Slack approvals require a recent SSO sign-in)."""
    last = user.last_login_at
    if last is not None and (datetime.now(UTC) - last).total_seconds() < OIDC_SIGN_IN_RECORD_S:
        return
    await ctx.repos.users.record_sign_in(user.tenant_id, user.id)


def _oidc_user_principal(identity: OIDCIdentity, tenant_id: str, role: str, user: User) -> Principal:
    return Principal(
        kind="user",
        tenant_id=tenant_id,
        home_tenant_id=tenant_id,
        auth_method="oidc",
        role=role,
        user_id=user.id,
        email=user.email,
        subject=identity.subject,
        # Never inherited over OIDC, whatever the local row says.
        is_platform_admin=False,
        expires_at=datetime.fromtimestamp(identity.expires_at, UTC),
    )


async def _provisioned_user(ctx: ApiContext, tenant_id: str, identity: OIDCIdentity, role: str) -> Optional[User]:
    """The account provisioned for this IdP subject, its stored role synced to ``role`` (audited)."""
    if len(identity.subject) > MAX_OIDC_SUBJECT_CHARS:
        return None
    user = await ctx.repos.users.get_by_oidc_subject(tenant_id, identity.subject)
    if user is None:
        return None
    if not user.is_active:
        raise unauthorized("account is disabled")
    if user.role != role:
        user = await accounts.sync_sso_role(ctx.repos, AuditLogger(ctx.repos), user, role)
        log.info("auth.oidc_role_synced", tenant_id=tenant_id, role=role)
    return user


async def _provision(ctx: ApiContext, tenant_id: str, identity: OIDCIdentity, role: str) -> Optional[User]:
    """Just-in-time account for a verified identity (no password, never a platform admin).

    Counts against ``max_users`` like an admin-created account: a full tenant
    refuses the sign-in with ``409 quota_exceeded`` rather than granting an
    unlinked session.
    """
    if identity.email is None or len(identity.subject) > MAX_OIDC_SUBJECT_CHARS:
        return None
    try:
        async with ctx.db.tenant_tx(tenant_id) as conn:
            await ensure_capacity(ctx.repos, tenant_id, "max_users", conn=conn)
            user = await ctx.repos.users.create(
                tenant_id,
                identity.email,
                role,
                password_hash=None,
                is_platform_admin=False,
                oidc_subject=identity.subject,
                conn=conn,
            )
            await AuditLogger(ctx.repos).record(
                tenant_id,
                "user.provisioned",
                "user",
                str(user.id),
                actor_type="system",
                actor_id="oidc",
                details={"role": role, "via": "oidc_jit", "email_domain": user.email.rpartition("@")[2]},
                conn=conn,
            )
    except QuotaExceeded as exc:
        log.info("auth.oidc_provisioning_refused", tenant_id=tenant_id, reason="max_users")
        raise quota_conflict(exc) from exc
    except ValueError:
        return None
    except Conflict:
        # A concurrent first sign-in of the same subject won the race.
        return await ctx.repos.users.get_by_oidc_subject(tenant_id, identity.subject)
    log.info("auth.oidc_user_provisioned", tenant_id=tenant_id, role=role)
    return user


async def _api_key_principal(ctx: ApiContext, presented: str) -> Principal:
    try:
        parsed = parse_api_key(presented)
    except InvalidApiKey as exc:
        raise unauthorized("invalid API key") from exc
    key = await ctx.repos.api_keys.get_by_id_all_tenants(parsed.key_id)
    stored = key.key_hash if key is not None else _DUMMY_KEY_HASH
    matches = verify_api_key(presented, stored)
    if key is None or not matches or key.is_revoked:
        raise unauthorized("invalid API key")
    try:
        await ctx.repos.api_keys.touch_last_used(key.tenant_id, key.id)
    except Exception as exc:  # noqa: BLE001 - bookkeeping only; never fail the request for it
        log.warning("auth.api_key_touch_failed", error_type=type(exc).__name__)
    return Principal(
        kind="api_key",
        tenant_id=key.tenant_id,
        home_tenant_id=key.tenant_id,
        auth_method="api_key",
        scopes=frozenset(key.scopes),
        api_key_id=key.id,
        subject=str(key.id),
    )


async def _require_active_tenant(ctx: ApiContext, tenant_id: str) -> None:
    tenant = await ctx.tenants.get(tenant_id)
    if tenant is None:
        raise unauthorized("tenant does not exist")
    if tenant.status != "active":
        # Users, SSO identities and API keys (ingest included) of a suspended tenant are refused.
        raise tenant_suspended()


async def _apply_tenant_override(ctx: ApiContext, conn: HTTPConnection, principal: Principal) -> Principal:
    requested = conn.headers.get(TENANT_HEADER)
    if requested is None or requested == principal.home_tenant_id:
        return principal
    if not principal.is_platform_admin:
        raise forbidden("X-Tenant-ID is only honoured for platform admins")
    if not is_valid_tenant_id(requested):
        raise ApiError(400, "invalid_tenant", "X-Tenant-ID is not a valid tenant id")
    tenant = await ctx.tenants.get(requested)
    if tenant is None:
        raise ApiError(404, "not_found", "tenant not found")
    await AuditLogger(ctx.repos).record_event(
        requested,
        "platform_admin.tenant_access",
        "tenant",
        requested,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details={
            "home_tenant_id": principal.home_tenant_id,
            "method": conn.scope.get("method", "WS"),
            "path": conn.url.path,
        },
    )
    log.info("auth.tenant_override", home_tenant_id=principal.home_tenant_id, tenant_id=requested)
    return principal.acting_on(requested)
