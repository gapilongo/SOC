# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/users`` and ``/api-keys`` (admin).

* Password hashes are never returned; passwords must be at least
  ``auth.password_min_length`` characters.
* Admins cannot change their own role or platform-admin flag, deactivate or
  delete themselves, or leave the tenant without an active admin. Only a
  platform admin can grant the platform-admin flag.
* Changing a password or deactivating a user revokes their refresh tokens.
* ``POST /users/{id}/mfa/reset`` removes a user's MFA (lost device) and signs
  them out everywhere. Admins reset users of their own tenant; only a
  platform admin resets a platform admin (or, with ``X-Tenant-ID``, a user
  of any tenant). Nobody resets their own MFA here (``/auth/mfa/disable``).
* An API key's secret appears only in the create response.
* Creating or reactivating an account beyond the tenant's ``max_users``
  quota (active accounts) is refused with ``409 quota_exceeded``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from lg_sotf.api.auth.deps import ADMIN, ADMIN_USER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import check_password
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.quotas import quota_conflict
from lg_sotf.api.schemas import ApiKeyCreatedOut, ApiKeyCreateIn, ApiKeyOut, UserCreateIn, UserOut, UserUpdateIn
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.repos import UNSET, User
from lg_sotf.db.repos.users import normalize_email
from lg_sotf.security.hashing import ahash_password, generate_api_key
from lg_sotf.services import accounts
from lg_sotf.services.tenancy import QuotaExceeded

users = APIRouter(prefix="/users", tags=["users"])
api_keys = APIRouter(prefix="/api-keys", tags=["api-keys"])

_REFUSALS: Dict[str, Tuple[int, str, str]] = {
    "platform_admin_target": (403, "forbidden", "only a platform admin can modify a platform-admin account"),
    "last_admin": (409, "last_admin", "the tenant must keep at least one active admin"),
}


def _refused(refusal: accounts.UserRefusal) -> ApiError:
    return ApiError(*_REFUSALS[refusal])


# ------------------------------------------------------------------ users


def user_out(user: User, mfa: Dict[UUID, datetime]) -> UserOut:
    """``UserOut`` with the MFA and provisioning flags (never the secret state itself)."""
    return UserOut.model_validate(user).model_copy(
        update={"mfa_enabled": user.id in mfa, "oidc_provisioned": user.oidc_subject is not None}
    )


@users.get("", response_model=List[UserOut], summary="List users")
async def list_users(
    request: Request,
    include_inactive: bool = Query(default=True),
    principal: Principal = Depends(require(ADMIN)),
) -> List[UserOut]:
    ctx = get_ctx(request)
    rows: List[User] = []
    cursor: Optional[str] = None
    while True:
        page = await ctx.repos.users.list(principal.tenant_id, include_inactive=include_inactive, cursor=cursor)
        rows.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    mfa = await ctx.repos.user_mfa.enabled_since(principal.tenant_id)
    return [user_out(u, mfa) for u in rows]


@users.get("/{user_id}", response_model=UserOut, summary="User detail")
async def get_user(user_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> UserOut:
    ctx = get_ctx(request)
    user = await ctx.repos.users.get(principal.tenant_id, user_id)
    return user_out(user, await ctx.repos.user_mfa.enabled_since(principal.tenant_id))


@users.post("", status_code=201, response_model=UserOut, summary="Create a user")
async def create_user(body: UserCreateIn, request: Request, principal: Principal = Depends(require(ADMIN))) -> UserOut:
    ctx = get_ctx(request)
    if body.is_platform_admin and not principal.is_platform_admin:
        raise ApiError(403, "forbidden", "only a platform admin can create platform admins")
    try:
        email = normalize_email(body.email)
    except ValueError as exc:
        raise ApiError(422, "validation_error", "email is not a valid address") from exc
    password_hash: Optional[str] = None
    if body.password is not None:
        check_password(ctx, body.password)
        password_hash = await ahash_password(body.password)
    try:
        user = await accounts.create_user(
            ctx.repos,
            AuditLogger(ctx.repos),
            principal.tenant_id,
            principal.actor,
            email=email,
            role=body.role,
            password_hash=password_hash,
            is_platform_admin=body.is_platform_admin,
            is_active=body.is_active,
        )
    except QuotaExceeded as exc:
        raise quota_conflict(exc) from exc
    except Conflict as exc:
        raise ApiError(409, "conflict", "a user with this email already exists") from exc
    return UserOut.model_validate(user)


@users.patch("/{user_id}", response_model=UserOut, summary="Update role, status or password")
async def update_user(
    user_id: UUID, body: UserUpdateIn, request: Request, principal: Principal = Depends(require(ADMIN_USER))
) -> UserOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    fields = body.model_fields_set
    for name in ("role", "is_active", "is_platform_admin", "password"):
        if name in fields and getattr(body, name) is None:
            raise ApiError(422, "validation_error", f"{name} cannot be null")
    myself = user_id == principal.user_id
    if myself and ({"role", "is_platform_admin"} & fields or body.is_active is False):
        raise ApiError(403, "forbidden", "you cannot change your own role, platform flag or active status")
    if body.is_platform_admin is not None and not principal.is_platform_admin:
        raise ApiError(403, "forbidden", "only a platform admin can change the platform-admin flag")
    password_hash: Optional[str] = UNSET
    if body.password is not None:
        check_password(ctx, body.password)
        password_hash = await ahash_password(body.password)
    try:
        result = await accounts.update_user(
            ctx.repos,
            AuditLogger(ctx.repos),
            tenant_id,
            principal.actor,
            user_id,
            by_platform_admin=principal.is_platform_admin,
            fields=fields,
            role=body.role,
            is_active=body.is_active,
            is_platform_admin=body.is_platform_admin,
            password_hash=password_hash,
        )
    except QuotaExceeded as exc:
        raise quota_conflict(exc) from exc
    if isinstance(result, str):
        raise _refused(result)
    return user_out(result, await ctx.repos.user_mfa.enabled_since(tenant_id))


@users.post("/{user_id}/mfa/reset", status_code=204, summary="Remove a user's MFA (lost device); signs them out")
async def reset_user_mfa(user_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> Response:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    if user_id == principal.user_id:
        raise ApiError(403, "forbidden", "use /auth/mfa/disable for your own account")
    refusal = await accounts.reset_mfa(
        ctx.repos,
        AuditLogger(ctx.repos),
        tenant_id,
        principal.actor,
        user_id,
        by_platform_admin=principal.is_platform_admin,
        actor_home_tenant_id=principal.home_tenant_id,
    )
    if refusal is not None:
        raise _refused(refusal)
    return Response(status_code=204)


@users.delete("/{user_id}", status_code=204, summary="Delete a user")
async def delete_user(user_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN_USER))) -> Response:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    if user_id == principal.user_id:
        raise ApiError(403, "forbidden", "you cannot delete yourself")
    try:
        refusal = await accounts.delete_user(
            ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, user_id, by_platform_admin=principal.is_platform_admin
        )
    except Conflict as exc:
        raise ApiError(
            409, "conflict", "the user is referenced by review history; deactivate the account instead"
        ) from exc
    if refusal is not None:
        raise _refused(refusal)
    return Response(status_code=204)


# --------------------------------------------------------------- api keys


@api_keys.get("", response_model=List[ApiKeyOut], summary="List API keys")
async def list_keys(
    request: Request,
    include_revoked: bool = Query(default=False),
    principal: Principal = Depends(require(ADMIN)),
) -> List[ApiKeyOut]:
    keys = await get_ctx(request).repos.api_keys.list(principal.tenant_id, include_revoked=include_revoked)
    return [ApiKeyOut.model_validate(k) for k in keys]


@api_keys.post("", status_code=201, response_model=ApiKeyCreatedOut, summary="Create an API key (secret shown once)")
async def create_key(
    body: ApiKeyCreateIn, request: Request, principal: Principal = Depends(require(ADMIN))
) -> ApiKeyCreatedOut:
    ctx = get_ctx(request)
    generated = generate_api_key()
    key = await accounts.create_api_key(
        ctx.repos,
        AuditLogger(ctx.repos),
        principal.tenant_id,
        principal.actor,
        name=body.name,
        prefix=generated.prefix,
        key_hash=generated.key_hash,
        scopes=list(body.scopes),
        created_by=principal.local_user_id,
        key_id=generated.key_id,
    )
    return ApiKeyCreatedOut.model_validate({**key.model_dump(exclude={"key_hash"}), "key": generated.token})


@api_keys.delete("/{key_id}", status_code=204, summary="Revoke an API key")
async def revoke_key(key_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> Response:
    ctx = get_ctx(request)
    if not await accounts.revoke_api_key(
        ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, key_id
    ):
        if await ctx.repos.api_keys.get_by_id(principal.tenant_id, key_id) is None:
            raise NotFound("api key", key_id)
        return Response(status_code=204)
    return Response(status_code=204)
