# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/users`` and ``/api-keys`` (admin).

* Password hashes are never returned; passwords must be at least
  ``auth.password_min_length`` characters.
* Admins cannot change their own role or platform-admin flag, deactivate or
  delete themselves, or leave the tenant without an active admin. Only a
  platform admin can grant the platform-admin flag.
* Changing a password or deactivating a user revokes their refresh tokens.
* An API key's secret appears only in the create response.
* Creating or reactivating an account beyond the tenant's ``max_users``
  quota (active accounts) is refused with ``409 quota_exceeded``.
"""

from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from lg_sotf.api.auth.deps import ADMIN, ADMIN_USER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.quotas import quota_conflict
from lg_sotf.api.schemas import ApiKeyCreatedOut, ApiKeyCreateIn, ApiKeyOut, UserCreateIn, UserOut, UserUpdateIn
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict, NotFound
from lg_sotf.db.repos import UNSET
from lg_sotf.db.repos.users import normalize_email
from lg_sotf.security.hashing import ahash_password, generate_api_key
from lg_sotf.services.tenancy import QuotaExceeded, ensure_capacity

users = APIRouter(prefix="/users", tags=["users"])
api_keys = APIRouter(prefix="/api-keys", tags=["api-keys"])

MAX_PASSWORD_CHARS = 1_024


def check_password(ctx: ApiContext, password: str) -> None:
    minimum = ctx.settings.auth.password_min_length
    if len(password) < minimum:
        raise ApiError(422, "weak_password", f"password must be at least {minimum} characters")
    if len(password) > MAX_PASSWORD_CHARS:
        raise ApiError(422, "weak_password", f"password must be at most {MAX_PASSWORD_CHARS} characters")
    if len(set(password)) < 4:
        raise ApiError(422, "weak_password", "password is too repetitive")


def _guard_platform_admin_target(principal: Principal, target: object) -> None:
    """Only a platform admin may modify or delete a platform-admin account.

    Otherwise a tenant admin could reset a platform admin's password, log in as
    them and use the cross-tenant ``X-Tenant-ID`` override.
    """
    if getattr(target, "is_platform_admin", False) and not principal.is_platform_admin:
        raise ApiError(403, "forbidden", "only a platform admin can modify a platform-admin account")


async def _audit(
    ctx: ApiContext, principal: Principal, action: str, resource: str, rid: str, **details: object
) -> None:
    await AuditLogger(ctx.repos).record(
        principal.tenant_id,
        action,
        resource,
        rid,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details=details,
    )


# ------------------------------------------------------------------ users


@users.get("", response_model=List[UserOut], summary="List users")
async def list_users(
    request: Request,
    include_inactive: bool = Query(default=True),
    principal: Principal = Depends(require(ADMIN)),
) -> List[UserOut]:
    rows = await get_ctx(request).repos.users.list(principal.tenant_id, include_inactive=include_inactive, limit=1000)
    return [UserOut.model_validate(u) for u in rows]


@users.get("/{user_id}", response_model=UserOut, summary="User detail")
async def get_user(user_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> UserOut:
    return UserOut.model_validate(await get_ctx(request).repos.users.get(principal.tenant_id, user_id))


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
        async with ctx.db.tenant_tx(principal.tenant_id) as conn:
            if body.is_active:
                await ensure_capacity(ctx.repos, principal.tenant_id, "max_users", conn=conn)
            user = await ctx.repos.users.create(
                principal.tenant_id,
                email,
                body.role,
                password_hash=password_hash,
                is_platform_admin=body.is_platform_admin,
                is_active=body.is_active,
                conn=conn,
            )
    except QuotaExceeded as exc:
        raise quota_conflict(exc) from exc
    except Conflict as exc:
        raise ApiError(409, "conflict", "a user with this email already exists") from exc
    await _audit(ctx, principal, "user.created", "user", str(user.id), role=user.role, sso_only=password_hash is None)
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
    async with ctx.db.tenant_tx(tenant_id) as conn:
        current = await ctx.repos.users.get(tenant_id, user_id, conn=conn)
        _guard_platform_admin_target(principal, current)
        demoting = (
            current.role == "admin"
            and current.is_active
            and ((body.role is not None and body.role != "admin") or body.is_active is False)
        )
        if demoting and await ctx.repos.users.count_active_admins(tenant_id, conn=conn) <= 1:
            raise ApiError(409, "last_admin", "the tenant must keep at least one active admin")
        if body.is_active is True and not current.is_active:
            try:
                await ensure_capacity(ctx.repos, tenant_id, "max_users", conn=conn)
            except QuotaExceeded as exc:
                raise quota_conflict(exc) from exc
        user = await ctx.repos.users.update(
            tenant_id,
            user_id,
            role=body.role if body.role is not None else UNSET,
            is_active=body.is_active if body.is_active is not None else UNSET,
            is_platform_admin=body.is_platform_admin if body.is_platform_admin is not None else UNSET,
            password_hash=password_hash,
            conn=conn,
        )
        revoked = 0
        if body.password is not None or body.is_active is False:
            revoked = await ctx.repos.refresh_tokens.revoke_all_for_user(tenant_id, user_id, conn=conn)
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "user.updated",
            "user",
            str(user_id),
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={
                "fields": sorted(fields - {"password"}) + (["password"] if "password" in fields else []),
                "role": user.role,
                "revoked_sessions": revoked,
            },
            conn=conn,
        )
    return UserOut.model_validate(user)


@users.delete("/{user_id}", status_code=204, summary="Delete a user")
async def delete_user(user_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN_USER))) -> Response:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    if user_id == principal.user_id:
        raise ApiError(403, "forbidden", "you cannot delete yourself")
    async with ctx.db.tenant_tx(tenant_id) as conn:
        current = await ctx.repos.users.get(tenant_id, user_id, conn=conn)
        _guard_platform_admin_target(principal, current)
        if (
            current.role == "admin"
            and current.is_active
            and await ctx.repos.users.count_active_admins(tenant_id, conn=conn) <= 1
        ):
            raise ApiError(409, "last_admin", "the tenant must keep at least one active admin")
        await ctx.repos.refresh_tokens.revoke_all_for_user(tenant_id, user_id, conn=conn)
        try:
            async with conn.transaction():
                await ctx.repos.users.delete(tenant_id, user_id, conn=conn)
        except Conflict as exc:
            raise ApiError(
                409, "conflict", "the user is referenced by review history; deactivate the account instead"
            ) from exc
        await AuditLogger(ctx.repos).record(
            tenant_id,
            "user.deleted",
            "user",
            str(user_id),
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"email_domain": current.email.rpartition("@")[2]},
            conn=conn,
        )
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
    key = await ctx.repos.api_keys.create(
        principal.tenant_id,
        body.name,
        generated.prefix,
        generated.key_hash,
        list(body.scopes),
        created_by=principal.local_user_id,
        key_id=generated.key_id,
    )
    await _audit(ctx, principal, "api_key.created", "api_key", str(key.id), scopes=key.scopes, name=key.name)
    return ApiKeyCreatedOut.model_validate({**key.model_dump(exclude={"key_hash"}), "key": generated.token})


@api_keys.delete("/{key_id}", status_code=204, summary="Revoke an API key")
async def revoke_key(key_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> Response:
    ctx = get_ctx(request)
    if not await ctx.repos.api_keys.revoke(principal.tenant_id, key_id):
        if await ctx.repos.api_keys.get_by_id(principal.tenant_id, key_id) is None:
            raise NotFound("api key", key_id)
        return Response(status_code=204)
    await _audit(ctx, principal, "api_key.revoked", "api_key", str(key_id))
    return Response(status_code=204)
