# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/platform`` (platform admins only): operations across tenants.

``POST /platform/tenants`` provisions a tenant, optionally with its first
admin user. The runtime database role cannot insert tenants itself; the row
is created through the ``lgsotf_create_tenant`` SECURITY DEFINER function
(migration 0002). The creation is audited in the new tenant and in the
platform admin's home tenant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import Field

from lg_sotf.api.auth.deps import PLATFORM_ADMIN, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.routers.identity import check_password
from lg_sotf.api.schemas import In, Out, UserOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import Conflict
from lg_sotf.db.repos.users import normalize_email
from lg_sotf.db.tenancy import TENANT_ID_PATTERN
from lg_sotf.security.hashing import ahash_password

router = APIRouter(prefix="/platform", tags=["platform"])


class TenantCreateIn(In):
    id: str = Field(pattern=TENANT_ID_PATTERN, description="2-63 characters: a-z, 0-9, '-', '_'.")
    name: str = Field(min_length=1, max_length=200)
    admin_email: Optional[str] = Field(default=None, min_length=3, max_length=320)
    admin_password: Optional[str] = Field(
        default=None, max_length=1_024, description="Omit for an SSO-only admin. Write-only."
    )


class TenantCreatedOut(Out):
    id: str
    name: str
    status: str
    created_at: datetime
    admin: Optional[UserOut] = None


@router.post("/tenants", status_code=201, response_model=TenantCreatedOut, summary="Provision a tenant")
async def create_tenant(
    body: TenantCreateIn, request: Request, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> TenantCreatedOut:
    ctx = get_ctx(request)
    name = body.name.strip()
    if not name:
        raise ApiError(422, "validation_error", "name must not be blank")
    if body.admin_password is not None and body.admin_email is None:
        raise ApiError(422, "validation_error", "admin_password needs admin_email")
    email: Optional[str] = None
    password_hash: Optional[str] = None
    if body.admin_email is not None:
        try:
            email = normalize_email(body.admin_email)
        except ValueError as exc:
            raise ApiError(422, "validation_error", "admin_email is not a valid address") from exc
        if body.admin_password is not None:
            check_password(ctx, body.admin_password)
            password_hash = await ahash_password(body.admin_password)
    try:
        tenant = await ctx.repos.tenants.provision(body.id, name)
    except Conflict as exc:
        raise ApiError(409, "conflict", f"tenant {body.id!r} already exists") from exc
    ctx.tenants.invalidate(tenant.id)
    audit = AuditLogger(ctx.repos)
    details = {"name": tenant.name, "home_tenant_id": principal.home_tenant_id, "with_admin": email is not None}
    for tenant_id, action in ((tenant.id, "tenant.created"), (principal.home_tenant_id, "platform.tenant_created")):
        await audit.record(
            tenant_id,
            action,
            "tenant",
            tenant.id,
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details=details,
        )
    admin: Optional[UserOut] = None
    if email is not None:
        user = await ctx.repos.users.create(tenant.id, email, "admin", password_hash=password_hash)
        await audit.record(
            tenant.id,
            "user.created",
            "user",
            str(user.id),
            actor_type=principal.actor_type,
            actor_id=principal.actor_id,
            details={"role": user.role, "sso_only": password_hash is None, "home_tenant_id": principal.home_tenant_id},
        )
        admin = UserOut.model_validate(user)
    return TenantCreatedOut(id=tenant.id, name=tenant.name, status=tenant.status, created_at=tenant.created_at, admin=admin)
