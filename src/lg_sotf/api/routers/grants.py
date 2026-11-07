# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""Delegated access for MSSPs: organisations, their members, and the grants customer tenants give them.

* ``PUT /platform/organisations/{tenant_id}`` (platform admins): make a
  tenant an MSSP organisation. Its staff are users of that tenant.
* ``/organisation/members`` (the organisation's admins): who may act under
  its grants. ``GET /organisation/grants`` (its staff): where they may act.
* ``/tenant/grants`` (the customer's admins): give an organisation (or one
  member) a role in this tenant until an expiry, see every grant given, and
  revoke one. Grants are given and revoked only by the customer's own
  accounts, never under a grant or a platform admin's ``X-Tenant-ID``.

A member acts in a granted tenant by sending ``X-Tenant-ID`` (see
``api.auth.authenticate``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from lg_sotf.api.auth.deps import PLATFORM_ADMIN, Access, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.common import aware
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.grant_schemas import MAX_GRANT_DAYS, GrantIn, GrantOut, MemberOut, OrganisationIn, OrganisationOut
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.errors import NotFound
from lg_sotf.db.tenancy import validate_tenant_id
from lg_sotf.services import grants as delegation

tenant_grants = APIRouter(prefix="/tenant/grants", tags=["grants"])
organisation = APIRouter(prefix="/organisation", tags=["grants"])
platform = APIRouter(prefix="/platform/organisations", tags=["platform"])

# The customer's admins (a platform admin may look with X-Tenant-ID); never someone acting under a grant.
GRANT_READER = Access(role="admin", no_grant=True)
# Only the customer's own admin accounts give and revoke access to it.
GRANTOR = Access(role="admin", user_account=True, home_tenant_only=True)
ORG_ADMIN = Access(role="admin", user_account=True, home_tenant_only=True)
ORG_STAFF = Access(role="viewer", user_account=True, home_tenant_only=True)


async def _require_organisation(request: Request, tenant_id: str) -> None:
    if await get_ctx(request).repos.organisations.get(tenant_id) is None:
        raise NotFound("organisation", tenant_id)


# ----------------------------------------------------------- customer side


@tenant_grants.get("", response_model=List[GrantOut], summary="Every grant this tenant gave (revoked included)")
async def list_grants(request: Request, principal: Principal = Depends(require(GRANT_READER))) -> List[GrantOut]:
    grants = await get_ctx(request).repos.grants.list_for_tenant(principal.tenant_id)
    return [GrantOut.model_validate(g) for g in grants]


@tenant_grants.post("", status_code=201, response_model=GrantOut, summary="Give an MSSP organisation a role here")
async def create_grant(body: GrantIn, request: Request, principal: Principal = Depends(require(GRANTOR))) -> GrantOut:
    """404 when the organisation (or ``user_id`` as one of its members) does not exist."""
    expires_at = aware(body.expires_at)
    assert expires_at is not None
    now = datetime.now(UTC)
    if not now < expires_at <= now + timedelta(days=MAX_GRANT_DAYS):
        raise ApiError(422, "validation_error", f"expires_at must be in the next {MAX_GRANT_DAYS} days")
    if body.organisation_id == principal.tenant_id:
        raise ApiError(422, "validation_error", "a tenant cannot grant itself")
    ctx = get_ctx(request)
    grant = await delegation.create_grant(
        ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor,
        organisation_id=body.organisation_id, role=body.role, reason=body.reason.strip(),
        expires_at=expires_at, user_id=body.user_id,
    )
    return GrantOut.model_validate(grant)


@tenant_grants.post("/{grant_id}/revoke", response_model=GrantOut, summary="Revoke a grant (effective at once)")
async def revoke_grant(grant_id: UUID, request: Request, principal: Principal = Depends(require(GRANTOR))) -> GrantOut:
    ctx = get_ctx(request)
    grant = await delegation.revoke_grant(ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, grant_id)
    return GrantOut.model_validate(grant)


# ------------------------------------------------------- organisation side


@organisation.get("/grants", response_model=List[GrantOut], summary="The tenants your organisation may act in")
async def organisation_grants(request: Request, principal: Principal = Depends(require(ORG_STAFF))) -> List[GrantOut]:
    grants = await get_ctx(request).repos.grants.list_for_organisation(principal.tenant_id)
    return [GrantOut.model_validate(g) for g in grants]


@organisation.get("/members", response_model=List[MemberOut], summary="Staff who may act under the grants")
async def list_members(request: Request, principal: Principal = Depends(require(ORG_STAFF))) -> List[MemberOut]:
    await _require_organisation(request, principal.tenant_id)
    members = await get_ctx(request).repos.organisations.list_members(principal.tenant_id)
    return [MemberOut.model_validate(m) for m in members]


@organisation.put("/members/{user_id}", response_model=MemberOut, summary="Add a staff account")
async def add_member(user_id: UUID, request: Request, principal: Principal = Depends(require(ORG_ADMIN))) -> MemberOut:
    await _require_organisation(request, principal.tenant_id)
    ctx = get_ctx(request)
    member = await delegation.add_member(ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, user_id)
    return MemberOut.model_validate(member)


@organisation.delete("/members/{user_id}", status_code=204, summary="Remove a staff account (and its own grants)")
async def remove_member(user_id: UUID, request: Request, principal: Principal = Depends(require(ORG_ADMIN))) -> Response:
    ctx = get_ctx(request)
    await delegation.remove_member(ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, user_id)
    return Response(status_code=204)


# ------------------------------------------------------------------ platform


@platform.put("/{tenant_id}", response_model=OrganisationOut, summary="Make a tenant an MSSP organisation")
async def save_organisation(
    tenant_id: str, body: OrganisationIn, request: Request, principal: Principal = Depends(require(PLATFORM_ADMIN))
) -> OrganisationOut:
    validate_tenant_id(tenant_id)
    ctx = get_ctx(request)
    if await ctx.tenants.get(tenant_id) is None:
        raise NotFound("tenant", tenant_id)
    saved = await delegation.save_organisation(
        ctx.repos, AuditLogger(ctx.repos), tenant_id, principal.actor, body.name.strip(),
        home_tenant_id=principal.home_tenant_id,
    )
    return OrganisationOut.model_validate(saved)
