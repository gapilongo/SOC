"""Delegated access: organisations, their members, and the grants customer tenants give them.

A grant is created and revoked by the customer tenant. Both changes are
audited in both chains in one transaction: the customer's (``grant.created``,
``grant.revoked``) and the organisation's home tenant's (``grant.received``,
``grant.revoked``), so neither side can lose the record. Membership changes
are audited in the organisation's chain. A grant to an organisation that does
not exist is stored and audited for the customer like any other (the answer
reveals nothing); there is no organisation chain to write to, and it never
works.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Organisation, OrganisationMember, Repositories, TenantGrant
from lg_sotf.db.tenancy import switch_tenant
from lg_sotf.db.types import Connection

GRANT = "tenant_grant"


def _grant_details(grant: TenantGrant) -> dict[str, object]:
    return {
        "tenant_id": grant.tenant_id,
        "organisation_id": grant.organisation_id,
        "user_id": str(grant.user_id) if grant.user_id else None,
        "role": grant.role,
        "allow_api_keys": grant.allow_api_keys,
        "expires_at": grant.expires_at.isoformat(),
        "reason": grant.reason,
    }


async def create_grant(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    organisation_id: str,
    role: str,
    reason: str,
    expires_at: datetime,
    user_id: Optional[UUID] = None,
    allow_api_keys: bool = False,
) -> TenantGrant:
    """Open ``tenant_id`` to the organisation (or one member); audited in both chains."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        grant = await repos.grants.create(
            tenant_id, organisation_id, role, reason=reason, created_by=actor.id or actor.type,
            expires_at=expires_at, user_id=user_id, allow_api_keys=allow_api_keys, conn=conn,
        )
        details = _grant_details(grant)
        await audit.record(
            tenant_id, "grant.created", GRANT, str(grant.id), actor_type=actor.type, actor_id=actor.id,
            details=details, conn=conn,
        )
        if await _is_organisation(repos, organisation_id, tenant_id, conn):
            await switch_tenant(conn, organisation_id)
            await audit.record(
                organisation_id, "grant.received", GRANT, str(grant.id), actor_type=actor.type, actor_id=actor.id,
                details=details, conn=conn,
            )
    return grant


async def _is_organisation(repos: Repositories, organisation_id: str, tenant_id: str, conn: Connection) -> bool:
    """Read in the organisation's own scope; the transaction is switched back to ``tenant_id`` after."""
    await switch_tenant(conn, organisation_id)
    found = await repos.organisations.get(organisation_id, conn=conn) is not None
    await switch_tenant(conn, tenant_id)
    return found


async def revoke_grant(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, grant_id: UUID
) -> TenantGrant:
    """Revoke a live grant of ``tenant_id`` (:class:`NotFound` when there is none); audited in both chains."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        grant = await repos.grants.revoke(tenant_id, grant_id, revoked_by=actor.id or actor.type, conn=conn)
        if grant is None:
            raise NotFound("grant", str(grant_id))
        # Nothing written under the grant outlives it: its suppression rules end with it.
        expired = await repos.suppressions.expire_for_grant(tenant_id, grant.id, conn=conn)
        known = await _is_organisation(repos, grant.organisation_id, tenant_id, conn)
        for chain in (tenant_id, grant.organisation_id) if known else (tenant_id,):
            await switch_tenant(conn, chain)
            await audit.record(
                chain, "grant.revoked", GRANT, str(grant.id), actor_type=actor.type, actor_id=actor.id,
                details={**_grant_details(grant), "suppression_rules_expired": expired}, conn=conn,
            )
    return grant


async def save_organisation(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, name: str, *, home_tenant_id: str
) -> Organisation:
    """Make ``tenant_id`` an MSSP organisation (or rename it); audited in that tenant and the admin's own."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        organisation = await repos.organisations.upsert(tenant_id, name, conn=conn)
        for chain, action in ((tenant_id, "organisation.saved"), (home_tenant_id, "platform.organisation_saved")):
            await switch_tenant(conn, chain)
            await audit.record(
                chain, action, "organisation", tenant_id, actor_type=actor.type, actor_id=actor.id,
                details={"name": name, "home_tenant_id": home_tenant_id}, conn=conn,
            )
    return organisation


async def add_member(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, user_id: UUID
) -> OrganisationMember:
    """Let a user of the organisation's home tenant act under its grants; audited in that tenant."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        member = await repos.organisations.add_member(tenant_id, user_id, added_by=actor.id, conn=conn)
        await audit.record(
            tenant_id, "organisation.member_added", "user", str(user_id), actor_type=actor.type, actor_id=actor.id,
            conn=conn,
        )
    return member


async def remove_member(repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, user_id: UUID) -> None:
    """Remove a member (:class:`NotFound` if not one); grants given to that member alone go with it."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if not await repos.organisations.remove_member(tenant_id, user_id, conn=conn):
            raise NotFound("organisation member", str(user_id))
        await audit.record(
            tenant_id, "organisation.member_removed", "user", str(user_id), actor_type=actor.type, actor_id=actor.id,
            conn=conn,
        )
