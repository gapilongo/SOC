"""Audited integration changes: create, update, delete and the recorded connection test.

Each function runs the change and its audit entry in one ``db.tenant_tx``,
so an audit failure rolls the change back. The caller
(``api.routers.integrations``) validates the configuration, encrypts the
secret and builds the audit details, which name fields and capabilities but
never carry secret values.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import Integration, Repositories
from lg_sotf.db.repos.integrations import NewOutboxEntry

RESOURCE = "integration"


async def create_integration(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    kind: str,
    name: str,
    details: Mapping[str, Any],
    **attributes: Any,
) -> Integration:
    """Create an integration (``attributes`` as for ``IntegrationsRepo.create``); audited ``integration.created``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        integration = await repos.integrations.create(tenant_id, kind, name, **attributes, conn=conn)
        await audit.record(
            tenant_id,
            "integration.created",
            RESOURCE,
            str(integration.id),
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
    return integration


async def update_integration(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    integration_id: UUID,
    changes: Mapping[str, Any],
    *,
    details: Mapping[str, Any],
) -> Integration:
    """Apply ``changes`` (repository column values); audited ``integration.updated``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        integration = await repos.integrations.update(tenant_id, integration_id, **changes, conn=conn)
        await audit.record(
            tenant_id,
            "integration.updated",
            RESOURCE,
            str(integration_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
    return integration


async def delete_integration(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    integration_id: UUID,
    *,
    details: Mapping[str, Any],
) -> bool:
    """Delete an integration with its delivery log and ticket links (audited); ``False`` when there is none."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if not await repos.integrations.delete(tenant_id, integration_id, conn=conn):
            return False
        await audit.record(
            tenant_id,
            "integration.deleted",
            RESOURCE,
            str(integration_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
    return True


async def record_test(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    entry: NewOutboxEntry,
    *,
    ok: bool,
    error: Optional[str],
    result: Optional[Mapping[str, Any]],
    details: Mapping[str, Any],
) -> None:
    """Store a finished connection test in the delivery log; audited ``integration.tested``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        await repos.integrations.record_test(tenant_id, entry, ok=ok, error=error, result=result, conn=conn)
        await audit.record(
            tenant_id,
            "integration.tested",
            RESOURCE,
            str(entry.integration_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
