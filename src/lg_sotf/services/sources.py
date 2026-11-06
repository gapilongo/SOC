"""Audited alert-source changes: create, update and delete.

Each function runs the change and its audit entry in one ``db.tenant_tx``,
so an audit failure rolls the change back. Validation and secret encryption
happen in the caller before the call (``api.routers.sources``).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import Repositories, Source
from lg_sotf.services.tenancy import ensure_capacity


async def create_source(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    source_type: str,
    name: str,
    source_id: str,
    config: Mapping[str, Any],
    secret_ciphertext: Optional[str],
    poll_interval_s: int,
    enabled: bool,
) -> Source:
    """Create a source within the ``max_sources`` quota (raises ``QuotaExceeded``); audited ``source.created``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        await ensure_capacity(repos, tenant_id, "max_sources", conn=conn)
        source = await repos.sources.create(
            tenant_id,
            source_type,
            name,
            source_id=source_id,
            config=config,
            secret_ciphertext=secret_ciphertext,
            poll_interval_s=poll_interval_s,
            enabled=enabled,
            conn=conn,
        )
        await audit.record(
            tenant_id,
            "source.created",
            "source",
            source.id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"type": source.type, "has_secret": secret_ciphertext is not None},
            conn=conn,
        )
    return source


async def update_source(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    source_id: str,
    changes: Mapping[str, Any],
    *,
    fields: Iterable[str],
) -> Source:
    """Apply ``changes`` (repository column values); ``fields`` are the request fields, audited by name only."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        source = await repos.sources.update(tenant_id, source_id, **changes, conn=conn)
        await audit.record(
            tenant_id,
            "source.updated",
            "source",
            source_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"fields": sorted(fields)},
            conn=conn,
        )
    return source


async def delete_source(repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, source_id: str) -> bool:
    """Delete a source (audited ``source.deleted``); ``False`` when there is none."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if not await repos.sources.delete(tenant_id, source_id, conn=conn):
            return False
        await audit.record(
            tenant_id,
            "source.deleted",
            "source",
            source_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={},
            conn=conn,
        )
    return True
