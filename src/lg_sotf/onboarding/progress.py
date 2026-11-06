"""Audited checklist steps: a ``tenants.onboarding`` mark and its audit entry in one transaction.

When the audit entry cannot be written the mark is not set either. Sending
the sample alerts ingests them first, in the ingestion service's own
transactions; that is idempotent (a repeat finds duplicates), so a request
whose audit write failed can simply be retried.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import Repositories


async def record_step(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    action: str,
    *,
    mark: Optional[str],
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """Set the checklist ``mark`` (an ``ONBOARDING_MARKS`` name; ``None`` sets none) and audit ``action``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if mark is not None:
            await repos.tenants.mark_onboarding(tenant_id, mark, conn=conn)
        await audit.record(
            tenant_id,
            action,
            "tenant",
            tenant_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details=details,
            conn=conn,
        )
