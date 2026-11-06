"""Audit trail: structured log line plus, for security-relevant events, a hash-chained ``audit_log`` row.

:meth:`AuditLogger.record` writes a change's entry on the change's own
connection (required), so both commit or neither does;
:meth:`AuditLogger.record_event` is the one write without a connection, for
access events and other entries that have no transaction to join
(``docs/adr/0003-data-access-and-audit.md``).

Logging goes through :mod:`lg_sotf.observability.logging` (this module never
configures logging). ``details`` must be small and must not contain secrets
or raw alert bodies; they are redacted before logging as defence in depth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Optional

from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact

if TYPE_CHECKING:
    from lg_sotf.db.repos import AuditEntry, Repositories
    from lg_sotf.db.repos._base import Connection

_log = get_logger("lg_sotf.audit")


@dataclass(frozen=True)
class Actor:
    """Who made a change, as ``audit_log`` records it (``actor_type``, ``actor_id``)."""

    type: str
    id: Optional[str]


class AuditLogger:
    def __init__(self, repos: Optional[Repositories] = None) -> None:
        self._repos = repos

    async def record(
        self,
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        *,
        actor_type: str = "system",
        actor_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
        conn: Connection,
    ) -> Optional[AuditEntry]:
        """Persist the audit entry of a change in the change's own transaction (``conn``), and log it.

        Persistence failures propagate: an action whose audit entry cannot
        be written must not be reported as done. Written on ``conn``, the
        entry commits or rolls back with the change it records (ADR-0003).
        An entry with no transaction to join uses :meth:`record_event`.
        """
        if conn is None:
            raise TypeError("AuditLogger.record needs the change's connection; use record_event for an event")
        return await self._write(tenant_id, action, resource_type, resource_id, actor_type, actor_id, details, conn)

    async def record_event(
        self,
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        *,
        actor_type: str = "system",
        actor_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Optional[AuditEntry]:
        """Persist and log an event that has no database transaction to join.

        For access events (sign-in, sign-out, exports, cross-tenant reads),
        refused or failed attempts, and changes outside the database (Redis,
        external systems) or spread over many transactions (streaming
        erasure). The entry is written in a transaction of its own, before
        the caller reports the action as done; failures propagate as with
        :meth:`record`. A database change records with :meth:`record`.
        """
        return await self._write(tenant_id, action, resource_type, resource_id, actor_type, actor_id, details, None)

    async def _write(
        self,
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str],
        actor_type: str,
        actor_id: Optional[str],
        details: Optional[Mapping[str, Any]],
        conn: Optional[Connection],
    ) -> Optional[AuditEntry]:
        safe_details, _ = redact(dict(details or {}))
        entry = None
        if self._repos is not None:
            entry = await self._repos.audit.append(
                tenant_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                safe_details,
                conn=conn,
            )
        _log.info(
            "audit",
            audit_action=action,
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            details=safe_details,
            persisted=entry is not None,
        )
        return entry
