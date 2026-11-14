"""Audit trail: structured log line plus, for security-relevant events, a hash-chained ``audit_log`` row.

:meth:`AuditLogger.record` writes a change's entry on the change's own
connection (required), so both commit or neither does;
:meth:`AuditLogger.record_event` is the one write without a connection, for
access events and other entries that have no transaction to join
(``docs/adr/0003-data-access-and-audit.md``).

Logging goes through :mod:`lg_sotf.observability.logging` (this module never
configures logging). ``details`` must be small and must not contain secrets
or raw alert bodies; they are redacted before logging as defence in depth.

Dual audit. While a request acts in a customer tenant under an MSSP
organisation's grant (:func:`act_under_grant`, set by authentication on
every request), each entry written to that tenant's chain is recorded
twice: in the customer's chain, its details naming the organisation and the
grant (``delegation``), and in the organisation's chain as
``delegated.<action>`` with the customer, the grant and the customer
entry's id and hash, never its details. With a connection both rows are
written in the change's transaction, so they commit together. No write path
has to remember the second entry.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional
from uuid import UUID

from lg_sotf.db.tenancy import switch_tenant
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact

if TYPE_CHECKING:
    from lg_sotf.db import Connection
    from lg_sotf.db.repos import AuditEntry, Repositories

_log = get_logger("lg_sotf.audit")


@dataclass(frozen=True)
class Actor:
    """Who made a change, as ``audit_log`` records it (``actor_type``, ``actor_id``)."""

    type: str
    id: Optional[str]


@dataclass(frozen=True)
class Delegation:
    """The current request acts in ``tenant_id`` under ``grant_id``, given to ``organisation_id``."""

    tenant_id: str
    organisation_id: str
    grant_id: str
    expires_at: Optional[datetime] = None


_delegation: ContextVar[Optional[Delegation]] = ContextVar("lg_sotf_audit_delegation", default=None)


_session_tag: ContextVar[Optional[str]] = ContextVar("lg_sotf_audit_session_tag", default=None)


def tag_session(auth_method: Optional[str]) -> None:
    """Write ``auth_method`` into the details of every audit entry of the current request (``None``: no tag).

    Authentication calls it on every request; it tags break-glass sessions.
    """
    _session_tag.set(auth_method)


def act_under_grant(delegation: Optional[Delegation]) -> None:
    """Set the grant the current request acts under (``None``: none). Authentication calls it on every request."""
    _delegation.set(delegation)


def acting_under_grant(tenant_id: str) -> bool:
    delegation = _delegation.get()
    return delegation is not None and delegation.tenant_id == tenant_id


def written_under_grant(tenant_id: str, expires_at: Optional[datetime]) -> Dict[str, Any]:
    """``expires_at`` and ``grant_id`` for a row written now in ``tenant_id``.

    Under a grant the row names the grant and expires with it at the latest:
    nothing written under a grant outlives it.
    """
    delegation = _delegation.get()
    if delegation is None or delegation.tenant_id != tenant_id or delegation.expires_at is None:
        return {"expires_at": expires_at, "grant_id": None}
    capped = delegation.expires_at if expires_at is None else min(expires_at, delegation.expires_at)
    return {"expires_at": capped, "grant_id": UUID(delegation.grant_id)}


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
        if _session_tag.get() is not None:
            safe_details["auth_method"] = _session_tag.get()
        delegation = _delegation.get()
        if delegation is not None and delegation.tenant_id != tenant_id:
            delegation = None  # an entry in another chain (the organisation's own, for one)
        if delegation is not None:
            safe_details["delegation"] = {"organisation_id": delegation.organisation_id, "grant_id": delegation.grant_id}
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
            if delegation is not None:
                await self._record_for_organisation(delegation, entry, conn)
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

    async def _record_for_organisation(
        self, delegation: Delegation, entry: AuditEntry, conn: Optional[Connection]
    ) -> None:
        """The organisation's entry for ``entry``, which was written in the customer's chain under its grant."""
        assert self._repos is not None
        if conn is not None:
            await switch_tenant(conn, delegation.organisation_id)
        await self._repos.audit.append(
            delegation.organisation_id,
            entry.actor_type,
            entry.actor_id,
            f"delegated.{entry.action}",
            entry.resource_type,
            entry.resource_id,
            {"tenant_id": entry.tenant_id, "grant_id": delegation.grant_id, "entry_id": entry.id, "entry_hash": entry.hash},
            conn=conn,
        )
        if conn is not None:
            await switch_tenant(conn, entry.tenant_id)
