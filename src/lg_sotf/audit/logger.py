"""Audit trail: structured log line plus, for security-relevant events, a hash-chained ``audit_log`` row.

Logging goes through :mod:`lg_sotf.observability.logging` (this module never
configures logging). ``details`` must be small and must not contain secrets
or raw alert bodies; they are redacted before logging as defence in depth.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Optional

from lg_sotf.observability.logging import get_logger
from lg_sotf.security.redaction import redact

if TYPE_CHECKING:
    from lg_sotf.db.repos import AuditEntry, Repositories
    from lg_sotf.db.repos._base import Connection

_log = get_logger("lg_sotf.audit")


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
        conn: Optional[Connection] = None,
    ) -> Optional[AuditEntry]:
        """Persist an audit entry (when repositories are configured) and log it.

        Persistence failures propagate: an action whose audit entry cannot
        be written must not be reported as done.
        """
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

    def log_security_event(self, event_type: str, severity: str, description: str, **fields: Any) -> None:
        safe, _ = redact(fields)
        _log.warning("security_event", event_type=event_type, severity=severity, description=description, **safe)

    def log_application_start(self, config_path: Optional[str] = None, version: Optional[str] = None) -> None:
        _log.info("application_started", config_path=config_path, version=version)

    def log_application_shutdown(self) -> None:
        _log.info("application_shutdown")
