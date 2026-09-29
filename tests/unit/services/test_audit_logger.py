"""AuditLogger persists through repos.audit, redacts details and never reconfigures logging."""

from __future__ import annotations

from types import SimpleNamespace

import structlog

from lg_sotf.audit import AuditLogger
from tests.unit.services.fakes import FakeAudit


async def test_record_persists_redacted_details() -> None:
    audit = FakeAudit()
    before = structlog.get_config()
    logger = AuditLogger(SimpleNamespace(audit=audit))  # type: ignore[arg-type]
    await logger.record("t1", "escalation.created", "escalation", "e1", details={"password": "hunter2", "level": "L1"})
    assert structlog.get_config() == before
    (tenant, actor_type, action, resource_type, resource_id, details), = audit.entries
    assert (tenant, action, resource_id) == ("t1", "escalation.created", "e1")
    assert details["level"] == "L1" and details["password"] != "hunter2"


async def test_record_without_repositories_only_logs() -> None:
    assert await AuditLogger().record("t1", "x.y", "thing") is None
