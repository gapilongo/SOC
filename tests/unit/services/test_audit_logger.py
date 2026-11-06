"""AuditLogger persists through repos.audit, redacts details and never reconfigures logging."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, List

import pytest
import structlog

from lg_sotf.audit import AuditLogger
from tests.unit.services.fakes import FakeAudit

CONN: Any = object()  # stands in for the caller's open transaction


async def test_record_persists_redacted_details() -> None:
    audit = FakeAudit()
    before = structlog.get_config()
    logger = AuditLogger(SimpleNamespace(audit=audit))  # type: ignore[arg-type]
    await logger.record(
        "t1", "escalation.created", "escalation", "e1", details={"password": "hunter2", "level": "L1"}, conn=CONN
    )
    assert structlog.get_config() == before
    (tenant, actor_type, action, resource_type, resource_id, details), = audit.entries
    assert (tenant, action, resource_id) == ("t1", "escalation.created", "e1")
    assert details["level"] == "L1" and details["password"] != "hunter2"


async def test_record_without_repositories_only_logs() -> None:
    assert await AuditLogger().record("t1", "x.y", "thing", conn=CONN) is None
    assert await AuditLogger().record_event("t1", "x.y", "thing") is None


async def test_record_requires_the_changes_connection() -> None:
    """``record`` is for changes: without their transaction it refuses; ``record_event`` is the way for events."""
    audit = FakeAudit()
    with pytest.raises(TypeError):
        await AuditLogger(SimpleNamespace(audit=audit)).record("t1", "x.y", "thing", conn=None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        await AuditLogger(SimpleNamespace(audit=audit)).record("t1", "x.y", "thing")  # type: ignore[call-arg]
    assert audit.entries == []


class _ConnAudit:
    def __init__(self) -> None:
        self.conns: List[Any] = []
        self.details: List[Any] = []

    async def append(self, *args: Any, conn: Any = None, **kwargs: Any) -> None:
        self.conns.append(conn)
        self.details.append(args[6])


async def test_record_writes_on_the_callers_connection_and_record_event_on_its_own() -> None:
    audit = _ConnAudit()
    logger = AuditLogger(SimpleNamespace(audit=audit))  # type: ignore[arg-type]
    conn = object()
    await logger.record("t1", "source.created", "source", "s1", conn=conn)  # type: ignore[arg-type]
    await logger.record_event("t1", "auth.login_failed", "user", "u1", details={"password": "hunter2"})
    assert audit.conns == [conn, None]
    assert audit.details[1]["password"] != "hunter2"


async def test_record_event_failure_propagates() -> None:
    class Failing:
        async def append(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("audit_log unavailable")

    logger = AuditLogger(SimpleNamespace(audit=Failing()))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError):
        await logger.record_event("t1", "auth.login", "user", "u1")
