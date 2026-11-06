"""Advisory lock registry: class numbers and the one per-tenant transaction lock helper."""

from __future__ import annotations

from typing import Any, List, Tuple

import pytest

from lg_sotf.db import locks

pytestmark = pytest.mark.unit


class RecordingConn:
    def __init__(self) -> None:
        self.calls: List[Tuple[Any, ...]] = []

    async def execute(self, *args: Any) -> str:
        self.calls.append(args)
        return "SELECT 1"


def test_class_numbers_are_unchanged() -> None:
    # Live transactions and pg_locks dashboards see these numbers: they never change.
    assert (locks.AUDIT_CHAIN, locks.PARTITION_MAINTENANCE, locks.RETENTION, locks.MIGRATIONS) == (
        710_001, 710_002, 710_003, 710_004,
    )
    assert locks.SCHEDULER_LEADER == 710_010
    assert (locks.ACTION_CAP, locks.ESCALATION_GROUP) == (710_020, 710_021)


@pytest.mark.parametrize("lock_class", [locks.AUDIT_CHAIN, locks.ACTION_CAP, locks.ESCALATION_GROUP])
async def test_tenant_xact_lock_runs_the_same_sql(lock_class: int) -> None:
    conn = RecordingConn()
    await locks.tenant_xact_lock(conn, lock_class, "tenant-a")
    assert conn.calls == [("SELECT pg_advisory_xact_lock($1, hashtext($2))", lock_class, "tenant-a")]
