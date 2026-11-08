"""Advisory lock namespaces.

Two-key advisory locks ``(class, key)`` keep application locks from colliding
with each other; each subsystem owns one class number, declared here and
nowhere else (``tests/unit/architecture/test_data_access.py`` enforces it).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lg_sotf.db.pool import Connection

AUDIT_CHAIN = 710_001
PARTITION_MAINTENANCE = 710_002
RETENTION = 710_003
MIGRATIONS = 710_004
SCHEDULER_LEADER = 710_010
# Per-tenant hourly cap on executed response actions (services.response).
ACTION_CAP = 710_020
# Per-tenant escalation grouping: parent lookup and attach/create (services.escalation).
ESCALATION_GROUP = 710_021
# Per-tenant blind-audit sampling: the window overlap check and the run it guards (services.blind_audit).
BLIND_AUDIT_SAMPLING = 710_022

_TENANT_XACT_LOCK_SQL = "SELECT pg_advisory_xact_lock($1, hashtext($2))"


async def tenant_xact_lock(conn: Connection, lock_class: int, key: str) -> None:
    """Take the transaction-scoped advisory lock ``(lock_class, hashtext(key))`` on ``conn``.

    ``key`` is usually the tenant id. The lock is released when the
    transaction ends, so ``conn`` must be inside one.
    """
    await conn.execute(_TENANT_XACT_LOCK_SQL, lock_class, key)
