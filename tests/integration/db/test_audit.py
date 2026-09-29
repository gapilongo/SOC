"""Hash-chained audit log: linking, verification, tamper detection and immutability."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from lg_sotf.db.errors import InvalidCursor
from lg_sotf.db.pagination import encode_cursor
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, TENANT_B

pytestmark = pytest.mark.asyncio


async def _append(repos: Repositories, tenant_id: str, n: int) -> list:
    return [
        await repos.audit.append(tenant_id, "user", "u1", f"action.{i}", "alert", f"a{i}", {"i": i, "note": "x"})
        for i in range(n)
    ]


async def test_entries_are_chained_per_tenant(repos: Repositories) -> None:
    a = await _append(repos, TENANT_A, 3)
    b = await _append(repos, TENANT_B, 2)
    assert a[0].prev_hash is None and b[0].prev_hash is None
    assert a[1].prev_hash == a[0].hash and a[2].prev_hash == a[1].hash
    assert b[1].prev_hash == b[0].hash
    assert len({e.hash for e in a + b}) == 5
    assert await repos.audit.verify_chain(TENANT_A) == (True, None)
    assert await repos.audit.verify_chain(TENANT_B) == (True, None)
    assert await repos.audit.verify_chain("tenant-empty") == (True, None)


async def test_hash_matches_documented_canonical_form(repos: Repositories) -> None:
    entry = (await _append(repos, TENANT_A, 1))[0]
    canonical = {
        "tenant_id": entry.tenant_id,
        "id": entry.id,
        "ts": entry.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "actor_type": entry.actor_type,
        "actor_id": entry.actor_id,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "details": entry.details,
        "prev_hash": entry.prev_hash,
    }

    def jsonb_text(value: object) -> str:
        if isinstance(value, dict):
            keys = sorted(value, key=lambda k: (len(k.encode()), k.encode()))
            return "{" + ", ".join(f"{json.dumps(k)}: {jsonb_text(value[k])}" for k in keys) + "}"
        return json.dumps(value)

    assert hashlib.sha256(jsonb_text(canonical).encode()).hexdigest() == entry.hash


async def test_concurrent_appends_keep_a_single_chain(repos: Repositories) -> None:
    await asyncio.gather(
        *(repos.audit.append(TENANT_A, "agent", "worker", "run.step", "run", str(i)) for i in range(25))
    )
    assert await repos.audit.verify_chain(TENANT_A) == (True, None)
    async with repos.db.tenant_tx(TENANT_A) as conn:
        rows = await conn.fetch("SELECT prev_hash FROM audit_log WHERE tenant_id = $1", TENANT_A)
    prevs = [r["prev_hash"] for r in rows]
    assert prevs.count(None) == 1 and len(set(prevs)) == 25


async def test_update_delete_truncate_blocked_without_bypass(db: Database, repos: Repositories) -> None:
    entry = (await _append(repos, TENANT_A, 1))[0]
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute("UPDATE audit_log SET action = 'forged' WHERE id = $1", entry.id)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute("DELETE FROM audit_log WHERE id = $1", entry.id)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute("TRUNCATE audit_log")
    async with db.system_tx() as conn:
        partition = await conn.fetchval("SELECT tableoid::regclass::text FROM audit_log WHERE id = $1", entry.id)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute(f"TRUNCATE {partition}")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await conn.execute(f"UPDATE {partition} SET action = 'forged'")  # noqa: S608
    assert await repos.audit.verify_chain(TENANT_A) == (True, None)


async def test_tampered_details_detected(db: Database, repos: Repositories) -> None:
    entries = await _append(repos, TENANT_A, 5)
    async with db.system_tx() as conn:
        await conn.execute(
            'UPDATE audit_log SET details = details || \'{"note": "edited"}\'::jsonb WHERE id = $1',
            entries[2].id,
        )
    assert await repos.audit.verify_chain(TENANT_A) == (False, entries[2].id)
    assert await repos.audit.verify_chain(TENANT_B) == (True, None)


async def test_rehashed_row_breaks_the_next_link(db: Database, repos: Repositories) -> None:
    entries = await _append(repos, TENANT_A, 4)
    async with db.system_tx() as conn:
        await conn.execute(
            """
            UPDATE audit_log SET action = 'forged',
                hash = audit_entry_hash(tenant_id, id, ts, actor_type, actor_id, 'forged', resource_type,
                                        resource_id, details, prev_hash)
            WHERE id = $1
            """,
            entries[1].id,
        )
    assert await repos.audit.verify_chain(TENANT_A) == (False, entries[2].id)


async def test_deleted_row_detected(db: Database, repos: Repositories) -> None:
    entries = await _append(repos, TENANT_A, 4)
    async with db.system_tx() as conn:
        await conn.execute("DELETE FROM audit_log WHERE id = $1", entries[1].id)
    assert await repos.audit.verify_chain(TENANT_A) == (False, entries[2].id)


async def test_verify_since_anchors_on_first_entry(db: Database, repos: Repositories) -> None:
    entries = await _append(repos, TENANT_A, 4)
    async with db.system_tx() as conn:
        await conn.execute("DELETE FROM audit_log WHERE id = $1", entries[0].id)
    assert (await repos.audit.verify_chain(TENANT_A)).ok
    assert await repos.audit.verify_chain(TENANT_A, since=entries[2].ts) == (True, None)


async def test_list_and_append_in_callers_transaction(db: Database, repos: Repositories) -> None:
    for i in range(5):
        await repos.audit.append(TENANT_A, "user", "u1", "escalation.claimed", "escalation", f"e{i % 2}")
    with pytest.raises(RuntimeError):
        async with db.tenant_tx(TENANT_A) as conn:
            await repos.audit.append(TENANT_A, "system", None, "rolled.back", "run", "r", conn=conn)
            raise RuntimeError("abort")
    page = await repos.audit.list(TENANT_A, limit=3)
    assert len(page.items) == 3 and page.next_cursor
    rest = await repos.audit.list(TENANT_A, limit=3, cursor=page.next_cursor)
    assert len(rest.items) == 2 and rest.next_cursor is None
    assert [e.id for e in page.items + rest.items] == sorted((e.id for e in page.items + rest.items), reverse=True)
    assert len((await repos.audit.list(TENANT_A, resource_id="e1")).items) == 2
    assert len((await repos.audit.list(TENANT_A, since=datetime.now(UTC) + timedelta(days=1))).items) == 0
    assert (await repos.audit.list(TENANT_A, action="rolled.back")).items == []
    assert await repos.audit.verify_chain(TENANT_A) == (True, None)
    with pytest.raises(ValueError):
        await repos.audit.append(TENANT_A, "robot", None, "x", "y")
    for key in (10**30, "12", -(2**63) - 1):
        with pytest.raises(InvalidCursor):
            await repos.audit.list(TENANT_A, cursor=encode_cursor(datetime.now(UTC), key))
