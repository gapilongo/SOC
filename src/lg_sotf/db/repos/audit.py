"""Append-only, hash-chained audit log.

Each tenant has its own chain ordered by ``id``. An entry's ``hash`` is
``sha256`` over the UTF-8 text of::

    jsonb_build_object('tenant_id', ..., 'id', ..., 'ts', <UTC ISO-8601 with
    microseconds and 'Z'>, 'actor_type', ..., 'actor_id', ..., 'action', ...,
    'resource_type', ..., 'resource_id', ..., 'details', ..., 'prev_hash', ...)::text

computed by the SQL function ``audit_entry_hash`` (migration 0001), where
``prev_hash`` is the previous entry's ``hash`` in the same tenant. Appends for
a tenant are serialised with a transaction-scoped advisory lock, so the chain
never forks. The database trigger rejects UPDATE/DELETE/TRUNCATE unless
``app.bypass_rls`` is on (retention only).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Mapping, NamedTuple, Optional

from lg_sotf.db import locks
from lg_sotf.db.pagination import Page, Params, check_limit, decode_cursor_bigint, paginate
from lg_sotf.db.repos._base import Connection, Record, Repository, check_choice, require_aware, to_models

AUDIT_ACTOR_TYPES = ("system", "user", "agent", "api_key")


class AuditEntry(Record):
    tenant_id: str
    id: int
    ts: datetime
    actor_type: str
    actor_id: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: Dict[str, Any]
    prev_hash: Optional[str]
    hash: str


class ChainVerification(NamedTuple):
    ok: bool
    first_bad_id: Optional[int]


class AuditRepo(Repository):
    async def append(
        self,
        tenant_id: str,
        actor_type: str,
        actor_id: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
        *,
        conn: Optional[Connection] = None,
    ) -> AuditEntry:
        """Append an entry to the tenant's chain.

        Pass ``conn`` to write the entry in the same transaction as the change
        it records; that transaction must use READ COMMITTED (the default).
        ``details`` must not contain secrets or raw alert bodies.
        """
        check_choice(actor_type, AUDIT_ACTOR_TYPES, "actor type")
        if not action or not resource_type:
            raise ValueError("action and resource_type are required")
        async with self._tenant(tenant_id, conn) as c:
            await locks.tenant_xact_lock(c, locks.AUDIT_CHAIN, tenant_id)
            row = await c.fetchrow(
                """
                WITH prev AS (
                    SELECT hash FROM audit_log WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1
                ), entry AS (
                    SELECT nextval(pg_get_serial_sequence('audit_log', 'id')) AS id, clock_timestamp() AS ts
                )
                INSERT INTO audit_log (tenant_id, id, ts, actor_type, actor_id, action, resource_type,
                                       resource_id, details, prev_hash, hash)
                SELECT $1, entry.id, entry.ts, $2, $3, $4, $5, $6, $7::jsonb, prev.hash,
                       audit_entry_hash($1, entry.id, entry.ts, $2, $3, $4, $5, $6, $7::jsonb, prev.hash)
                FROM entry LEFT JOIN prev ON true
                RETURNING *
                """,
                tenant_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                dict(details or {}),
            )
        return AuditEntry.model_validate(dict(row))

    async def list(
        self,
        tenant_id: str,
        *,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Page[AuditEntry]:
        """Newest first, keyset-paginated over (ts, id)."""
        check_limit(limit)
        require_aware(since, "since")
        require_aware(until, "until")
        params = Params(tenant_id)
        where = ["tenant_id = $1"]
        for column, value in (
            ("resource_type", resource_type),
            ("resource_id", resource_id),
            ("action", action),
            ("actor_id", actor_id),
        ):
            if value is not None:
                where.append(f"{column} = {params.add(value)}")
        if since is not None:
            where.append(f"ts >= {params.add(since)}")
        if until is not None:
            where.append(f"ts < {params.add(until)}")
        if cursor:
            ts, key = decode_cursor_bigint(cursor)
            where.append(f"(ts, id) < ({params.add(ts)}, {params.add(key)}::bigint)")
        sql = (
            f"SELECT * FROM audit_log WHERE {' AND '.join(where)} "  # noqa: S608
            f"ORDER BY ts DESC, id DESC LIMIT {params.add(limit + 1)}"
        )
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(sql, *params.values)
        return paginate(to_models(AuditEntry, rows), limit, lambda e: (e.ts, e.id))

    async def verify_chain(
        self, tenant_id: str, since: Optional[datetime] = None, *, batch_size: int = 1_000
    ) -> ChainVerification:
        """Recompute every hash and link from ``since`` (or the oldest retained entry).

        The first entry checked is trusted as the anchor for its ``prev_hash``
        because older partitions may have been dropped by retention. Returns
        the id of the first entry whose hash or link does not match.
        """
        require_aware(since, "since")
        prev_hash: Optional[str] = None
        first = True
        async with self.db.tenant_tx(tenant_id, readonly=True) as c:
            cur = c.cursor(
                """
                SELECT id, prev_hash, hash,
                       audit_entry_hash(tenant_id, id, ts, actor_type, actor_id, action, resource_type,
                                        resource_id, details, prev_hash) AS computed
                FROM audit_log
                WHERE tenant_id = $1 AND ($2::timestamptz IS NULL OR ts >= $2)
                ORDER BY id
                """,
                tenant_id,
                since,
                prefetch=batch_size,
            )
            async for row in cur:
                if row["computed"] != row["hash"] or (not first and row["prev_hash"] != prev_hash):
                    return ChainVerification(False, row["id"])
                prev_hash = row["hash"]
                first = False
        return ChainVerification(True, None)
