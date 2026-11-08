"""Read-only catalog queries behind ``lg-sotf verify-invariants`` (:mod:`lg_sotf.invariants`).

Every function reads the system catalogs, or tenant tables inside the
caller's transaction, as the connected role; none of them writes. They
answer for whoever is connected, so ``verify-invariants`` connects with the
runtime URL (``database.url``) the API and the workers use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from lg_sotf.db.checkpointer import CHECKPOINT_RLS_TABLES
from lg_sotf.db.types import Connection

__all__ = [
    "AUDIT_TRIGGERS",
    "RoleAttributes",
    "TableSecurity",
    "audit_triggers",
    "bypass_honoured",
    "current_role_attributes",
    "privileges_on",
    "tables_with_visible_rows",
    "tenant_table_security",
]

# Row-level triggers that refuse UPDATE/DELETE and the statement trigger that refuses TRUNCATE (0001).
AUDIT_TRIGGERS: Sequence[str] = ("audit_log_immutable", "audit_log_no_truncate")

# Every table with a tenant_id column (partitions included), plus tenants and the LangGraph checkpoint tables.
_TENANT_TABLES_SQL = """
SELECT c.relname AS name, c.relispartition AS partition, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced,
       EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid) AS policy,
       has_table_privilege(c.oid, 'SELECT') AS readable,
       -- reltuples is -1 until the table (or any partition) is first analyzed: NULL means unknown.
       (CASE WHEN c.relkind = 'p'
             THEN (SELECT CASE WHEN bool_or(k.reltuples < 0) THEN NULL ELSE COALESCE(sum(k.reltuples), 0) END
                   FROM pg_catalog.pg_inherits i
                   JOIN pg_catalog.pg_class k ON k.oid = i.inhrelid WHERE i.inhparent = c.oid)
             WHEN c.reltuples < 0 THEN NULL
             ELSE c.reltuples END)::bigint AS estimated_rows,
       (CASE WHEN c.relkind = 'p'
             THEN (SELECT COALESCE(sum(pg_table_size(i.inhrelid)), 0) FROM pg_catalog.pg_inherits i
                   WHERE i.inhparent = c.oid)
             ELSE pg_table_size(c.oid) END)::bigint AS size_bytes
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  AND (c.relname = ANY($1::text[])
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                  WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
ORDER BY c.relname
"""

_ROLE_SQL = """
SELECT current_user AS name, r.rolsuper AS superuser, r.rolbypassrls AS bypassrls,
       pg_has_role(current_user, t.relowner, 'MEMBER') AS owner_member
FROM pg_catalog.pg_roles r, pg_catalog.pg_class t
WHERE r.rolname = current_user AND t.oid = 'public.tenants'::regclass
"""

_AUDIT_TRIGGERS_SQL = """
SELECT tgname AS name, tgenabled <> 'D' AS enabled
FROM pg_catalog.pg_trigger
WHERE tgrelid = 'public.audit_log'::regclass AND NOT tgisinternal AND tgname = ANY($1::text[])
"""


@dataclass(frozen=True)
class TableSecurity:
    """Row-level security state of one tenant-owned table, as the catalog records it."""

    name: str
    partition: bool
    rls: bool
    forced: bool
    policy: bool
    readable: bool
    estimated_rows: Optional[int] = None  # None: never analyzed, no statistics
    size_bytes: int = 0

    @property
    def isolated(self) -> bool:
        return self.rls and self.forced and self.policy


@dataclass(frozen=True)
class RoleAttributes:
    """The connected role and whether it could see past tenant isolation."""

    name: str
    superuser: bool
    bypassrls: bool
    owner_member: bool

    @property
    def can_bypass_rls(self) -> bool:
        return self.superuser or self.bypassrls or self.owner_member


async def tenant_table_security(conn: Connection) -> List[TableSecurity]:
    rows = await conn.fetch(_TENANT_TABLES_SQL, ["tenants", *CHECKPOINT_RLS_TABLES])
    return [TableSecurity(**dict(r)) for r in rows]


async def current_role_attributes(conn: Connection) -> RoleAttributes:
    row = await conn.fetchrow(_ROLE_SQL)
    if row is None:  # pragma: no cover - current_user always has a pg_roles row
        raise LookupError("the connected role is not in pg_roles")
    return RoleAttributes(**dict(row))


async def privileges_on(conn: Connection, table: str, privileges: Sequence[str]) -> Dict[str, bool]:
    """``{privilege: held}`` for the connected role on ``public.<table>``."""
    held: Dict[str, bool] = {}
    for privilege in privileges:
        held[privilege] = bool(await conn.fetchval("SELECT has_table_privilege($1, $2)", f"public.{table}", privilege))
    return held


async def audit_triggers(conn: Connection) -> Dict[str, bool]:
    """``{trigger: enabled}`` for the audit-log mutation triggers that exist."""
    rows = await conn.fetch(_AUDIT_TRIGGERS_SQL, list(AUDIT_TRIGGERS))
    return {r["name"]: bool(r["enabled"]) for r in rows}


async def bypass_honoured(conn: Connection) -> bool:
    """Set ``app.bypass_rls`` for the caller's transaction and return whether the RLS policies honour it.

    Only members of the schema owner role are honoured (``lgsotf_rls_bypass()``, 0001).
    """
    await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
    return bool(await conn.fetchval("SELECT lgsotf_rls_bypass()"))


async def tables_with_visible_rows(conn: Connection, tables: Sequence[str]) -> List[str]:
    """The ``tables`` in which the caller's transaction sees at least one row.

    Run inside a tenant transaction for a tenant that owns no data: any row
    seen belongs to another tenant. When every row is hidden PostgreSQL reads
    the whole table, so callers pass small tables only.
    """
    seen: List[str] = []
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        if await conn.fetchval(f"SELECT EXISTS (SELECT 1 FROM public.{quoted})"):  # noqa: S608 - catalog names
            seen.append(table)
    return seen
