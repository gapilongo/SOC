"""The SELECT-only database role shadow runs connect as (AI-E1.5c).

A shadow run (:mod:`lg_sotf.security.shadow`) gets every database connection
from a pool of its own, logged in as ``database.shadow_url``: a role with
``SELECT`` on the tables a run reads and nothing else (``lg-sotf migrate``
grants it, :func:`lg_sotf.db.migrate.grant_shadow_privileges`), whose
sessions are read only (``default_transaction_read_only``). The database,
not the statement guard of :mod:`lg_sotf.db.shadow_connection`, is then
what stops a shadow run from writing: a statement that slips past the guard
and leaves the read-only transaction still has no privilege to write.

The role writes nothing, not even ``shadow_effects`` or ``shadow_verdicts``:
those rows are written by the runtime role after the run has left shadow
mode, so a statement that escaped the guard has no table to write to.

Without ``database.shadow_url`` a shadow run refuses to start, and a shadow
transaction never falls back to the runtime pool.
"""

from __future__ import annotations

from typing import Optional, Sequence, cast

from lg_sotf.settings import DatabaseSettings, Settings

DEFAULT_SHADOW_ROLE = "lgsotf_shadow"

# What makes a role unfit to be the shadow role: anything that can write or bypass isolation.
# ``{role}`` is the role name expression: a bind parameter, or ``current_user`` on the role's own session.
UNSAFE_ROLE_SQL = """
SELECT r.rolsuper, r.rolbypassrls,
       pg_has_role(r.oid, (SELECT relowner FROM pg_class WHERE oid = 'public.tenants'::regclass), 'MEMBER'),
       ARRAY(
           SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND (
               (c.relkind IN ('r', 'p', 'v', 'm', 'f')
                AND has_table_privilege(r.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE'))
               OR (c.relkind = 'S' AND has_sequence_privilege(r.oid, c.oid, 'USAGE, UPDATE')))
           UNION ALL
           SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.prosecdef AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
           ORDER BY 1
       )
FROM pg_roles r WHERE r.rolname = {role}
"""


def unsafe_role_reasons(row: Optional[tuple[object, ...]], role: str) -> list[str]:
    """Why the role described by a :data:`UNSAFE_ROLE_SQL` row cannot be the shadow role (empty: it can)."""
    if row is None:
        return [f"database role {role!r} does not exist"]
    superuser, bypassrls, owner_member, writable = row
    flags = ((superuser, "is a superuser"), (bypassrls, "has BYPASSRLS"), (owner_member, "is a member of the schema owner"))
    reasons = [text for flag, text in flags if flag]
    names = [str(name) for name in cast(Sequence[object], writable or ())]
    if names:
        reasons.append("may write to " + ", ".join(names[:10]))
    return reasons


def shadow_dsn(database: DatabaseSettings) -> Optional[str]:
    """``database.shadow_url``, or ``None`` when it is unset or empty."""
    url = database.shadow_url
    value = url.get_secret_value().strip() if url is not None else ""
    return value or None


def shadow_role_configured(settings: Settings) -> bool:
    """True when shadow runs can start: ``database.shadow_url`` names the SELECT-only shadow role's login."""
    return shadow_dsn(settings.database) is not None


__all__ = [
    "DEFAULT_SHADOW_ROLE",
    "UNSAFE_ROLE_SQL",
    "shadow_dsn",
    "shadow_role_configured",
    "unsafe_role_reasons",
]
