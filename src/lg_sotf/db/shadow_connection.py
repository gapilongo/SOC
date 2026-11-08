"""The connection a shadow run's transactions get: read only, and no statement that escapes it.

:class:`~lg_sotf.db.pool.Database` opens every transaction of a shadow run
read only. PostgreSQL still accepts a few statements there that reach past
the transaction: ``COMMIT`` (the next statement then runs in autocommit, read
write), ``SET TRANSACTION READ WRITE`` before the first query,
``NOTIFY``/``pg_notify`` (delivered to listeners), session-level settings and
advisory locks that outlive the transaction. :class:`ShadowConnection`
refuses them (``ShadowEgressRefused``) before they are sent; every other
call goes to the driver's connection unchanged.
"""

from __future__ import annotations

import re
from typing import Any, cast

from lg_sotf.db.types import Connection
from lg_sotf.security.shadow import refuse_in_shadow

_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
# The first keyword of a statement a shadow run may not send (SET LOCAL stays inside the transaction).
_REFUSED_STATEMENT = re.compile(
    r"^\s*(COMMIT|ROLLBACK|ABORT|END|BEGIN|START|SAVEPOINT|RELEASE|PREPARE|SET(?!\s+LOCAL\b)|RESET|DISCARD|"
    r"NOTIFY|LISTEN|UNLISTEN|LOCK|COPY|DO|CALL|VACUUM|ANALYZE|CLUSTER|REINDEX|CHECKPOINT|LOAD)\b",
    re.IGNORECASE,
)
# Functions with an effect beyond the transaction, anywhere in a statement.
_REFUSED_CALL = re.compile(
    r"\bpg_notify\s*\(|\bpg_(try_)?advisory_lock(_shared)?\s*\(|\bdblink|\bset_config\s*\([^)]*,\s*false\s*\)",
    re.IGNORECASE,
)


def check_shadow_statement(query: str) -> None:
    """Refuse (in a shadow run) a statement that would reach past its read-only transaction."""
    text = _COMMENTS.sub(" ", query)
    if _REFUSED_CALL.search(text) or any(_REFUSED_STATEMENT.match(part) for part in text.split(";")):
        refuse_in_shadow("database", "SQL " + " ".join(text.split())[:80])


class ShadowConnection:
    """A driver connection whose statements pass :func:`check_shadow_statement` first."""

    def __init__(self, conn: Connection) -> None:
        self._conn: Any = conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def execute(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.execute(query, *args, **kwargs)

    def executemany(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.executemany(query, *args, **kwargs)

    def fetch(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.fetch(query, *args, **kwargs)

    def fetchrow(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.fetchrow(query, *args, **kwargs)

    def fetchval(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.fetchval(query, *args, **kwargs)

    def prepare(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.prepare(query, *args, **kwargs)

    def cursor(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.cursor(query, *args, **kwargs)


def shadow_connection(conn: Connection) -> Connection:
    return cast(Connection, ShadowConnection(conn))
