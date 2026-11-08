"""The connection a shadow run's transactions get: read only, and no statement that escapes it.

:class:`~lg_sotf.db.pool.Database` opens every transaction of a shadow run
read only. PostgreSQL still accepts a few statements there that reach past
the transaction: ``COMMIT`` (the next statement then runs in autocommit, read
write), ``SET TRANSACTION READ WRITE`` before the first query,
``NOTIFY``/``pg_notify`` (delivered to listeners), session-level settings and
advisory locks that outlive the transaction. :class:`ShadowConnection`
refuses them (``ShadowEgressRefused``) before they are sent. Only the
driver methods named here are reachable: the query methods (checked), the
transaction and state probes (:data:`PASSTHROUGH`); anything else, ``copy_*``,
listeners and codecs included, is refused.

The check is a pattern match, not an SQL parser: a statement written to slip
past it still runs in the read-only transaction. Anything it is unsure of
(a ``set_config`` whose third argument is not a literal ``true``) is refused.
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
# Functions with an effect beyond the transaction, anywhere in a statement (quoted names too).
_REFUSED_CALL = re.compile(r'(?<![\w$])"?(pg_notify|pg_(try_)?advisory_lock(_shared)?|dblink\w*)"?\s*\(', re.IGNORECASE)
# set_config is session-wide unless its third argument is true: only the literal true passes.
_SET_CONFIG = re.compile(r'(?<![\w$])"?set_config"?\s*\(([^)]*)\)?', re.IGNORECASE)
_LOCAL_ONLY = re.compile(r",\s*true\s*$", re.IGNORECASE)
PASSTHROUGH = frozenset({"transaction", "is_in_transaction", "is_closed", "get_server_version"})


def check_shadow_statement(query: str) -> None:
    """Refuse (in a shadow run) a statement that would reach past its read-only transaction."""
    text = _COMMENTS.sub(" ", query)
    if (
        _REFUSED_CALL.search(text)
        or any(not _LOCAL_ONLY.search(args) for args in _SET_CONFIG.findall(text))
        or any(_REFUSED_STATEMENT.match(part) for part in text.split(";"))
    ):
        refuse_in_shadow("database", "SQL " + " ".join(text.split())[:80])


class ShadowConnection:
    """A driver connection whose statements pass :func:`check_shadow_statement` first."""

    def __init__(self, conn: Connection) -> None:
        self._conn: Any = conn

    def __getattr__(self, name: str) -> Any:
        if name not in PASSTHROUGH:
            refuse_in_shadow("database", f"connection.{name}")
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

    def fetchmany(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.fetchmany(query, *args, **kwargs)

    def prepare(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.prepare(query, *args, **kwargs)

    def cursor(self, query: str, *args: Any, **kwargs: Any) -> Any:
        check_shadow_statement(query)
        return self._conn.cursor(query, *args, **kwargs)


def shadow_connection(conn: Connection) -> Connection:
    return cast(Connection, ShadowConnection(conn))
