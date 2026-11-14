"""asyncpg connection pool with tenant-scoped transactions.

Every tenant query runs inside :meth:`Database.tenant_tx`, which sets the
transaction-local ``app.tenant_id`` GUC that the row-level-security policies
check. :meth:`Database.system_tx` sets ``app.bypass_rls`` instead and is
reserved for the scheduler, retention and migrations; the policies honour it
only for members of the schema owner role (``lgsotf_rls_bypass()``), so the
API/worker runtime role cannot bypass isolation by setting the GUC.

In a shadow run (:mod:`lg_sotf.security.shadow`) every transaction and bare
connection comes from a second pool, logged in as the SELECT-only shadow
role (``database.shadow_url``, :mod:`lg_sotf.db.shadow_role`), and is read
only, whatever the caller asked for: a write that no egress boundary
diverted fails for lack of privilege instead of committing. Without that
pool (:meth:`Database.open_shadow`) a shadow transaction is refused; it never
falls back to the runtime pool. Its connections also refuse the statements
that would reach past a read-only transaction
(:mod:`lg_sotf.db.shadow_connection`), as defence in depth.

:meth:`Database.run_tenant_tx` and :func:`retry_stale_statement` run a
transaction again, once, when a migration made one of the pool's cached
prepared statements stale (a rolling upgrade migrates while the previous
release is still running). The second attempt opens a new transaction, so in
a shadow run it is read only too.
"""

from __future__ import annotations

import asyncio
import enum
import json
import re
import ssl
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import date, datetime
from datetime import time as dt_time
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping, Optional, TypeAlias, TypeVar, Union

import asyncpg
import structlog

from lg_sotf.db.errors import DatabaseError, DatabaseUnavailable, PoolExhausted, ShadowRoleRequired, SystemScopeDenied
from lg_sotf.db.shadow_connection import shadow_connection
from lg_sotf.db.shadow_role import UNSAFE_ROLE_SQL, shadow_dsn, unsafe_role_reasons
from lg_sotf.db.tenancy import validate_tenant_id
from lg_sotf.db.types import Connection
from lg_sotf.db.urls import redact_url, to_libpq_url
from lg_sotf.observability.metrics import record_stale_statement_retry
from lg_sotf.security.shadow import REFUSE, egress, in_shadow, refuse_in_shadow
from lg_sotf.settings import DatabaseSettings, Settings

log = structlog.get_logger(__name__)

SSLArg: TypeAlias = Union[bool, str, ssl.SSLContext, None]
T = TypeVar("T")

# Raised by asyncpg when a schema change made a statement it had prepared stale: the result type of
# a cached statement changed (ALTER TABLE) or a cached type did. asyncpg clears the statement and type
# caches of every connection in the pool before raising, but inside a transaction it cannot run the
# statement again itself: Postgres has aborted (and on exit rolled back) the whole transaction.
STALE_STATEMENT_ERRORS = (asyncpg.InvalidCachedStatementError, asyncpg.OutdatedSchemaCacheError)


async def retry_stale_statement(attempt: Callable[[], Awaitable[T]]) -> T:
    """Await ``attempt()``; on a stale cached statement, await it once more.

    ``attempt`` must be one whole transaction that only talks to the
    database, so that running it again repeats nothing outside the database.
    The second attempt prepares its statements afresh. A second stale
    statement (another migration in between) is raised.
    """
    try:
        return await attempt()
    except STALE_STATEMENT_ERRORS as exc:
        log.warning("db.stale_statement_retry", error=type(exc).__name__)
        record_stale_statement_retry()
    return await attempt()


# A ``\u0000`` escape that is not itself an escaped backslash followed by "u0000".
_NUL_ESCAPE = re.compile(r"(?<!\\)((?:\\\\)*)\\u0000")
REPLACEMENT_CHAR = "�"


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, enum.Enum):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def json_dumps(value: Any) -> str:
    """Serialise for json/jsonb parameters.

    PostgreSQL cannot store NUL characters or lone UTF-16 surrogates. Both
    occur in attacker-influenced alert content, and one of them would fail a
    whole batch insert, so they are replaced with U+FFFD / ``?`` here, the one
    place every JSON parameter passes through.
    """
    text = json.dumps(value, default=_json_default, separators=(",", ":"), ensure_ascii=False)
    if "\\u0000" in text:
        text = _NUL_ESCAPE.sub(r"\1\\ufffd", text)
    if not text.isascii():
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = text.encode("utf-8", "replace").decode("utf-8")
    return text


def sanitize_text(value: str) -> str:
    """Make a string storable in a TEXT column (see :func:`json_dumps`)."""
    if "\x00" in value:
        value = value.replace("\x00", REPLACEMENT_CHAR)
    if not value.isascii():
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            value = value.encode("utf-8", "replace").decode("utf-8")
    return value


async def _init_connection(conn: Connection) -> None:
    for typename in ("json", "jsonb"):
        await conn.set_type_codec(typename, encoder=json_dumps, decoder=json.loads, schema="pg_catalog", format="text")


def build_ssl_arg(ssl_mode: Optional[str], ssl_root_cert: Optional[str]) -> SSLArg:
    """Translate libpq-style ``sslmode`` settings into asyncpg's ``ssl`` argument.

    ``None`` means "not configured": asyncpg then honours ``sslmode`` in the DSN.
    As in libpq, ``require`` with a root certificate verifies the chain.
    """
    if ssl_mode is None:
        return None
    if ssl_mode == "disable":
        return False
    if ssl_mode == "prefer":
        return "prefer"
    if ssl_mode == "require" and not ssl_root_cert:
        return "require"
    ctx = ssl.create_default_context(cafile=ssl_root_cert) if ssl_root_cert else ssl.create_default_context()
    if ssl_mode in ("require", "verify-ca"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif ssl_mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        raise ValueError(f"unsupported ssl_mode: {ssl_mode!r}")
    return ctx


@dataclass(frozen=True)
class PoolStats:
    size: int
    idle: int
    min_size: int
    max_size: int


class Database:
    """Owns the asyncpg pool for one process.

    Create with :meth:`connect` (or ``Database(...)`` then :meth:`open`) and
    call :meth:`close` on shutdown.
    """

    def __init__(
        self,
        settings: DatabaseSettings,
        *,
        dsn: Optional[str] = None,
        application_name: str = "lg-sotf",
        acquire_timeout_s: float = 10.0,
        min_size: Optional[int] = None,
        max_size: Optional[int] = None,
        server_settings: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._settings = settings
        self._dsn = to_libpq_url(dsn or self._settings.url.get_secret_value())
        self._application_name = application_name
        self._acquire_timeout_s = acquire_timeout_s
        self._min_size = self._settings.pool_min if min_size is None else min_size
        self._max_size = self._settings.pool_max if max_size is None else max_size
        if self._min_size < 0 or self._max_size < 1 or self._min_size > self._max_size:
            raise ValueError("invalid pool size: require 0 <= min_size <= max_size and max_size >= 1")
        self._server_settings = dict(server_settings or {})
        self._pool: Optional[asyncpg.Pool] = None
        shadow = shadow_dsn(settings)
        self._shadow_dsn = None if shadow is None else to_libpq_url(shadow)
        self._shadow_pool: Optional[asyncpg.Pool] = None
        self._lock = asyncio.Lock()
        self._system_scope_verified = False

    @classmethod
    async def connect(cls, settings: DatabaseSettings, **kwargs: Any) -> Database:
        db = cls(settings, **kwargs)
        await db.open()
        return db

    @property
    def is_open(self) -> bool:
        return self._pool is not None and not self._pool.is_closing()

    @egress("database_connection", REFUSE)
    async def _create_pool(
        self, dsn: str, min_size: int, max_size: int, server_settings: Mapping[str, str]
    ) -> asyncpg.Pool:
        kwargs: dict[str, Any] = {
            "dsn": dsn,
            "min_size": min_size,
            "max_size": max_size,
            "command_timeout": self._settings.command_timeout_s,
            "server_settings": {
                "statement_timeout": str(int(self._settings.statement_timeout_ms)),
                **server_settings,
            },
            "init": _init_connection,
        }
        ssl_arg = build_ssl_arg(self._settings.ssl_mode, self._settings.ssl_root_cert)
        if ssl_arg is not None:
            kwargs["ssl"] = ssl_arg
        try:
            return await asyncpg.create_pool(**kwargs)
        except (TimeoutError, OSError, asyncpg.PostgresError) as exc:
            raise DatabaseUnavailable(f"cannot connect to {redact_url(dsn)}: {type(exc).__name__}") from exc

    @egress("database_connection", REFUSE)
    async def open(self) -> None:
        async with self._lock:
            if self._pool is not None:
                return
            server_settings = {"application_name": self._application_name, **self._server_settings}
            self._pool = await self._create_pool(self._dsn, self._min_size, self._max_size, server_settings)
            log.info("db.pool_opened", min_size=self._min_size, max_size=self._max_size)

    @egress("database_connection", REFUSE)
    async def open_shadow(self) -> None:
        """Open the shadow runs' pool (the SELECT-only shadow role), once; a shadow run calls it before it starts.

        Raises :class:`ShadowRoleRequired` when ``database.shadow_url`` is unset, or
        when its role could write or bypass tenant isolation.
        """
        async with self._lock:
            if self._shadow_pool is not None:
                return
            if self._shadow_dsn is None:
                raise ShadowRoleRequired(
                    "shadow runs need database.shadow_url, the login of the SELECT-only shadow role; refusing to start"
                )
            read_only = {"application_name": f"{self._application_name}-shadow", "default_transaction_read_only": "on"}
            pool = await self._create_pool(self._shadow_dsn, 0, self._settings.shadow_pool_max, read_only)
            try:
                async with pool.acquire(timeout=self._acquire_timeout_s) as conn:
                    row = await conn.fetchrow(UNSAFE_ROLE_SQL.format(role="current_user"))
                    role = await conn.fetchval("SELECT current_user")
            except (TimeoutError, OSError, asyncpg.PostgresError) as exc:
                pool.terminate()
                raise DatabaseUnavailable(f"cannot connect as the shadow role: {type(exc).__name__}") from exc
            reasons = unsafe_role_reasons(None if row is None else tuple(row), str(role))
            if reasons:
                await pool.close()
                raise ShadowRoleRequired(f"database.shadow_url logs in as {role!r}, which " + "; ".join(reasons))
            self._shadow_pool = pool
            log.info("db.shadow_pool_opened", max_size=self._settings.shadow_pool_max)

    async def close(self, timeout_s: float = 10.0) -> None:
        async with self._lock:
            pools = [p for p in (self._pool, self._shadow_pool) if p is not None]
            self._pool = self._shadow_pool = None
        for pool in pools:
            try:
                await asyncio.wait_for(pool.close(), timeout=timeout_s)
            except TimeoutError:
                log.warning("db.pool_close_timeout", timeout_s=timeout_s)
                pool.terminate()
        if pools:
            log.info("db.pool_closed")

    async def __aenter__(self) -> Database:
        await self.open()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise DatabaseUnavailable("database pool is not open")
        return self._pool

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        """A pooled connection without a tenant scope (in a read-only transaction in a shadow run).

        Only for health checks and administrative statements; RLS makes
        tenant tables appear empty here.
        """
        async with self._acquire() as conn:
            if not in_shadow():
                yield conn
                return
            async with conn.transaction(readonly=True):
                # A first statement, so SET TRANSACTION READ WRITE can no longer follow the BEGIN.
                await conn.execute("SELECT 1")
                yield shadow_connection(conn)

    def _shadow_or_refuse(self) -> asyncpg.Pool:
        if self._shadow_pool is None:
            # Never the runtime pool: a shadow run reads only as the SELECT-only shadow role.
            refuse_in_shadow("database", "a connection without the shadow role (Database.open_shadow)")
            raise ShadowRoleRequired("the shadow pool is not open")  # pragma: no cover - refuse_in_shadow raised
        return self._shadow_pool

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Connection]:
        pool = self._shadow_or_refuse() if in_shadow() else self._require_pool()
        try:
            conn = await pool.acquire(timeout=self._acquire_timeout_s)
        except TimeoutError as exc:
            raise PoolExhausted(f"no database connection available within {self._acquire_timeout_s}s") from exc
        except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            raise DatabaseUnavailable(f"cannot acquire a database connection: {type(exc).__name__}") from exc
        try:
            yield conn
        finally:
            await pool.release(conn)

    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str, *, readonly: bool = False) -> AsyncIterator[Connection]:
        """Transaction scoped to one tenant via ``app.tenant_id``."""
        validate_tenant_id(tenant_id)
        async with self._acquire() as conn:
            async with conn.transaction(readonly=readonly or in_shadow()):
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
                yield shadow_connection(conn) if in_shadow() else conn

    async def run_tenant_tx(
        self, tenant_id: str, work: Callable[[Connection], Awaitable[T]], *, readonly: bool = False
    ) -> T:
        """``await work(conn)`` in :meth:`tenant_tx`, retried once (:func:`retry_stale_statement`).

        ``work`` must only run statements on ``conn``. A retry opens a new
        :meth:`tenant_tx` for the same ``tenant_id``, so it is scoped exactly
        like the first attempt.
        """

        async def attempt() -> T:
            async with self.tenant_tx(tenant_id, readonly=readonly) as conn:
                return await work(conn)

        return await retry_stale_statement(attempt)

    @asynccontextmanager
    async def system_tx(self, *, readonly: bool = False) -> AsyncIterator[Connection]:
        """Transaction that bypasses tenant RLS (scheduler, retention, migrate).

        Raises :class:`SystemScopeDenied` when the connected role is not a
        member of the schema owner role, instead of silently seeing no rows.
        """
        async with self._acquire() as conn:
            async with conn.transaction(readonly=readonly or in_shadow()):
                await conn.execute("SELECT set_config('app.bypass_rls', 'on', true)")
                if in_shadow() or not self._system_scope_verified:
                    await self._verify_system_scope(conn)
                yield shadow_connection(conn) if in_shadow() else conn

    async def _verify_system_scope(self, conn: Connection) -> None:
        try:
            allowed = await conn.fetchval("SELECT lgsotf_rls_bypass()")
        except asyncpg.UndefinedFunctionError as exc:
            raise DatabaseError("database schema is not migrated; run `lg-sotf migrate`") from exc
        if not allowed:
            raise SystemScopeDenied(
                "this database role cannot bypass tenant isolation; system operations must run as the schema owner"
            )
        if not in_shadow():  # the shadow pool's role is another one, checked on every use (and always refused)
            self._system_scope_verified = True

    async def ping(self, *, acquire_timeout_s: float = 1.0) -> Optional[float]:
        """Round-trip ``SELECT 1`` and return its latency in seconds.

        Returns ``None`` without a round trip when every pooled connection is
        checked out: the database answered those connections, and failing
        readiness because of load would pull every replica at once. Raises
        :class:`DatabaseUnavailable` when the database cannot be reached.
        """
        pool = self._require_pool()
        started = time.perf_counter()
        try:
            conn = await pool.acquire(timeout=acquire_timeout_s)
        except TimeoutError as exc:
            if pool.get_size() >= pool.get_max_size() and pool.get_idle_size() == 0:
                return None
            raise DatabaseUnavailable("database ping failed: timed out connecting") from exc
        except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            raise DatabaseUnavailable(f"database ping failed: {type(exc).__name__}") from exc
        try:
            await conn.fetchval("SELECT 1", timeout=max(acquire_timeout_s, 1.0))
        except (TimeoutError, OSError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            raise DatabaseUnavailable(f"database ping failed: {type(exc).__name__}") from exc
        finally:
            await pool.release(conn)
        return time.perf_counter() - started

    def stats(self) -> PoolStats:
        pool = self._require_pool()
        return PoolStats(
            size=pool.get_size(),
            idle=pool.get_idle_size(),
            min_size=pool.get_min_size(),
            max_size=pool.get_max_size(),
        )


def owner_dsn(settings: Settings) -> str:
    """The schema-owner URL as ``postgresql://``: ``database.migration_url``, falling back to ``database.url``.

    Migrations, the scheduler (retention, partitions, leader lease) and the
    one-shot CLI operations connect as the schema owner; the API and the
    workers use ``database.url`` (the RLS-bound runtime role).
    """
    url = settings.database.migration_url or settings.database.url
    return to_libpq_url(url.get_secret_value())


def owner_database(settings: Settings, application_name: str) -> Database:
    """A small schema-owner pool (0 to 2 connections) for one-shot CLI operations."""
    return Database(
        settings.database, dsn=owner_dsn(settings), application_name=application_name, min_size=0, max_size=2
    )
