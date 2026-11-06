"""Shared plumbing for repositories."""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import (
    Any,
    AsyncIterator,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Type,
    TypeVar,
    Union,
)

import asyncpg
from pydantic import BaseModel, ConfigDict

from lg_sotf.db.errors import Conflict, DatabaseError, InvalidValue, ReferenceNotFound
from lg_sotf.db.pagination import Params
from lg_sotf.db.pool import Database
from lg_sotf.db.tenancy import switch_tenant, validate_tenant_id
from lg_sotf.db.types import Connection, DbRecord

# Foreign-key constraint name suffix -> the resource that was missing.
_FK_RESOURCES = (
    ("_tenant_id_fkey", "tenant"),
    ("_alert_fk", "alert"),
    ("_escalation_fk", "escalation"),
    ("_feedback_fk", "feedback"),
    ("_rollback_of_fk", "response action"),
    ("_integration_fk", "integration"),
    ("_replaced_by_fk", "refresh token"),
    ("_user_fk", "user"),
    ("_assigned_to_fk", "user"),
    ("_decided_by_fk", "user"),
    ("_created_by_fk", "user"),
)


def translate_db_error(exc: asyncpg.PostgresError) -> Optional[DatabaseError]:
    """Map a driver error caused by caller input to a domain error, or ``None``.

    Messages carry constraint names only, never the offending values.
    """
    constraint = getattr(exc, "constraint_name", None)
    if isinstance(exc, asyncpg.ForeignKeyViolationError):
        if "still referenced" in (exc.detail or ""):
            return Conflict(f"row is still referenced ({constraint})")
        resource = next((r for suffix, r in _FK_RESOURCES if (constraint or "").endswith(suffix)), "referenced row")
        return ReferenceNotFound(resource, constraint)
    if isinstance(exc, asyncpg.UniqueViolationError):
        return Conflict(f"a row with the same key already exists ({constraint})")
    if isinstance(exc, asyncpg.CheckViolationError):
        return InvalidValue(f"value rejected by constraint {constraint}")
    if isinstance(exc, asyncpg.NotNullViolationError):
        return InvalidValue(f"missing required value for {getattr(exc, 'column_name', None) or 'a column'}")
    if isinstance(exc, asyncpg.DataError):
        return InvalidValue(f"invalid value ({exc.sqlstate or 'data error'})")
    return None


class Record(BaseModel):
    """Immutable row returned by a repository."""

    model_config = ConfigDict(frozen=True, extra="ignore")


R = TypeVar("R", bound=Record)


def to_model(model: Type[R], row: Optional[DbRecord]) -> Optional[R]:
    return None if row is None else model.model_validate(dict(row))


def to_models(model: Type[R], rows: Iterable[DbRecord]) -> List[R]:
    return [model.model_validate(dict(r)) for r in rows]


class _Unset:
    """Marks a keyword argument that was not passed (distinct from ``None``)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNSET"

    def __bool__(self) -> bool:
        return False


UNSET: Any = _Unset()


def set_clauses(values: Mapping[str, Any], params: Params) -> List[str]:
    """``col = $n`` fragments for every value that is not :data:`UNSET`.

    Column names come from repository code, never from callers.
    """
    return [f"{col} = {params.add(value)}" for col, value in values.items() if value is not UNSET]


# Typed query helpers: the driver's results are ``Any`` or optional; these state what a statement returns.


async def fetch_one(conn: Connection, query: str, *args: Any) -> DbRecord:
    """``fetchrow`` for a statement that always returns a row (``INSERT ... RETURNING``, an aggregate, a row
    the transaction has just written or locked). No row means a broken invariant, never "not found"."""
    row = await conn.fetchrow(query, *args)
    if row is None:
        raise DatabaseError("the statement returned no row")
    return row


async def fetch_int(conn: Connection, query: str, *args: Any) -> int:
    """``fetchval`` of a non-null integer (``count(*)``, a ``COALESCE``d sum)."""
    value = await conn.fetchval(query, *args)
    if value is None:
        raise DatabaseError("the statement returned no value")
    return int(value)


async def fetch_bool(conn: Connection, query: str, *args: Any) -> bool:
    """``fetchval`` of a boolean (``EXISTS``, ``pg_try_advisory_lock``); no row or NULL is ``False``."""
    return bool(await conn.fetchval(query, *args))


def affected(status: str) -> int:
    """Rows a statement changed, from its command tag (``"UPDATE 3"``, ``"INSERT 0 5"``)."""
    return int(status.split()[-1])


def check_choice(value: str, allowed: Sequence[str], what: str) -> str:
    if value not in allowed:
        raise ValueError(f"invalid {what}: {value!r} (expected one of {', '.join(allowed)})")
    return value


def check_choices(value: Union[str, Sequence[str], None], allowed: Sequence[str], what: str) -> Optional[List[str]]:
    """Normalise a single value or a sequence filter into a validated list."""
    if value is None:
        return None
    items = [value] if isinstance(value, str) else list(value)
    for item in items:
        check_choice(item, allowed, what)
    return items


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def check_sha256_hex(value: str, what: str) -> str:
    """Secrets are stored only as lowercase hex sha256 digests."""
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"{what} must be a lowercase hex sha256 digest")
    return value


def require_aware(value: Optional[datetime], what: str) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        raise ValueError(f"{what} must be timezone-aware")
    return value


def utcnow() -> datetime:
    return datetime.now(UTC)


def truncate(text: Optional[str], limit: int) -> Optional[str]:
    if text is None or len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


@asynccontextmanager
async def _translated() -> AsyncIterator[None]:
    try:
        yield
    except asyncpg.PostgresError as exc:
        translated = translate_db_error(exc)
        if translated is None:
            raise
        raise translated from exc


class Repository:
    """Base class: every repository wraps one :class:`Database`.

    Tenant methods accept an optional ``conn`` so several repository calls can
    share one ``db.tenant_tx(tenant_id)`` transaction (for example a status
    change and its audit entry). A passed connection must already be inside a
    transaction scoped to the same tenant (or a system transaction).

    Driver errors caused by input (unknown referenced rows, CHECK/NOT NULL
    violations, malformed values, duplicate keys) surface as
    :class:`ReferenceNotFound`, :class:`InvalidValue` and :class:`Conflict`.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db

    @asynccontextmanager
    async def _tenant(self, tenant_id: str, conn: Optional[Connection] = None) -> AsyncIterator[Connection]:
        validate_tenant_id(tenant_id)
        if conn is not None:
            if not conn.is_in_transaction():
                raise RuntimeError("a connection passed to a repository must be inside db.tenant_tx()")
            async with _translated():
                yield conn
            return
        async with _translated():
            async with self._db.tenant_tx(tenant_id) as scoped:
                yield scoped

    @asynccontextmanager
    async def _system(
        self, conn: Optional[Connection] = None, *, readonly: bool = False
    ) -> AsyncIterator[Connection]:
        if conn is not None:
            if not conn.is_in_transaction():
                raise RuntimeError("a connection passed to a repository must be inside db.system_tx()")
            async with _translated():
                yield conn
            return
        async with _translated():
            async with self._db.system_tx(readonly=readonly) as scoped:
                yield scoped

    @asynccontextmanager
    async def _lookup(self) -> AsyncIterator[Connection]:
        """Connection for the SECURITY DEFINER credential lookups (no tenant scope)."""
        async with _translated():
            async with self._db.connection() as c:
                yield c

    @staticmethod
    async def _switch_tenant(conn: Connection, tenant_id: str) -> None:
        """Re-scope an open tenant transaction to another tenant (multi-tenant batch writes)."""
        await switch_tenant(conn, tenant_id)
