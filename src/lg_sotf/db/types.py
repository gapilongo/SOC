"""Static types for database connections and rows.

asyncpg ships no type information, so ``asyncpg.Connection`` and
``asyncpg.Record`` are ``Any`` to mypy and every query result typed through
them is unchecked. :class:`DbConnection` and :class:`DbRecord` describe
exactly the parts of the driver this code base uses. They are Protocols:
structural, so the real asyncpg objects satisfy them with no wrapper and no
runtime cost, and no stub package is needed.

Code outside ``lg_sotf.db`` annotates connections as ``lg_sotf.db.Connection``
and never imports the driver for its types.
"""

from __future__ import annotations

from typing import Any, AsyncIterable, Awaitable, Callable, Iterator, List, Optional, Protocol, Tuple, TypeAlias, Union


class DbRecord(Protocol):
    """A result row (``asyncpg.Record``): read by column name or position; ``dict(row)`` copies it.

    Unlike a mapping, iterating a row yields its values, not its column names.
    """

    def __getitem__(self, key: Union[str, int], /) -> Any: ...

    def get(self, key: str, default: Any = None, /) -> Any: ...

    def keys(self) -> Iterator[str]: ...

    def values(self) -> Iterator[Any]: ...

    def items(self) -> Iterator[Tuple[str, Any]]: ...

    def __iter__(self) -> Iterator[Any]: ...

    def __len__(self) -> int: ...

    def __contains__(self, key: object, /) -> bool: ...


class DbTransaction(Protocol):
    """``Connection.transaction()``: a transaction, or a savepoint inside one."""

    async def __aenter__(self) -> Any: ...

    async def __aexit__(self, *exc_info: Any) -> Optional[bool]: ...


class DbConnection(Protocol):
    """The ``asyncpg.Connection`` methods used here (queries, transactions, lifecycle, codecs).

    The driver's coroutine methods are declared as returning awaitables; ``timeout`` is the driver's
    per-call timeout in seconds.
    """

    def execute(self, query: str, *args: Any, timeout: Optional[float] = None) -> Awaitable[str]:
        """Run a statement; the result is its command tag (``"UPDATE 3"``)."""
        ...

    def fetch(self, query: str, *args: Any, timeout: Optional[float] = None) -> Awaitable[List[DbRecord]]: ...

    def fetchrow(self, query: str, *args: Any, timeout: Optional[float] = None) -> Awaitable[Optional[DbRecord]]: ...

    def fetchval(self, query: str, *args: Any, column: int = 0, timeout: Optional[float] = None) -> Awaitable[Any]: ...

    def cursor(
        self, query: str, *args: Any, prefetch: Optional[int] = None, timeout: Optional[float] = None
    ) -> AsyncIterable[DbRecord]:
        """Iterate a query's rows in batches of ``prefetch`` (inside a transaction)."""
        ...

    def transaction(
        self, *, isolation: Optional[str] = None, readonly: bool = False, deferrable: bool = False
    ) -> DbTransaction: ...

    def is_in_transaction(self) -> bool: ...

    def set_type_codec(
        self, typename: str, *, encoder: Callable[[Any], Any], decoder: Callable[[Any], Any], **options: Any
    ) -> Awaitable[None]:
        """Register a codec; ``options`` are the driver's ``schema`` and ``format``."""
        ...

    def is_closed(self) -> bool: ...

    def close(self, *, timeout: Optional[float] = None) -> Awaitable[None]: ...

    def terminate(self) -> None: ...


#: The connection type every repository, service and helper is annotated with.
Connection: TypeAlias = DbConnection

__all__ = ["Connection", "DbConnection", "DbRecord", "DbTransaction"]
