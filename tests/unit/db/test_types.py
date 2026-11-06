"""Typed DB connection (roadmap F9): the Protocols match the driver, and the typed query helpers."""

from __future__ import annotations

import inspect
from typing import Any, List, Optional

import asyncpg
import pytest

from lg_sotf import db
from lg_sotf.db.errors import DatabaseError
from lg_sotf.db.repos import _base
from lg_sotf.db.types import Connection, DbConnection, DbRecord


def _members(protocol: type) -> List[str]:
    return [name for name, value in vars(protocol).items() if callable(value) and not name.startswith("_")]


@pytest.mark.parametrize("name", _members(DbConnection))
def test_every_connection_method_exists_on_the_driver_with_its_keywords(name: str) -> None:
    # asyncpg is untyped, so mypy cannot check that it satisfies the Protocol; this does.
    declared = inspect.signature(getattr(DbConnection, name)).parameters
    actual = inspect.signature(getattr(asyncpg.Connection, name)).parameters
    keywords = {p for p, v in declared.items() if v.kind is inspect.Parameter.KEYWORD_ONLY}
    accepts_any = any(v.kind is inspect.Parameter.VAR_KEYWORD for v in actual.values())
    assert accepts_any or keywords <= set(actual), (name, keywords - set(actual))


@pytest.mark.parametrize("name", ["get", "keys", "values", "items"])
def test_every_record_method_exists_on_the_driver(name: str) -> None:
    assert callable(getattr(asyncpg.Record, name))


def test_one_alias_everywhere() -> None:
    assert db.Connection is Connection is DbConnection
    assert _base.Connection is Connection


class _FakeConnection:
    def __init__(self, row: Optional[dict] = None, value: Any = None) -> None:
        self.row, self.value = row, value
        self.calls: List[tuple] = []

    async def fetchrow(self, query: str, *args: Any) -> Optional[dict]:
        self.calls.append((query, args))
        return self.row

    async def fetchval(self, query: str, *args: Any) -> Any:
        self.calls.append((query, args))
        return self.value


def _conn(**kwargs: Any) -> Connection:
    fake: Any = _FakeConnection(**kwargs)
    return fake  # structural: the helpers only call fetchrow/fetchval


async def test_fetch_one_returns_the_row_and_passes_the_arguments() -> None:
    conn = _conn(row={"id": 1})
    row: DbRecord = await _base.fetch_one(conn, "SELECT $1, $2", "a", 2)
    assert row["id"] == 1
    assert conn.calls == [("SELECT $1, $2", ("a", 2))]  # type: ignore[attr-defined]


async def test_fetch_one_without_a_row_is_a_broken_invariant() -> None:
    with pytest.raises(DatabaseError, match="no row"):
        await _base.fetch_one(_conn(row=None), "SELECT 1 WHERE false")


async def test_fetch_int_converts_and_refuses_null() -> None:
    assert await _base.fetch_int(_conn(value=3), "SELECT count(*)") == 3
    with pytest.raises(DatabaseError, match="no value"):
        await _base.fetch_int(_conn(value=None), "SELECT NULL")


@pytest.mark.parametrize(("value", "expected"), [(True, True), (False, False), (None, False)])
async def test_fetch_bool(value: Any, expected: bool) -> None:
    assert await _base.fetch_bool(_conn(value=value), "SELECT EXISTS (SELECT 1)") is expected


@pytest.mark.parametrize(("tag", "rows"), [("UPDATE 3", 3), ("DELETE 0", 0), ("INSERT 0 5", 5)])
def test_affected_reads_the_command_tag(tag: str, rows: int) -> None:
    assert _base.affected(tag) == rows
