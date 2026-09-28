"""Keyset pagination helpers.

Cursors are opaque to clients: URL-safe base64 of a small JSON document that
records the sort key of the last row returned. Queries resume strictly after
that key, so pages stay stable while new rows are inserted.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Generic, Iterator, List, Optional, Sequence, Tuple, TypeVar, Union
from uuid import UUID

from lg_sotf.db.errors import InvalidCursor

T = TypeVar("T")

MAX_PAGE_SIZE = 500
_CURSOR_VERSION = 1


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of results. Unpacks as ``items, next_cursor``."""

    items: List[T]
    next_cursor: Optional[str]

    def __iter__(self) -> Iterator[Any]:
        return iter((self.items, self.next_cursor))

    def __len__(self) -> int:
        return len(self.items)


def check_limit(limit: int, maximum: int = MAX_PAGE_SIZE) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > maximum:
        raise ValueError(f"limit must be an integer between 1 and {maximum}")
    return limit


def encode_cursor(ts: datetime, key: Union[str, int]) -> str:
    if ts.tzinfo is None:
        raise ValueError("cursor timestamps must be timezone-aware")
    doc = {"v": _CURSOR_VERSION, "t": ts.astimezone(UTC).isoformat(), "k": key}
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> Tuple[datetime, Union[str, int]]:
    """Return ``(timestamp, key)`` from a cursor produced by :func:`encode_cursor`."""
    if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
        raise InvalidCursor("malformed cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        doc = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if not isinstance(doc, dict) or doc.get("v") != _CURSOR_VERSION:
            raise InvalidCursor("unsupported cursor version")
        ts = datetime.fromisoformat(doc["t"])
        key = doc["k"]
    except InvalidCursor:
        raise
    except (binascii.Error, UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        raise InvalidCursor("malformed cursor") from exc
    if ts.tzinfo is None or not isinstance(key, (str, int)) or isinstance(key, bool):
        raise InvalidCursor("malformed cursor")
    return ts, key


_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
MAX_TEXT_KEY_CHARS = 256


def decode_cursor_bigint(cursor: str) -> Tuple[datetime, int]:
    """Decode a cursor whose key is a ``BIGINT`` id."""
    ts, key = decode_cursor(cursor)
    if not isinstance(key, int) or not _INT64_MIN <= key <= _INT64_MAX:
        raise InvalidCursor("malformed cursor")
    return ts, key


def decode_cursor_uuid(cursor: str) -> Tuple[datetime, UUID]:
    """Decode a cursor whose key is a ``UUID`` id."""
    ts, key = decode_cursor(cursor)
    if not isinstance(key, str):
        raise InvalidCursor("malformed cursor")
    try:
        return ts, UUID(key)
    except ValueError as exc:
        raise InvalidCursor("malformed cursor") from exc


def decode_cursor_text(cursor: str) -> Tuple[datetime, str]:
    """Decode a cursor whose key is a ``TEXT`` id."""
    ts, key = decode_cursor(cursor)
    if not isinstance(key, str) or not key or len(key) > MAX_TEXT_KEY_CHARS or "\x00" in key:
        raise InvalidCursor("malformed cursor")
    return ts, key


def paginate(rows: Sequence[T], limit: int, key: Any) -> Page[T]:
    """Build a page from ``limit + 1`` fetched rows.

    ``key(row)`` returns the ``(timestamp, id)`` sort key of a row.
    """
    items = list(rows[:limit])
    next_cursor = None
    if len(rows) > limit and items:
        ts, ident = key(items[-1])
        next_cursor = encode_cursor(ts, ident)
    return Page(items=items, next_cursor=next_cursor)


class Params:
    """Accumulates positional query parameters for dynamically built SQL."""

    def __init__(self, *initial: Any) -> None:
        self.values: List[Any] = list(initial)

    def add(self, value: Any) -> str:
        self.values.append(value)
        return f"${len(self.values)}"


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
