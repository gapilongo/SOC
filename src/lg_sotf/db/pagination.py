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
from typing import Any, Dict, Generic, Iterator, List, Optional, Sequence, Tuple, TypeVar, Union
from uuid import UUID

from lg_sotf.db.errors import InvalidCursor

T = TypeVar("T")

MAX_PAGE_SIZE = 500
# The largest page an API list endpoint serves (its ``limit`` query parameter's maximum).
API_MAX_LIMIT = 200
_CURSOR_VERSION = 1
MAX_CURSOR_CHARS = 512
# Text keysets: the longest sort value (an email address is at most 320 characters) and the
# cursor that carries it (base64 of the JSON document).
MAX_TEXT_SORT_CHARS = 320
MAX_TEXT_CURSOR_CHARS = 1_024


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


def _pack(doc: Dict[str, Any]) -> str:
    raw = json.dumps({"v": _CURSOR_VERSION, **doc}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unpack(cursor: str, max_chars: int = MAX_CURSOR_CHARS) -> Dict[str, Any]:
    """The JSON document of a cursor of this version (``InvalidCursor`` otherwise)."""
    if not isinstance(cursor, str) or not cursor or len(cursor) > max_chars:
        raise InvalidCursor("malformed cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        doc = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidCursor("malformed cursor") from exc
    if not isinstance(doc, dict) or doc.get("v") != _CURSOR_VERSION:
        raise InvalidCursor("unsupported cursor version")
    return doc


def encode_cursor(ts: datetime, key: Union[str, int]) -> str:
    if ts.tzinfo is None:
        raise ValueError("cursor timestamps must be timezone-aware")
    return _pack({"t": ts.astimezone(UTC).isoformat(), "k": key})


def decode_cursor(cursor: str) -> Tuple[datetime, Union[str, int]]:
    """Return ``(timestamp, key)`` from a cursor produced by :func:`encode_cursor`."""
    doc = _unpack(cursor)
    try:
        ts = datetime.fromisoformat(doc["t"])
        key = doc["k"]
    except (ValueError, KeyError, TypeError) as exc:
        raise InvalidCursor("malformed cursor") from exc
    if ts.tzinfo is None or not isinstance(key, (str, int)) or isinstance(key, bool):
        raise InvalidCursor("malformed cursor")
    return ts, key


def encode_text_cursor(sort: str, key: str) -> str:
    """Cursor for a ``(text sort column, id)`` keyset, such as users by ``(email, id)``."""
    return _pack({"s": sort, "k": key})


def decode_text_cursor(cursor: str) -> Tuple[str, str]:
    """Return ``(sort value, key)`` from a cursor produced by :func:`encode_text_cursor`."""
    doc = _unpack(cursor, MAX_TEXT_CURSOR_CHARS)
    return _text_part(doc.get("s")), _text_part(doc.get("k"))


def _text_part(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT_SORT_CHARS or "\x00" in value:
        raise InvalidCursor("malformed cursor")
    return value


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
