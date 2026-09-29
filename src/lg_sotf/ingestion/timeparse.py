"""Vendor timestamp parsing.

Accepted inputs:

* ISO 8601 / RFC 3339 strings with or without an offset (``Z``, ``+00:00``,
  ``+0000``) and with up to nanosecond fractions; naive values are taken as
  UTC and flagged.
* RFC 2822 strings (``Tue, 05 Mar 2024 10:15:30 GMT``).
* Epoch numbers (or numeric strings) in seconds, milliseconds, microseconds
  or nanoseconds, detected by magnitude.
* ``datetime`` objects.

Results are always UTC. Values later than ``now + max_future`` are clamped to
``now`` and flagged, since a far-future occurrence time would pin an alert to
the top of time-ordered views and poison polling watermarks. Values before
1990 are treated as invalid.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, List, Optional

MIN_PLAUSIBLE = datetime(1990, 1, 1, tzinfo=UTC)
DEFAULT_MAX_FUTURE = timedelta(minutes=15)

# Magnitude thresholds for epoch values: anything below 1e11 is seconds (up to
# year 5138), below 1e14 milliseconds, below 1e17 microseconds, else nanoseconds.
_EPOCH_UNITS = ((1e11, 1.0), (1e14, 1e3), (1e17, 1e6), (1e20, 1e9))

FLAG_MISSING = "occurred_at_missing"
FLAG_INVALID = "occurred_at_invalid"
FLAG_CLAMPED = "occurred_at_clamped_future"
FLAG_ASSUMED_UTC = "occurred_at_assumed_utc"


@dataclass
class ParsedTime:
    value: Optional[datetime]
    flags: List[str] = field(default_factory=list)


def _from_epoch(number: float) -> Optional[datetime]:
    if not math.isfinite(number) or number <= 0:
        return None
    for limit, divisor in _EPOCH_UNITS:
        if number < limit:
            try:
                return datetime.fromtimestamp(number / divisor, tz=UTC)
            except (OverflowError, OSError, ValueError):
                return None
    return None


def _from_string(text: str) -> tuple[Optional[datetime], bool]:
    """Returns (value, assumed_utc)."""
    text = text.strip().replace("\x00", "")
    if not text or len(text) > 64:
        return None, False
    try:
        number = float(text)
    except (ValueError, OverflowError):
        pass
    else:
        return _from_epoch(number), False
    candidate = text
    if candidate.endswith(("z", "Z")) and len(candidate) > 1:
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None, False
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC), True
    return _to_utc(parsed), False


def _to_utc(value: datetime) -> Optional[datetime]:
    """``None`` when the UTC conversion leaves datetime's range (``0001-01-01T00:00+01:00``)."""
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def parse_timestamp(
    value: Any,
    *,
    now: Optional[datetime] = None,
    max_future: timedelta = DEFAULT_MAX_FUTURE,
) -> ParsedTime:
    """Parse a vendor timestamp. ``value`` of ``None`` gives ``ParsedTime(None, [missing])``."""
    if value is None or value == "":
        return ParsedTime(None, [FLAG_MISSING])
    assumed_utc = False
    parsed: Optional[datetime]
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, datetime):
        if value.tzinfo is None:
            parsed, assumed_utc = value.replace(tzinfo=UTC), True
        else:
            parsed = _to_utc(value)
    elif isinstance(value, (int, float)):
        try:
            parsed = _from_epoch(float(value))
        except OverflowError:
            parsed = None
    elif isinstance(value, str):
        parsed, assumed_utc = _from_string(value)
    else:
        parsed = None
    if parsed is None or parsed < MIN_PLAUSIBLE:
        return ParsedTime(None, [FLAG_INVALID])
    flags = [FLAG_ASSUMED_UTC] if assumed_utc else []
    current = now or datetime.now(UTC)
    if parsed > current + max_future:
        flags.append(FLAG_CLAMPED)
        parsed = current
    return ParsedTime(parsed, flags)


def first_timestamp(
    *values: Any, now: Optional[datetime] = None, max_future: timedelta = DEFAULT_MAX_FUTURE
) -> ParsedTime:
    """The first candidate that parses; flags describe the chosen one (or ``missing``/``invalid``)."""
    saw_value = False
    for value in values:
        if value is None or value == "":
            continue
        saw_value = True
        result = parse_timestamp(value, now=now, max_future=max_future)
        if result.value is not None:
            return result
    return ParsedTime(None, [FLAG_INVALID if saw_value else FLAG_MISSING])


def isoformat_z(value: datetime) -> str:
    """UTC ISO 8601 with a ``Z`` suffix and millisecond precision (vendor query syntax)."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
