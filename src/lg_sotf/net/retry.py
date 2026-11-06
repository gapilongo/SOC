"""``Retry-After`` parsing shared by the outbound HTTP clients."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Optional

# Upper bound for any Retry-After hint: a server cannot park a caller (or a scheduled retry) for longer.
MAX_RETRY_AFTER_S = 3_600.0


def parse_retry_after(
    value: Optional[str], *, now: Optional[datetime] = None, cap: float = MAX_RETRY_AFTER_S
) -> Optional[float]:
    """Seconds to wait from a ``Retry-After`` header (delta seconds or HTTP date), in ``[0, cap]``.

    ``None`` for a missing or unreadable value, including ``nan`` and
    ``inf``: those would otherwise reach sleeps and retry schedules.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - (now or datetime.now(UTC))).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(max(0.0, seconds), cap)
