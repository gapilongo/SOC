"""The MCP client's Retry-After handling (roadmap X3): seconds, fractions and HTTP dates, at most 10 s.

Before X3 only a whole number of seconds was honoured; a fractional value or an
HTTP date fell back to the exponential backoff.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import List

import httpx
import pytest

from lg_sotf.mcp.client import LgSotfApiClient, _retry_delay
from tests.unit.mcp._support import StubApi, fake_key


class _Sleeps:
    def __init__(self) -> None:
        self.calls: List[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


async def _slept_after(retry_after: str) -> float:
    stub = StubApi()
    answers = [httpx.Response(503, headers={"Retry-After": retry_after}), httpx.Response(200, json={})]
    stub.routes["GET /api/v1/alerts"] = lambda _r: answers.pop(0)
    sleeps = _Sleeps()
    client = LgSotfApiClient("https://soc.example.com", fake_key(), transport=stub.transport(), sleep=sleeps)
    assert await client.get("/api/v1/alerts") == {}
    (slept,) = sleeps.calls
    return slept


@pytest.mark.parametrize(
    ("header", "slept"),
    [("3", 3.0), (" 2 ", 2.0), ("1.5", 1.5), ("0.25", 0.25), ("0", 0.0), ("10", 10.0), ("60", 10.0), ("-4", 0.0)],
)
async def test_retry_after_seconds_are_honoured_up_to_10s(header: str, slept: float) -> None:
    assert await _slept_after(header) == slept


async def test_a_retry_after_http_date_is_honoured() -> None:
    soon = format_datetime(datetime.now(UTC) + timedelta(seconds=6), usegmt=True)
    assert 4.0 <= await _slept_after(soon) <= 6.0
    later = format_datetime(datetime.now(UTC) + timedelta(hours=1), usegmt=True)
    assert await _slept_after(later) == 10.0
    past = format_datetime(datetime.now(UTC) - timedelta(minutes=1), usegmt=True)
    assert await _slept_after(past) == 0.0


@pytest.mark.parametrize("header", ["soon", "nan", "inf", ""])
async def test_an_unreadable_retry_after_falls_back_to_backoff(header: str) -> None:
    assert await _slept_after(header) == 0.5


@pytest.mark.parametrize(("attempt", "delay"), [(0, 0.5), (1, 1.0), (2, 2.0), (4, 8.0), (5, 10.0)])
def test_the_backoff_is_capped_at_10s(attempt: int, delay: float) -> None:
    assert _retry_delay(None, attempt) == delay
