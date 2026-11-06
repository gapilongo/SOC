"""Retry-After parsing (delta seconds or HTTP date, capped, non-finite refused)."""

from __future__ import annotations

import datetime as dt

from lg_sotf.net.retry import MAX_RETRY_AFTER_S, parse_retry_after


def test_parse_retry_after() -> None:
    now = dt.datetime(2024, 3, 5, 10, 0, 0, tzinfo=dt.UTC)
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after("-3") == 0.0
    assert parse_retry_after("Tue, 05 Mar 2024 10:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None
    # Non-finite and absurd hints never reach a sleep or a retry schedule.
    assert parse_retry_after("inf") is None and parse_retry_after("nan") is None and parse_retry_after("-inf") is None
    assert parse_retry_after("1e12") == 3_600.0 and parse_retry_after("2.5") == 2.5
    assert parse_retry_after("90", cap=10.0) == 10.0


def test_default_cap() -> None:
    assert MAX_RETRY_AFTER_S == 3_600.0
