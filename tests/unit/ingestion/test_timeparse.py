from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from lg_sotf.ingestion.timeparse import (
    FLAG_ASSUMED_UTC,
    FLAG_CLAMPED,
    FLAG_INVALID,
    FLAG_MISSING,
    first_timestamp,
    isoformat_z,
    parse_timestamp,
)

NOW = datetime(2024, 3, 5, 12, 0, 0, tzinfo=UTC)
T = datetime(2024, 3, 5, 10, 15, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "2024-03-05T10:15:30Z",
        "2024-03-05T10:15:30+00:00",
        "2024-03-05T11:15:30+01:00",
        "2024-03-05T05:15:30-05:00",
        "2024-03-05T10:15:30.000+0000",
        "20240305T101530Z",
        "Tue, 05 Mar 2024 10:15:30 GMT",
        1709633730,
        1709633730.0,
        "1709633730",
        1709633730000,
        "1709633730000",
        1709633730000000,
        1709633730000000000,
        datetime(2024, 3, 5, 12, 15, 30, tzinfo=timezone(timedelta(hours=2))),
    ],
)
def test_formats_convert_to_utc(value: object) -> None:
    result = parse_timestamp(value, now=NOW)
    assert result.value == T
    assert result.value.tzinfo == UTC
    assert result.flags == []


def test_sub_microsecond_fractions_are_truncated() -> None:
    result = parse_timestamp("2024-03-05T10:15:30.123456789Z", now=NOW)
    assert result.value == T.replace(microsecond=123456)
    assert parse_timestamp("2024-03-05T10:15:30.1234567Z", now=NOW).value == T.replace(microsecond=123456)


def test_naive_values_are_assumed_utc_and_flagged() -> None:
    result = parse_timestamp("2024-03-05 10:15:30", now=NOW)
    assert result.value == T
    assert result.flags == [FLAG_ASSUMED_UTC]
    assert parse_timestamp(datetime(2024, 3, 5, 10, 15, 30), now=NOW).flags == [FLAG_ASSUMED_UTC]


def test_far_future_is_clamped_and_flagged() -> None:
    result = parse_timestamp("2031-01-01T00:00:00Z", now=NOW)
    assert result.value == NOW
    assert result.flags == [FLAG_CLAMPED]
    slight = parse_timestamp(NOW + timedelta(minutes=5), now=NOW)
    assert slight.value == NOW + timedelta(minutes=5) and slight.flags == []


@pytest.mark.parametrize("value", ["not a date", "1980-01-01T00:00:00Z", -5, 0, True, {"a": 1}, "9" * 80, float("inf")])
def test_invalid_values(value: object) -> None:
    result = parse_timestamp(value, now=NOW)
    assert result.value is None
    assert result.flags == [FLAG_INVALID]


def test_missing_values() -> None:
    assert parse_timestamp(None).flags == [FLAG_MISSING]
    assert parse_timestamp("").flags == [FLAG_MISSING]


def test_first_timestamp_skips_blank_and_invalid_candidates() -> None:
    assert first_timestamp(None, "junk", 1709633730, now=NOW).value == T
    assert first_timestamp(None, "", now=NOW).flags == [FLAG_MISSING]
    assert first_timestamp("junk", now=NOW).flags == [FLAG_INVALID]


def test_isoformat_z() -> None:
    assert isoformat_z(T.replace(microsecond=123456)) == "2024-03-05T10:15:30.123Z"


@pytest.mark.parametrize(
    "value",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-14:00", 10**400, -(10**400), 1e308, "1e400"],
)
def test_out_of_range_values_are_invalid_not_errors(value: object) -> None:
    parsed = parse_timestamp(value, now=NOW)
    assert parsed.value is None and parsed.flags == [FLAG_INVALID]
