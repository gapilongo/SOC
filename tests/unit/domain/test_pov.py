"""Proof-of-value runs (PRD-11.1): the windows of a run, its status, and what the API shows of it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

import pytest

from lg_sotf.api.routers.pov import run_out, shadow_reports
from lg_sotf.db.repos.pov_runs import PovRun
from lg_sotf.domain.pov import (
    MAX_BACKTEST_DAYS,
    MAX_SHADOW_DAYS,
    POV_BACKTEST_STATUSES,
    backtest_days,
    plan_windows,
    pov_status,
    shadow_status,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 14, 9, 30, tzinfo=UTC)


def make_run(*, backtest_status: str = "pending", cancelled_at: Optional[datetime] = None, **extra: Any) -> PovRun:
    windows = plan_windows(NOW, backtest_days=30, shadow_days=14)
    return PovRun(
        id=uuid4(), tenant_id="acme", name="Acme PoV", backtest_start=windows.backtest_start,
        backtest_end=windows.backtest_end, shadow_start=windows.shadow_start, shadow_end=windows.shadow_end,
        backtest_status=backtest_status, backtest_attempts=0, backtest_started_at=None, backtest_finished_at=None,
        backtest_error=None, backtest_result=extra.pop("backtest_result", None), created_by="u-1", created_at=NOW,
        cancelled_at=cancelled_at, cancelled_by=None, **extra,
    )


def test_the_history_window_ends_and_the_shadow_period_starts_at_creation() -> None:
    windows = plan_windows(NOW, backtest_days=90, shadow_days=14)
    assert (windows.backtest_start, windows.backtest_end) == (NOW - timedelta(days=90), NOW)
    assert (windows.shadow_start, windows.shadow_end) == (NOW, NOW + timedelta(days=14))
    assert backtest_days(windows.backtest_start, windows.backtest_end) == 90


@pytest.mark.parametrize(
    "kwargs",
    [
        {"backtest_days": 0, "shadow_days": 14},
        {"backtest_days": MAX_BACKTEST_DAYS + 1, "shadow_days": 14},
        {"backtest_days": 30, "shadow_days": 0},
        {"backtest_days": 30, "shadow_days": MAX_SHADOW_DAYS + 1},
    ],
)
def test_windows_outside_the_limits_are_refused(kwargs: Any) -> None:
    with pytest.raises(ValueError, match="must be between"):
        plan_windows(NOW, **kwargs)


def test_a_naive_clock_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        plan_windows(NOW.replace(tzinfo=None), backtest_days=1, shadow_days=1)


def test_the_shadow_period_follows_the_clock() -> None:
    start, end = NOW, NOW + timedelta(days=14)
    assert shadow_status(start, end, NOW - timedelta(seconds=1)) == "scheduled"
    assert shadow_status(start, end, NOW) == "running"
    assert shadow_status(start, end, end - timedelta(seconds=1)) == "running"
    assert shadow_status(start, end, end) == "completed"


@pytest.mark.parametrize(
    ("backtest", "after_days", "cancelled", "expected"),
    [
        ("pending", 0, False, "backtest"),
        ("running", 1, False, "backtest"),
        ("running", 20, False, "backtest"),  # its shadow period is over, its backtest is not
        ("completed", 1, False, "shadow"),
        ("no_data", 1, False, "shadow"),
        ("failed", 13, False, "shadow"),
        ("completed", 14, False, "completed"),
        ("failed", 30, False, "completed"),
        ("pending", 1, True, "cancelled"),
        ("completed", 30, True, "cancelled"),
    ],
)
def test_the_phase_of_a_run(backtest: str, after_days: int, cancelled: bool, expected: str) -> None:
    assert backtest in POV_BACKTEST_STATUSES
    now = NOW + timedelta(days=after_days)
    status = pov_status(
        backtest_status=backtest, shadow_end=NOW + timedelta(days=14), cancelled_at=NOW if cancelled else None, now=now
    )
    assert status == expected


def test_shadow_report_links_cover_the_whole_days_of_the_period() -> None:
    assert shadow_reports(make_run()) == {
        "value": "/reports/value?from=2026-11-14&to=2026-11-28",
        "accuracy": "/reports/accuracy?from=2026-11-14&to=2026-11-28",
        "detections": "/reports/detections?from=2026-11-14&to=2026-11-28",
    }
    # A period that ends at midnight does not reach into the next day.
    midnight = make_run().model_copy(
        update={"shadow_start": datetime(2026, 11, 14, tzinfo=UTC), "shadow_end": datetime(2026, 11, 15, tzinfo=UTC)}
    )
    assert shadow_reports(midnight)["value"] == "/reports/value?from=2026-11-14&to=2026-11-14"


def test_the_backtest_result_is_shown_on_the_runs_own_read_only() -> None:
    run = make_run(backtest_status="completed", backtest_result={"metrics": {"items": 3}})
    assert run_out(run, now=NOW).backtest.result is None
    detail = run_out(run, now=NOW + timedelta(days=1), detail=True)
    assert (detail.status, detail.backtest.result, detail.shadow.status) == ("shadow", {"metrics": {"items": 3}}, "running")
    assert (detail.backtest.window_start, detail.backtest.window_end) == (run.backtest_start, run.backtest_end)


def test_a_cancelled_runs_shadow_period_ended_when_it_was_cancelled() -> None:
    cancelled = run_out(make_run(cancelled_at=NOW + timedelta(days=2)), now=NOW + timedelta(days=3))
    assert (cancelled.status, cancelled.shadow.status, cancelled.backtest.status) == ("cancelled", "completed", "pending")
