"""Proof-of-value (PoV) runs (PRD-11.1): the two windows of a run and its status.

A PoV run shows what the triage would have done on a tenant's own alerts,
in two phases that only read:

* the **backtest** replays the alerts analysts decided in the history window
  ``[backtest_start, backtest_end)`` through the current pipeline
  (:mod:`lg_sotf.eval.history`: read-only transactions, nothing created);
* the **shadow period** ``[shadow_start, shadow_end)`` follows it: the run
  only observes the alerts that arrive, and its results are the tenant's
  reports over that window.

A run is created with a number of days for each phase, counted from the
moment it is created: the history window ends there and the shadow period
starts there. A tenant has one run in progress at a time.

The backtest's status is stored (the scheduler runs it); the shadow period's
and the run's are derived from the clock, here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Optional, Tuple, get_args

#: ``no_data``: the history window holds no analyst-decided alert, so nothing was replayed.
PovBacktestStatus = Literal["pending", "running", "completed", "no_data", "failed"]
POV_BACKTEST_STATUSES: Tuple[PovBacktestStatus, ...] = get_args(PovBacktestStatus)
PovShadowStatus = Literal["scheduled", "running", "completed"]
#: The phase a run is in: its backtest is still to finish, it is shadowing, it is over, or it was cancelled.
PovStatus = Literal["backtest", "shadow", "completed", "cancelled"]

MAX_NAME_CHARS = 120
MAX_BACKTEST_DAYS = 366
MAX_SHADOW_DAYS = 90
DEFAULT_BACKTEST_DAYS = 90
DEFAULT_SHADOW_DAYS = 14
# A backtest calls the model for every alert it replays: at most this many alerts per run, and at
# most this many runs created per tenant in 24 hours.
BACKTEST_ALERT_LIMIT = 500
MAX_RUNS_PER_DAY = 3
# A backtest interrupted this many times (the scheduler stopped mid-run) is recorded as failed.
MAX_BACKTEST_ATTEMPTS = 3
MAX_BACKTEST_ERROR_CHARS = 300
_BACKTEST_OPEN = ("pending", "running")


@dataclass(frozen=True)
class PovWindows:
    backtest_start: datetime
    backtest_end: datetime
    shadow_start: datetime
    shadow_end: datetime


def plan_windows(now: datetime, *, backtest_days: int, shadow_days: int) -> PovWindows:
    """The windows of a run created at ``now``: history up to ``now``, the shadow period from ``now``."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not 1 <= backtest_days <= MAX_BACKTEST_DAYS:
        raise ValueError(f"backtest_days must be between 1 and {MAX_BACKTEST_DAYS}")
    if not 1 <= shadow_days <= MAX_SHADOW_DAYS:
        raise ValueError(f"shadow_days must be between 1 and {MAX_SHADOW_DAYS}")
    return PovWindows(
        backtest_start=now - timedelta(days=backtest_days),
        backtest_end=now,
        shadow_start=now,
        shadow_end=now + timedelta(days=shadow_days),
    )


def shadow_status(shadow_start: datetime, shadow_end: datetime, now: datetime) -> PovShadowStatus:
    if now < shadow_start:
        return "scheduled"
    return "running" if now < shadow_end else "completed"


def pov_status(
    *, backtest_status: str, shadow_end: datetime, cancelled_at: Optional[datetime], now: datetime
) -> PovStatus:
    """The run's phase at ``now``. A run is over once its shadow period ended and its backtest is settled."""
    if cancelled_at is not None:
        return "cancelled"
    if backtest_status in _BACKTEST_OPEN:
        return "backtest"
    return "shadow" if now < shadow_end else "completed"


def backtest_days(backtest_start: datetime, backtest_end: datetime) -> int:
    """The length of the history window in whole days (a run's window is a whole number of days)."""
    return max(1, round((backtest_end - backtest_start) / timedelta(days=1)))
