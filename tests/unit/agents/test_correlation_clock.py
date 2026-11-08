"""Correlation's clock (AI-E1.9): the wall clock in production, the alert's own time in an evaluation replay."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict

import pytest

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.domain.routing import RoutingThresholds, correlated_confidence
from lg_sotf.settings import Settings
from tests.unit.agents._support import Related, fake_repos

EVENT = datetime(2026, 10, 19, 8, 4, 52, tzinfo=UTC)
ALERT = {"occurred_at": EVENT.isoformat(), "entities": {"ips": ["10.20.5.10"]}}


def agent(make_settings: Callable[..., Settings], clock: str | None = None, **routing: Any) -> CorrelationAgent:
    config: Dict[str, Any] = {"clock": clock} if clock else {}
    return CorrelationAgent(settings=make_settings(agents={"correlation": config}, routing=routing))


def test_the_wall_clock_is_the_default(make_settings: Callable[..., Settings]) -> None:
    before = datetime.now(UTC)
    assert agent(make_settings).clock(ALERT) >= before


@pytest.mark.parametrize("occurred_at", ["2026-10-19T08:04:52", "not a time", None])
def test_an_alert_without_a_usable_time_stays_on_the_wall_clock(
    make_settings: Callable[..., Settings], occurred_at: Any
) -> None:
    before = datetime.now(UTC)
    now = agent(make_settings, "event").clock({"occurred_at": occurred_at})  # a naive time is not comparable
    assert before <= now <= datetime.now(UTC)


def test_the_event_clock_keeps_the_gaps_and_starts_the_replay_now(make_settings: Callable[..., Settings]) -> None:
    clock = agent(make_settings, "event")
    before = datetime.now(UTC)
    first = clock.clock(ALERT)
    assert before <= first <= datetime.now(UTC)
    for gap in (timedelta(minutes=5), timedelta(days=3), -timedelta(hours=2)):
        assert clock.clock({"occurred_at": (EVENT + gap).isoformat()}) == first + gap


async def test_on_event_time_sightings_and_the_window_follow_the_alert(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(agents={"correlation": {"clock": "event"}})
    repos = fake_repos(related=[Related("r1", 1, EVENT - timedelta(minutes=5))])
    correlation = CorrelationAgent(settings=settings)
    first = correlation.clock(ALERT)
    later = {**ALERT, "occurred_at": (EVENT + timedelta(hours=2)).isoformat()}
    await correlation.run(AgentContext("t1", "a1", settings, repos=repos), later, base_confidence=30)
    (_, _, _, seen_at), = repos.indicators.sightings
    (_, query), = repos.indicators.queries
    assert seen_at == first + timedelta(hours=2)
    assert query["since"] == seen_at - timedelta(minutes=60)
    # An alert replayed out of order never correlates with sightings from its own future.
    assert seen_at < query["until"] <= seen_at + timedelta(seconds=1)


async def test_on_the_wall_clock_the_window_has_no_upper_bound(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    await CorrelationAgent(settings=settings).run(AgentContext("t1", "a1", settings, repos=repos), ALERT, base_confidence=30)
    (_, query), = repos.indicators.queries
    assert query["until"] is None and query["since"] > datetime.now(UTC) - timedelta(minutes=61)


@pytest.mark.parametrize(
    ("base", "adjusted", "cap", "expected"),
    [
        (60, 95, True, 79),  # related alerts never lift the confidence to the response policy
        (60, 75, True, 75),
        (79.6, 99, True, 79),
        (80, 95, True, 95),  # triage already reached it (trusted rule evidence and the model agree)
        (60, 95, False, 95),
    ],
)
def test_the_correlation_cap(base: float, adjusted: int, cap: bool, expected: int) -> None:
    thresholds = RoutingThresholds(cap_correlated_confidence=cap)
    assert correlated_confidence(base, adjusted, thresholds) == expected


async def test_the_agent_applies_the_cap(make_settings: Callable[..., Settings]) -> None:
    related = [Related(f"r{i}", 3, datetime.now(UTC) - timedelta(minutes=1)) for i in range(8)]
    for cap, expected in ((True, 79), (False, 100)):
        settings = make_settings(routing={"cap_correlated_confidence": cap})
        ctx = AgentContext("t1", "a1", settings, repos=fake_repos(related=related))
        result = await CorrelationAgent(settings=settings).run(ctx, ALERT, base_confidence=70)
        assert result.burst and result.confidence == expected
