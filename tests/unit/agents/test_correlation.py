"""Correlation over the indicator index: bounded indicator types, hashed values, burst detection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Callable, List, Tuple

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.correlation.base import CorrelationAgent, frequency_level
from lg_sotf.agents.correlation.indicators import extract_indicators, is_public_ip
from lg_sotf.settings import Settings

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


@dataclass
class Related:
    alert_id: str
    shared_indicator_count: int
    last_seen: datetime


class FakeIndicators:
    def __init__(self, related: List[Related]) -> None:
        self.related = related
        self.sightings: List[Tuple[Any, ...]] = []
        self.queries: List[Any] = []

    async def add_sightings(self, tenant_id: str, alert_id: str, sightings: Any) -> int:
        self.sightings.extend(sightings)
        return len(sightings)

    async def related_alerts(self, tenant_id: str, indicators: Any, **kwargs: Any) -> List[Related]:
        self.queries.append((indicators, kwargs))
        return self.related


def test_extract_only_bounded_types_from_known_fields() -> None:
    alert = {
        "entities": {
            "ips": ["8.8.8.8", "not-an-ip", "8.8.8.8"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e", "xyz"],
            "domains": ["evil.example.com"],
            "users": [{"value": "jdoe"}],
            "hosts": ["ws-1"],
        },
        "raw": {"source_ip": "10.0.0.1", "request_id": "7f2c-unique-per-event", "user_agent": "curl"},
    }
    found = {(i.type, i.value) for i in extract_indicators(alert)}
    assert found == {
        ("ip", "8.8.8.8"),
        ("ip", "10.0.0.1"),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ("domain", "evil.example.com"),
        ("user", "jdoe"),
        ("host", "ws-1"),
    }
    assert is_public_ip("8.8.8.8") and not is_public_ip("10.0.0.1")


def test_indicator_count_is_capped() -> None:
    alert = {"entities": {"ips": [f"8.8.{i // 250}.{i % 250}" for i in range(500)]}}
    assert len(extract_indicators(alert)) == 10


def repos_with(related: List[Related]) -> Any:
    return SimpleNamespace(indicators=FakeIndicators(related))


async def test_no_related_alerts_skips_the_llm(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = repos_with([])
    ctx = AgentContext("t1", "a1", settings, repos=repos)
    result = await CorrelationAgent(settings=settings).run(ctx, {"entities": {"ips": ["8.8.8.8"]}}, base_confidence=40, now=NOW)
    assert (result.score, result.related_count, result.llm_used, result.confidence) == (0, 0, False, 40)
    (itype, value_hash, display, seen_at), = repos.indicators.sightings
    assert itype == "ip" and value_hash != "8.8.8.8" and len(value_hash) == 64 and display == "8.8.8.8"
    assert seen_at == NOW


async def test_burst_and_frequency_come_from_sightings(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    related = [Related(f"r{i}", 2, NOW - timedelta(minutes=1)) for i in range(6)]
    ctx = AgentContext("t1", "a1", settings, repos=repos_with(related))
    agent = CorrelationAgent(settings=settings)
    result = await agent.run(ctx, {"entities": {"hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}}, base_confidence=40, now=NOW)
    assert result.burst and result.related_count == 6 and result.llm_used
    assert result.related_alert_ids == [f"r{i}" for i in range(6)]
    assert result.confidence > 40 and result.score > 0
    _, kwargs = ctx.repos.indicators.queries[0]
    assert kwargs["since"] == NOW - agent.window and kwargs["exclude_alert_id"] == "a1"


def test_frequency_levels() -> None:
    assert [frequency_level(x) for x in (1, 6, 21, 51)] == ["low", "medium", "high", "critical"]
