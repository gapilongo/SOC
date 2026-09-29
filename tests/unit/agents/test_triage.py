"""Triage agent: rule evidence kept apart from LLM evidence; LLM failures degrade to rules."""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest

import lg_sotf.agents.base as agent_base
from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.triage.base import TriageAgent, priority_for, rule_confidence, rule_indicators
from lg_sotf.llm.errors import LLMBudgetExceeded, LLMOutputError
from lg_sotf.settings import Settings

BENIGN = {"title": "Scheduled backup maintenance test", "severity": "low", "source_id": "prod-siem"}
MALICIOUS = {
    "title": "Malware backdoor exploit detected",
    "severity": "critical",
    "source_id": "edr-prod",
    "raw": {"destination_port": 4444, "file_hash": "d41d8cd98f00b204e9800998ecf8427e"},
}


def ctx(settings: Settings) -> AgentContext:
    return AgentContext(tenant_id="t1", alert_id="a1", settings=settings)


def test_rule_scoring() -> None:
    assert rule_confidence(BENIGN) == 0
    assert rule_confidence(MALICIOUS) == 100
    fp, tp = rule_indicators(BENIGN)
    assert {"test_detected", "scheduled_detected", "maintenance_detected", "backup_detected"} <= set(fp)
    fp, tp = rule_indicators(MALICIOUS)
    assert {"malware_detected", "suspicious_port", "file_hash_present"} <= set(tp)


def test_priority_scale() -> None:
    assert priority_for("critical", 95) == 10
    assert priority_for("info", 10) == 1
    assert 1 <= priority_for("unknown", 60) <= 10


async def test_fake_llm_blends_with_rules(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    agent = TriageAgent(settings=settings)
    result = await agent.run(ctx(settings), BENIGN)
    assert result.llm_used and result.rule_confidence == 0
    assert result.confidence <= 10
    assert result.rule_fp and all(i not in result.rule_fp for i in result.llm_fp)


async def test_llm_output_error_falls_back_to_rules(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise LLMOutputError("bad json")

    monkeypatch.setattr(agent_base, "ainvoke_structured", broken)
    settings = make_settings()
    result = await TriageAgent(settings=settings).run(ctx(settings), MALICIOUS)
    assert not result.llm_used and result.confidence == result.rule_confidence == 100
    assert result.notes


async def test_budget_exhaustion_is_remembered(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def over(*args: Any, **kwargs: Any) -> Any:
        raise LLMBudgetExceeded("t1", limit=1, used=1, requested=1)

    monkeypatch.setattr(agent_base, "ainvoke_structured", over)
    settings = make_settings()
    c = ctx(settings)
    await TriageAgent(settings=settings).run(c, BENIGN)
    assert c.llm_budget_exceeded


async def test_transport_errors_propagate(
    make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down(*args: Any, **kwargs: Any) -> Any:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(agent_base, "ainvoke_structured", down)
    settings = make_settings()
    with pytest.raises(httpx.ConnectError):
        await TriageAgent(settings=settings).run(ctx(settings), BENIGN)


async def test_llm_disabled_uses_rules(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(llm={"enabled": False})
    result = await TriageAgent(settings=settings).run(ctx(settings), MALICIOUS)
    assert not result.llm_used


def test_agent_is_stateless_singleton(make_settings: Callable[..., Settings]) -> None:
    agent = TriageAgent(settings=make_settings(agents={"triage": {"llm_weight": 0.5}}))
    assert agent.llm_weight == 0.5
    with pytest.raises(ValueError):
        TriageAgent(settings=make_settings(agents={"triage": {"llm_weight": 2}}))
