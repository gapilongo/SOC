"""Agents against real Postgres and Redis: per-alert LLM accounting, related digests, history, tenant keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable, List

import httpx
import pytest

from lg_sotf.agents.analysis.base import AnalysisAgent
from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.correlation.base import CorrelationAgent
from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.repos import Repositories
from lg_sotf.llm import TokenBudget
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import hmac_indicator
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService, encrypt_tool_secret
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert

pytestmark = pytest.mark.integration

ENTITIES = {"ips": ["185.220.101.44"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"], "hosts": ["ws-042"]}
ALERT = {
    "title": "Unusual outbound connection from workstation",
    "severity": "medium",
    "source_id": "edr-prod",
    "entities": ENTITIES,
}


def model_factory(model: ScriptedChatModel) -> Any:
    return lambda tier, settings: model


async def test_usage_totals_accumulate_in_the_alert_summary(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    alert_id = await make_alert(repos, TENANT_A, title=ALERT["title"], severity="medium", normalized=ALERT)
    model = ScriptedChatModel(model_name="fake-it")
    triage = TriageAgent(settings=settings, model_factory=model_factory(model))
    analysis = AnalysisAgent(settings=settings, model_factory=model_factory(model))

    t = await triage.run(AgentContext(TENANT_A, alert_id, settings, repos=repos), ALERT)
    after_triage = (await repos.alerts.get(TENANT_A, alert_id)).summary["llm_usage"]
    await analysis.run(AgentContext(TENANT_A, alert_id, settings, repos=repos), ALERT, triage=t.digest(), correlation={})
    usage = (await repos.alerts.get(TENANT_A, alert_id)).summary["llm_usage"]

    assert after_triage["calls"] == 1 and set(after_triage["by_agent"]) == {"triage"}
    assert usage["calls"] == 2 and set(usage["by_agent"]) == {"triage", "analysis"}
    assert usage["by_agent"]["triage"] == after_triage["by_agent"]["triage"]
    assert usage["input_tokens"] > after_triage["input_tokens"] and usage["cost_usd"] == 0.0
    assert usage["total_tokens"] == sum(usage[k] for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"))
    # A second tenant's alert with the same id space is untouched.
    other = await make_alert(repos, TENANT_B, title="x", normalized={"title": "x"})
    assert "llm_usage" not in (await repos.alerts.get(TENANT_B, other)).summary


async def test_tenant_budget_exhaustion_falls_back_to_rules_and_is_flagged(
    repos: Repositories, redis_client: Any, make_settings: Callable[..., Settings], unique_prefix: str
) -> None:
    settings = make_settings(redis={"key_prefix": unique_prefix})
    alert_id = await make_alert(repos, TENANT_A, title=ALERT["title"], severity="medium", normalized=ALERT)
    budget = TokenBudget(redis_client, settings)
    ctx = AgentContext(TENANT_A, alert_id, settings, repos=repos, budget=budget, budget_limit=10)
    model = ScriptedChatModel(model_name="fake-it")
    result = await TriageAgent(settings=settings, model_factory=model_factory(model)).run(ctx, ALERT)
    assert model.calls == [] and not result.llm_used and ctx.llm_budget_exceeded
    summary = (await repos.alerts.get(TENANT_A, alert_id)).summary
    assert summary["llm_budget_exceeded"] is True and summary["llm_usage"]["budget_exceeded"] == 1
    assert await budget.used(TENANT_A) == 0


async def test_correlation_prompt_carries_real_related_alert_digests(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    now = datetime.now(UTC)
    earlier = await make_alert(
        repos, TENANT_A, title="Beacon to the same relay", severity="high",
        normalized={"title": "Beacon to the same relay", "entities": ENTITIES, "mitre": {"techniques": ["T1071"]}},
    )
    await repos.alerts.update(TENANT_A, earlier, disposition="malicious")
    agent = CorrelationAgent(settings=settings, model_factory=model_factory(ScriptedChatModel()))
    await agent.run(AgentContext(TENANT_A, earlier, settings, repos=repos), {"entities": ENTITIES}, base_confidence=50, now=now - timedelta(minutes=5))

    current = await make_alert(repos, TENANT_A, title=ALERT["title"], severity="medium", normalized=ALERT)
    model = ScriptedChatModel()
    agent = CorrelationAgent(settings=settings, model_factory=model_factory(model))
    result = await agent.run(AgentContext(TENANT_A, current, settings, repos=repos), ALERT, base_confidence=50, now=now)
    assert result.related_alert_ids == [earlier] and result.related_dispositions == {"malicious": 1}
    [call] = model.calls
    human = str(call.messages[1].content)
    assert "Beacon to the same relay" in human and '"disposition":"malicious"' in human and "T1071" in human
    assert earlier not in human


async def test_history_provider_reads_prior_dispositions(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    prior = await make_alert(repos, TENANT_A, title="Confirmed intrusion on ws-042", severity="critical", normalized=ALERT)
    # What the close node writes after an analyst's true-positive decision.
    await repos.alerts.update(
        TENANT_A,
        prior,
        disposition="malicious",
        summary={"close_reason": "analyst:true_positive", "analyst_decision": "true_positive"},
    )
    automated = await make_alert(repos, TENANT_A, title="Policy response on ws-042", severity="high", normalized=ALERT)
    await repos.alerts.update(TENANT_A, automated, disposition="malicious", summary={"close_reason": "policy:response"})
    host_hash = hmac_indicator("host", "ws-042", settings=settings)
    for alert_id in (prior, automated):
        await repos.indicators.add_sightings(TENANT_A, alert_id, [("host", host_hash, "ws-042", datetime.now(UTC))])
    service = EnrichmentService.from_settings(settings)
    current = await make_alert(repos, TENANT_A, title="x", normalized=ALERT)
    result = await service.history(TENANT_A, "host", "WS-042", repos=repos, exclude_alert_id=current)
    assert result.status == "ok" and result.verdict == "malicious"
    assert result.data["confirmed_malicious"] == 1 and result.data["model_malicious"] == 1
    # Without the analyst-confirmed alert, the automated verdict alone is not malicious history.
    only_automated = await service.history(TENANT_A, "host", "ws-042", repos=repos, exclude_alert_id=prior)
    assert only_automated.verdict == "unknown" and only_automated.data["model_malicious"] == 1
    other_tenant = await service.history(TENANT_B, "host", "ws-042", repos=repos)
    assert other_tenant.status == "not_found"


async def test_tenant_provider_key_from_encrypted_settings(repos: Repositories, make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    box = SecretBox.from_settings(settings)
    await repos.tenants.update_settings(
        TENANT_A, {"tools": {"virustotal": {"api_key_ciphertext": encrypt_tool_secret(box, TENANT_A, "virustotal", "tenant-a-vt")}}}
    )
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7}}}})

    service = EnrichmentService.from_settings(settings, transport=httpx.MockTransport(handler), secret_box=box)
    [result] = [r for r in await service.lookup(TENANT_A, "hash", ENTITIES["hashes"][0], repos=repos) if r.provider == "virustotal"]
    assert result.verdict == "malicious" and seen[0].headers["x-apikey"] == "tenant-a-vt"
    assert await service.configured_kinds(TENANT_B, repos) == {}
    await service.aclose()


async def test_verdict_cache_invalidation(redis_client: Any, unique_prefix: str) -> None:
    cache = VerdictCache(redis_client, unique_prefix)
    assert await cache.put_analyst_benign(TENANT_A, "fp-1", decision="false_positive", alert_id="a1", escalation_id=None)
    assert (await cache.get(TENANT_A, "fp-1"))["decision"] == "false_positive"
    assert await cache.invalidate(TENANT_A, "fp-1") is True
    assert await cache.get(TENANT_A, "fp-1") is None
    assert await cache.invalidate(TENANT_A, "fp-1") is False
