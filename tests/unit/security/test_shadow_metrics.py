"""Shadow mode (AI-E1.5a): cost, refusal and enrichment metrics of a shadow run move only ``mode="shadow"``.

Each probe produces a real value: a priced model call, a model refusal through an agent, a provider lookup and a
cache hit through the enrichment service.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.agents.triage.base import TriageAgent
from lg_sotf.llm.fake import Refuse
from lg_sotf.llm.usage import UsageRecorder
from lg_sotf.observability.metrics import REGISTRY
from lg_sotf.security.shadow import ShadowRun, shadow_scope
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment.base import EnrichmentResult, LookupRequest
from lg_sotf.tools.enrichment.service import EnrichmentService
from tests.unit.agents._support import AMBIGUOUS, ctx, factory, fake_repos, scripted

pytestmark = pytest.mark.unit

PRICED_MODEL = "claude-sonnet-5-5"


def both(name: str, **labels: str) -> Dict[str, float]:
    return {mode: REGISTRY.get_sample_value(name, {**labels, "mode": mode}) or 0.0 for mode in ("live", "shadow")}


def moved(before: Dict[str, float], after: Dict[str, float]) -> Dict[str, float]:
    return {mode: after[mode] - before[mode] for mode in before}


def test_a_shadow_run_priced_call_moves_only_the_shadow_cost(make_settings: Callable[..., Settings]) -> None:
    recorder = UsageRecorder(make_settings())
    before = both("lgsotf_llm_cost_usd_total", model=PRICED_MODEL)
    with shadow_scope(ShadowRun("shadow/cost")) as run:
        cost = recorder.record(model=PRICED_MODEL, agent="analysis", outcome="success", tenant_id="t1",
                               input_tokens=10_000, output_tokens=2_000)
    delta = moved(before, both("lgsotf_llm_cost_usd_total", model=PRICED_MODEL))
    assert cost > 0 and delta["live"] == 0 and delta["shadow"] == pytest.approx(float(cost))
    assert run.llm_cost_usd == cost and recorder.pending_rows() == []


async def test_a_shadow_run_refusal_moves_only_the_shadow_refusals(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    model = scripted(TriageAssessment=[Refuse("cyber")])
    before = both("lgsotf_llm_refusals_total", agent="triage", category="cyber")
    with shadow_scope(ShadowRun("shadow/refusal")):
        result = await TriageAgent(settings=settings, model_factory=factory(model)).run(
            ctx(settings, repos=fake_repos()), AMBIGUOUS
        )
    assert result.llm_refusal is not None
    assert moved(before, both("lgsotf_llm_refusals_total", agent="triage", category="cyber")) == {
        "live": 0, "shadow": 1,
    }


class Provider:
    name = "metric_ti"
    kinds = frozenset({"ip"})
    external = True
    cache_ttl_s = 300.0
    requests_per_minute = 0

    def __init__(self) -> None:
        self.sent: List[str] = []

    def requires_credentials(self) -> bool:
        return False

    async def lookup(self, request: LookupRequest) -> EnrichmentResult:
        self.sent.append(request.value)
        return EnrichmentResult.ok(self.name, request.kind, "malicious", {"score": 99})

    async def aclose(self) -> None:
        return None


async def test_a_shadow_run_enrichment_lookups_move_only_the_shadow_series(make_settings: Any) -> None:
    provider = Provider()
    service = EnrichmentService([provider], make_settings())
    await service.lookup("tenant-a", "ip", "185.220.101.44")  # live: fills the cache
    labels = {"provider": "metric_ti"}
    before = {s: both("lgsotf_enrichment_lookups_total", **labels, status=s) for s in ("cached", "skipped")}
    with shadow_scope(ShadowRun("shadow/ti-metrics")):
        hit = await service.lookup("tenant-a", "ip", "185.220.101.44")
        miss = await service.lookup("tenant-a", "ip", "45.155.205.233")
    assert hit[0].cached and miss[0].status == "skipped" and provider.sent == ["185.220.101.44"]
    for status in ("cached", "skipped"):
        after = both("lgsotf_enrichment_lookups_total", **labels, status=status)
        assert moved(before[status], after) == {"live": 0, "shadow": 1}
