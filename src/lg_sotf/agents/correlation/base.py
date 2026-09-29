"""Correlation through the indicator-sighting index.

For each alert the agent records its indicators in ``indicator_sightings``
(HMAC-hashed per install, redacted display) and asks the index for other
alerts of the same tenant that shared any of them within the correlation
window. Frequency and burst detection come from those sightings. An optional
fast-tier LLM call, made only when related alerts exist, rates whether they
look like one campaign.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from pydantic import BaseModel, Field

from lg_sotf.agents.base import AgentContext, BaseAgent
from lg_sotf.agents.correlation.indicators import Indicator, extract_indicators
from lg_sotf.core.exceptions import AgentError
from lg_sotf.security.hashing import hmac_indicator

MAX_RELATED = 20
TYPE_WEIGHTS: Dict[str, int] = {"hash": 30, "ip": 25, "domain": 25, "url": 25, "user": 20, "host": 15, "process": 10}

SYSTEM_PROMPT = (
    "You are a SOC analyst correlating a security alert with related alerts that share indicators. "
    "Judge whether the activity looks like a coordinated campaign or unrelated noise."
)
TASK_PROMPT = (
    "Return campaign_likelihood (0-100), short attack campaign indicators and a brief reasoning. "
    "Base the answer only on the supplied alert and the related-alert statistics."
)


class CorrelationAssessment(BaseModel):
    campaign_likelihood: int = Field(ge=0, le=100)
    attack_campaign_indicators: List[str] = Field(default_factory=list, max_length=10)
    reasoning: str = Field(max_length=2_000)


@dataclass
class CorrelationResult:
    score: int
    confidence: int
    related_alert_ids: List[str]
    related_count: int
    indicator_count: int
    indicator_types: Dict[str, int]
    burst: bool
    frequency_level: str
    llm_used: bool = False
    campaign_indicators: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def digest(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("notes")
        return data


def frequency_level(alerts_per_hour: float) -> str:
    if alerts_per_hour > 50:
        return "critical"
    if alerts_per_hour > 20:
        return "high"
    if alerts_per_hour > 5:
        return "medium"
    return "low"


class CorrelationAgent(BaseAgent):
    name = "correlation"

    def __init__(self, config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        self.window = timedelta(minutes=int(self.get_config("correlation_window_minutes", 60)))
        self.burst_window = timedelta(minutes=int(self.get_config("burst_window_minutes", 15)))
        self.burst_threshold = int(self.get_config("burst_threshold", 5))
        self.max_related = min(MAX_RELATED, int(self.get_config("max_correlations", 10)))
        self.enable_llm = bool(self.get_config("enable_llm_correlation", True))
        self.llm_weight = float(self.get_config("llm_weight", 0.3))

    async def run(
        self,
        ctx: AgentContext,
        alert: Mapping[str, Any],
        *,
        base_confidence: float,
        now: Optional[datetime] = None,
    ) -> CorrelationResult:
        if ctx.repos is None:
            raise AgentError("correlation needs repositories in the agent context")
        now = now or datetime.now(UTC)
        indicators = extract_indicators(alert)
        hashed = [(i, hmac_indicator(i.type, i.value, settings=ctx.settings)) for i in indicators]
        if hashed:
            await ctx.repos.indicators.add_sightings(
                ctx.tenant_id, ctx.alert_id, [(i.type, h, i.display, now) for i, h in hashed]
            )
        related = []
        if hashed:
            related = await ctx.repos.indicators.related_alerts(
                ctx.tenant_id,
                [(i.type, h) for i, h in hashed],
                since=now - self.window,
                limit=self.max_related,
                exclude_alert_id=ctx.alert_id,
            )

        type_counts: Dict[str, int] = {}
        for ind in indicators:
            type_counts[ind.type] = type_counts.get(ind.type, 0) + 1
        recent = [r for r in related if r.last_seen >= now - self.burst_window]
        burst = len(recent) >= self.burst_threshold
        per_hour = len(related) / max(self.window.total_seconds() / 3600.0, 1e-9)
        rule_score = self._rule_score(related, indicators, burst)
        confidence = self._adjust_confidence(base_confidence, len(related), burst, frequency_level(per_hour))

        result = CorrelationResult(
            score=rule_score,
            confidence=confidence,
            related_alert_ids=[r.alert_id for r in related][: self.max_related],
            related_count=len(related),
            indicator_count=len(indicators),
            indicator_types=type_counts,
            burst=burst,
            frequency_level=frequency_level(per_hour),
        )
        if not related:
            return result

        llm = await self.call_llm(
            ctx,
            tier="fast",
            schema=CorrelationAssessment,
            system=SYSTEM_PROMPT,
            task=TASK_PROMPT,
            untrusted={
                "alert": dict(alert),
                "related": {
                    "related_alerts": len(related),
                    "max_shared_indicators": max(r.shared_indicator_count for r in related),
                    "burst": burst,
                    "indicator_types": type_counts,
                },
            },
            enabled=self.enable_llm,
        )
        result.notes.extend(llm.notes)
        if llm.value is not None:
            result.llm_used = True
            result.score = max(
                0, min(100, round(rule_score * (1 - self.llm_weight) + llm.value.campaign_likelihood * self.llm_weight))
            )
            result.campaign_indicators = [c[:120] for c in llm.value.attack_campaign_indicators]
        return result

    @staticmethod
    def _rule_score(related: List[Any], indicators: List[Indicator], burst: bool) -> int:
        if not related:
            return 0
        weight = max((TYPE_WEIGHTS.get(i.type, 10) for i in indicators), default=10)
        score = sum(min(3, r.shared_indicator_count) * weight // 3 for r in related)
        if burst:
            score += 20
        return max(0, min(100, score))

    @staticmethod
    def _adjust_confidence(base: float, related: int, burst: bool, level: str) -> int:
        adjustment = min(20, related * 5)
        if burst:
            adjustment += 15
        adjustment += {"critical": 15, "high": 10}.get(level, 0)
        return max(0, min(100, round(base + adjustment)))

