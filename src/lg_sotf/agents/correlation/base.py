"""Correlation through the indicator-sighting index.

For each alert the agent records its indicators in ``indicator_sightings``
(HMAC-hashed per install, redacted display) and asks the index for other
alerts of the same tenant that shared any of them within the correlation
window. Frequency and burst detection come from those sightings.

When related alerts exist the agent reads a compact digest of each (title,
severity, status, disposition, time, MITRE techniques, shared-indicator
count) and makes at most one fast-tier LLM call with those digests to rate
whether they look like one campaign. Without related alerts no call is made.

Email alerts are correlated on what the message is about, not on the
tenant's own infrastructure: domains and URLs of the tenant's internal
domains (``tools.internal_domains``) are left out, as is the reporter (see
:mod:`lg_sotf.domain.indicators`), so ordinary internal mail
and a prolific reporter never look like a campaign.

Correlation is evidence, not a score boost (decision policy v2, FIX-1): its
digest (related alerts, burst, frequency, campaign rating) goes to the
analysis model and into the alert summary, but the alert's confidence is
left as triage set it. Related alerts, bursts and alert rates therefore
never move an alert into the grey zone or to the response policy on their
own.

A refusal of that call leaves the alert's assessment open: its confidence is
raised to the grey zone (``routing.correlation_grey_zone_min``) and the
digest carries ``llm_refusal``, so routing sends it to an analyst instead of
an automatic close.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Tuple, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from lg_sotf.agents.base import AccountedRun, AgentContext, BaseAgent, LLMResult
from lg_sotf.agents.triage.base import agent_refusal
from lg_sotf.db.errors import NotFound
from lg_sotf.domain.indicators import Indicator, extract_indicators
from lg_sotf.domain.phishing import PhishingProfile
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.errors import AgentError
from lg_sotf.llm.registry import register_prompt
from lg_sotf.llm.schema import clipped_list, clipped_str
from lg_sotf.security.hashing import hmac_indicator

if TYPE_CHECKING:
    from lg_sotf.core.state import CorrelationDigest

MAX_RELATED = 20
MAX_DIGESTS = 10
DIGEST_TITLE_CHARS = 160
TYPE_WEIGHTS: Dict[str, int] = {"hash": 30, "ip": 25, "domain": 25, "url": 25, "user": 20, "host": 15, "process": 10}

SYSTEM_PROMPT = (
    "You are an analyst in a security operations center (SOC) correlating one alert from the organisation's "
    "own monitoring with earlier alerts that share indicators (hosts, users, IPs, domains, hashes). This is "
    "defensive work: the goal is to tell a coordinated intrusion or campaign apart from unrelated or routine "
    "activity so defenders can prioritise. Describe evidence only; never provide attack instructions."
)
TASK_PROMPT = (
    "Using the alert and the related-alert digests, return campaign_likelihood (0-100, how likely these "
    "alerts are one coordinated activity), attack_campaign_indicators (short phrases naming the concrete "
    "shared evidence) and a brief reasoning. Related alerts already closed as benign by analysts count "
    "against a campaign; confirmed malicious ones count for it."
)


class CorrelationAssessment(BaseModel):
    """The fast-tier model's answer. Over-long text and lists are truncated to their limits, never rejected."""

    campaign_likelihood: int = Field(ge=0, le=100)
    attack_campaign_indicators: clipped_list(10, item_chars=120)  # type: ignore[valid-type]
    reasoning: clipped_str(2_000)  # type: ignore[valid-type]


PROMPT = register_prompt("correlation.assess", system=SYSTEM_PROMPT, task=TASK_PROMPT, schema=CorrelationAssessment)


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
    llm_skipped: Optional[str] = None
    llm_refusal: Optional[Dict[str, Optional[str]]] = None
    related_dispositions: Dict[str, int] = field(default_factory=dict)
    campaign_indicators: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def digest(self) -> CorrelationDigest:
        data = asdict(self)
        data.pop("notes")
        if data["llm_refusal"] is None:
            data.pop("llm_refusal")
        return cast("CorrelationDigest", data)


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

    @staticmethod
    async def indicators(ctx: AgentContext, alert: Mapping[str, Any]) -> List[Indicator]:
        """The alert's indicators; for email alerts without the tenant's own domains and links."""
        indicators = extract_indicators(alert)
        if not isinstance(alert.get("email"), Mapping) or ctx.repos is None:
            return indicators
        try:
            tenant_settings = (await ctx.repos.tenants.get(ctx.tenant_id)).settings or {}
        except NotFound:
            tenant_settings = {}
        profile = PhishingProfile.from_settings(tenant_settings, ctx.settings.tools)
        if not profile.internal_domains:
            return indicators

        def internal(ind: Indicator) -> bool:
            if ind.type == "domain":
                return profile.is_internal(ind.value)
            if ind.type == "url":
                try:
                    return profile.is_internal(urlsplit(ind.value).hostname)
                except ValueError:
                    return False
            return False

        return [i for i in indicators if not internal(i)]

    async def run(
        self,
        ctx: AgentContext,
        alert: Mapping[str, Any],
        *,
        base_confidence: float,
        now: Optional[datetime] = None,
    ) -> CorrelationResult:
        async with AccountedRun(ctx):
            return await self._run(ctx, alert, base_confidence=base_confidence, now=now)

    async def _run(
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
        indicators = await self.indicators(ctx, alert)
        hashed = [(i, hmac_indicator(i.type, i.value, settings=ctx.settings)) for i in indicators]
        if hashed and ctx.persist:
            await ctx.repos.indicators.add_sightings(
                ctx.tenant_id, ctx.alert_id, [(i.type, h, i.display, now) for i, h in hashed]
            )
        related = await self._related(ctx, [(i.type, h) for i, h in hashed], now)

        type_counts: Dict[str, int] = {}
        for ind in indicators:
            type_counts[ind.type] = type_counts.get(ind.type, 0) + 1
        recent = [r for r in related if r.last_seen >= now - self.burst_window]
        burst = len(recent) >= self.burst_threshold
        per_hour = len(related) / max(self.window.total_seconds() / 3600.0, 1e-9)
        rule_score = self._rule_score(related, indicators, burst)
        confidence = max(0, min(100, round(base_confidence)))

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
            result.llm_skipped = self.skip_llm("no_related_alerts").skipped
            return result

        digests = await self.related_digests(ctx, related[:MAX_DIGESTS])
        for d in digests:
            key = str(d.get("disposition") or "undecided")
            result.related_dispositions[key] = result.related_dispositions.get(key, 0) + 1

        llm: LLMResult[CorrelationAssessment] = await self.call_llm(
            ctx,
            tier="fast",
            prompt=PROMPT,
            untrusted={
                "alert": self.alert_view(alert),
                "correlation": {
                    "related_alerts": len(related),
                    "max_shared_indicators": max(r.shared_indicator_count for r in related),
                    "burst": burst,
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "indicator_types": type_counts,
                },
                "related_alerts": digests,
            },
            enabled=self.enable_llm,
        )
        result.notes.extend(llm.notes)
        result.llm_skipped = llm.skipped
        result.llm_refusal = agent_refusal(llm, self.name)
        if llm.refused:
            grey = RoutingThresholds.from_settings(ctx.settings.routing).correlation_grey_zone_min
            result.confidence = max(result.confidence, grey)
            result.notes.append("correlation: model refused; confidence held in the grey zone for review")
        if llm.value is not None:
            result.llm_used = True
            result.score = max(
                0, min(100, round(rule_score * (1 - self.llm_weight) + llm.value.campaign_likelihood * self.llm_weight))
            )
            result.campaign_indicators = list(llm.value.attack_campaign_indicators)
        return result

    @staticmethod
    def alert_view(alert: Mapping[str, Any]) -> Dict[str, Any]:
        """The alert without its raw event: correlation reasons over entities and detections."""
        keys = ("title", "severity", "category", "description", "occurred_at", "source_id", "entities", "mitre")
        return {k: alert[k] for k in keys if k in alert}

    @staticmethod
    async def related_digests(ctx: AgentContext, related: List[Any]) -> List[Dict[str, Any]]:
        """Compact, bounded view of each related alert (no raw events, no ids)."""
        repos = ctx.repos
        if repos is None or not related:
            return []
        out: List[Dict[str, Any]] = []
        async with repos.db.tenant_tx(ctx.tenant_id) as conn:
            for idx, r in enumerate(related, start=1):
                try:
                    other = await repos.alerts.get(ctx.tenant_id, r.alert_id, conn=conn)
                except NotFound:
                    continue
                normalized = other.normalized if isinstance(other.normalized, Mapping) else {}
                mitre = normalized.get("mitre") if isinstance(normalized.get("mitre"), Mapping) else {}
                techniques = [str(t)[:40] for t in (mitre or {}).get("techniques") or [] if isinstance(t, (str, int))]
                verdict = other.summary.get("verdict") if isinstance(other.summary, Mapping) else None
                out.append(
                    {
                        "ref": f"r{idx}",
                        "title": other.title[:DIGEST_TITLE_CHARS],
                        "severity": other.severity,
                        "category": other.category,
                        "status": other.status,
                        "disposition": other.disposition,
                        "verdict": verdict if isinstance(verdict, str) else None,
                        "occurred_at": other.occurred_at.isoformat(),
                        "shared_indicators": r.shared_indicator_count,
                        "mitre_techniques": techniques[:5],
                    }
                )
        return out

    async def _related(self, ctx: AgentContext, keys: List[Tuple[str, str]], now: datetime) -> List[Any]:
        """Alerts sharing an indicator within the window. A sample waiting for its blind-audit label is left
        out: its disposition must not reach this alert's digest or the model (it is hidden until labelled)."""
        if not keys or ctx.repos is None:
            return []
        related = await ctx.repos.indicators.related_alerts(
            ctx.tenant_id, keys, since=now - self.window, limit=self.max_related, exclude_alert_id=ctx.alert_id
        )
        if not related:
            return []
        hidden = await ctx.repos.blind_audit.pending_alert_ids(ctx.tenant_id, [r.alert_id for r in related])
        return [r for r in related if r.alert_id not in hidden]

    @staticmethod
    def _rule_score(related: List[Any], indicators: List[Indicator], burst: bool) -> int:
        if not related:
            return 0
        weight = max((TYPE_WEIGHTS.get(i.type, 10) for i in indicators), default=10)
        score: int = sum(min(3, r.shared_indicator_count) * weight // 3 for r in related)
        if burst:
            score += 20
        return max(0, min(100, score))

