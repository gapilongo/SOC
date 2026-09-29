"""Internal history provider: how this tenant's earlier alerts with the same entity were decided.

Backed by the indicator-sighting index (HMAC-hashed values) and the alerts
repository, so nothing leaves the platform and no credentials are needed.
For one entity it reports how many earlier alerts in the look-back window
shared it and how they ended (dispositions, still-open alerts), with a few
compact examples.

Only human-backed outcomes decide the provider's verdict, because the
verdict becomes rule evidence (``prior_malicious_history``) for later alerts:

* ``malicious`` needs an analyst-confirmed true positive
  (``summary.analyst_decision == "true_positive"`` or a close reason of
  ``analyst:true_positive``);
* ``harmless`` needs at least two benign outcomes, all of them analyst
  decisions or analyst-made suppressions (analyst close reasons, suppression
  rules, the analyst verdict cache), and no malicious ones.

Dispositions reached by automation (``policy:response``, ``policy:close``,
``triage:false_positive``), which can rest on a model's verdict alone, are
reported as ``model_malicious``/``model_benign`` counts: the model sees them,
but they never become rule evidence, so one persuaded verdict cannot launder
itself into corroboration for every later alert about the same host or user.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, FrozenSet, List, Mapping, Optional

from lg_sotf.db.errors import NotFound
from lg_sotf.security.hashing import hmac_indicator
from lg_sotf.tools.enrichment.base import EnrichmentResult, LookupRequest, Verdict

MAX_HISTORY_ALERTS = 20
MAX_EXAMPLES = 3
OPEN_STATUSES = frozenset({"new", "queued", "processing", "waiting_human", "waiting_approval"})
# Close reasons written by the workflow's close node that stand for a human decision.
ANALYST_BENIGN_REASONS = frozenset(
    {"analyst:false_positive", "analyst:benign_positive", "suppression_rule", "verdict_cache"}
)
ANALYST_MALICIOUS_REASON = "analyst:true_positive"


def confirmed_outcome(disposition: Optional[str], summary: Any) -> Optional[str]:
    """``malicious``/``benign`` when a human stands behind the alert's disposition, else None."""
    if not disposition or not isinstance(summary, Mapping):
        return None
    reason = summary.get("close_reason")
    decision = summary.get("analyst_decision")
    if disposition == "malicious" and (decision == "true_positive" or reason == ANALYST_MALICIOUS_REASON):
        return "malicious"
    if disposition == "benign" and (
        decision in ("false_positive", "benign_positive") or reason in ANALYST_BENIGN_REASONS
    ):
        return "benign"
    return None


class HistoryProvider:
    name = "history"
    kinds: FrozenSet[str] = frozenset({"ip", "domain", "url", "hash", "user", "host", "process"})
    external = False

    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        cfg = dict(config or {})
        self.lookback = timedelta(days=max(1, min(365, int(cfg.get("lookback_days", 30)))))
        self.max_alerts = max(1, min(MAX_HISTORY_ALERTS, int(cfg.get("max_alerts", 10))))
        self.cache_ttl_s = float(cfg.get("cache_ttl_s", 60.0))

    def requires_credentials(self) -> bool:
        return False

    async def aclose(self) -> None:
        return None

    @staticmethod
    def verdict(confirmed: Mapping[str, int], dispositions: Optional[Mapping[str, int]] = None) -> Verdict:
        """From analyst-confirmed outcomes (see the module docs).

        ``harmless`` also needs every decided alert (``dispositions``, confirmed
        or not) to be benign: an automated malicious close is not evidence of
        malice, but it does rule out calling the entity's history harmless.
        """
        if confirmed.get("malicious", 0) > 0:
            return "malicious"
        benign = confirmed.get("benign", 0)
        decided = dispositions if dispositions is not None else confirmed
        if benign >= 2 and sum(confirmed.values()) == benign and sum(decided.values()) == decided.get("benign", 0):
            return "harmless"
        return "unknown"

    async def lookup(self, request: LookupRequest, *, now: Optional[datetime] = None) -> EnrichmentResult:
        if request.kind not in self.kinds:
            return EnrichmentResult.failed(self.name, request.kind, "unsupported")
        if request.repos is None:
            return EnrichmentResult.failed(self.name, request.kind, "not_configured", "no database access")
        repos = request.repos
        value_hash = hmac_indicator(request.kind, request.value, settings=request.settings)
        since = (now or datetime.now(UTC)) - self.lookback
        related = await repos.indicators.related_alerts(
            request.tenant_id,
            [(request.kind, value_hash)],
            since=since,
            limit=self.max_alerts,
            exclude_alert_id=request.exclude_alert_id,
        )
        if not related:
            return EnrichmentResult(self.name, request.kind, "not_found", "unknown", {"prior_alerts": 0})
        dispositions: Dict[str, int] = {}
        confirmed: Dict[str, int] = {}
        open_count = 0
        severities: Dict[str, int] = {}
        examples: List[str] = []
        last_seen = max(r.last_seen for r in related)
        async with repos.db.tenant_tx(request.tenant_id) as conn:
            for r in related:
                try:
                    alert = await repos.alerts.get(request.tenant_id, r.alert_id, conn=conn)
                except NotFound:
                    continue  # removed by retention since it was sighted
                if alert.disposition:
                    dispositions[alert.disposition] = dispositions.get(alert.disposition, 0) + 1
                    outcome = confirmed_outcome(alert.disposition, alert.summary)
                    if outcome is not None:
                        confirmed[outcome] = confirmed.get(outcome, 0) + 1
                if alert.status in OPEN_STATUSES:
                    open_count += 1
                severities[alert.severity] = severities.get(alert.severity, 0) + 1
                if len(examples) < MAX_EXAMPLES:
                    label = alert.disposition or alert.status
                    if alert.disposition and confirmed_outcome(alert.disposition, alert.summary) is not None:
                        label = f"{alert.disposition} (analyst)"
                    examples.append(f"{alert.severity}/{label}: {alert.title[:80]}")
        data: Dict[str, Any] = {
            "prior_alerts": len(related),
            "confirmed_malicious": confirmed.get("malicious", 0),
            "confirmed_benign": confirmed.get("benign", 0),
            "model_malicious": dispositions.get("malicious", 0) - confirmed.get("malicious", 0),
            "model_benign": dispositions.get("benign", 0) - confirmed.get("benign", 0),
            "inconclusive": dispositions.get("inconclusive", 0),
            "open": open_count,
            "high_or_critical": severities.get("high", 0) + severities.get("critical", 0),
            "last_seen": last_seen.date().isoformat(),
            "lookback_days": self.lookback.days,
            "examples": examples,
        }
        return EnrichmentResult.ok(self.name, request.kind, self.verdict(confirmed, dispositions), data)
