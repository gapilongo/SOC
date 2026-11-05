"""Value, accuracy and detection-tuning reports (``/reports/*``) and their metric definitions.

Everything here is measured on the tenant's own data. The definitions are
also in ``docs/reporting.md``; keep the two in sync.

Value (per alert, cohort = alerts *ingested* in the window, bucketed by UTC day):

* ``handled_without_human``: closed with no analyst decision and no person
  approving or rejecting a response action. Suppression-rule and
  verdict-cache closes count here (a person wrote the rule or made the
  earlier decision, but nobody looked at *this* alert); they are also
  broken out as ``suppressed_by_rule`` / ``verdict_cache_hits``.
* ``needed_human``: an analyst decided it, a person approved or rejected one
  of its actions, or it is waiting for an analyst or an approval.
* ``in_progress``: neither yet (new, queued, processing, failed).
* ``handled_without_human_rate`` = handled / (handled + needed); ``None``
  when both are zero. Alerts still in progress are left out rather than
  counted either way.
* ``analyst_hours_saved`` = handled * ``reporting.minutes_per_alert`` / 60.
  An estimate: it assumes every alert automation handled would otherwise
  have cost an analyst that many minutes, and credits nothing for the
  enrichment and summaries prepared on escalated alerts.
* ``auto_closed_benign``: handled and closed as benign. ``auto_contained``:
  handled and closed as malicious after a policy response whose actions
  completed through a connector; ``auto_contained_dry_run`` the same in
  dry-run mode (nothing was changed on a real system).
* ``mean_time_to_verdict_s``: ingestion to the first automated verdict (the
  triage agent finishing, or the close for alerts the gate closed before
  triage). ``mttr_s``: ingestion to close, over the cohort's closed alerts
  (``mttr_auto_s`` / ``mttr_human_s`` split it). ``mtta_s``: escalation
  created to claimed, over escalations *created* in the window.
* ``sla_breaches``: SLA sweep actions in the window (an escalation raised a
  level or expired), from the audit log.
* ``llm_cost_per_alert_usd``: LLM cost recorded on the window's days over
  alerts ingested in the window.

Accuracy (alerts whose analyst decision was recorded in the window):

* the analyst class is the alert's latest decision other than
  ``needs_more_info``: ``true_positive`` -> ``malicious``,
  ``false_positive``/``benign_positive`` -> ``benign``;
* the AI class is the analysis verdict on the alert's *first* escalation
  (what the model concluded before any analyst input); without a verdict,
  the escalation's threat score (or confidence) banded with the routing
  thresholds: below ``close_max_threat`` -> ``benign``, from
  ``response_threshold`` -> ``malicious``, between -> ``inconclusive``;
* headline ``false_negative_rate``: AI ``benign`` among analyst
  ``malicious``. ``agreement_rate``: AI class equals analyst class over all
  samples (an ``inconclusive`` AI verdict never agrees);
* fewer than :data:`MIN_ACCURACY_SAMPLES` samples is ``insufficient_data``.

Only escalated alerts have an analyst decision, so accuracy describes the
alerts the AI sent to a human, not the ones it closed on its own.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, fields
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple, Type, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis.exceptions import RedisError

from lg_sotf.core.routing import RoutingThresholds
from lg_sotf.db.repos.alerts import SEVERITIES
from lg_sotf.db.repos.feedback import FeedbackStats
from lg_sotf.db.repos.reports import AccuracyGroupRow, DetectionRow, EscalationDayRow, ValueDayRow
from lg_sotf.llm.pricing import LOCAL_PREFIX
from lg_sotf.observability.logging import get_logger

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)

DEFAULT_MINUTES_PER_ALERT = 15
MAX_MINUTES_PER_ALERT = 480
DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 366
CACHE_TTL_S = 60
MIN_ACCURACY_SAMPLES = 30
MIN_FEEDBACK_SAMPLES = 10
DETECTION_LIMIT = 200
# Detection suggestions (see detection_suggestion).
MIN_DECIDED_FOR_SUGGESTION = 10
TUNE_BENIGN_RATE = 0.80
SUPPRESSION_BENIGN_RATE = 0.95
MIN_CONFIRMED_BENIGN = 3
Z_95 = 1.959963984540054

AnalystClass = Literal["malicious", "benign"]
AiClass = Literal["malicious", "benign", "inconclusive"]
ANALYST_CLASSES: Tuple[str, ...] = ("malicious", "benign")
AI_CLASSES: Tuple[str, ...] = ("malicious", "benign", "inconclusive")
BENIGN_DECISIONS = frozenset({"false_positive", "benign_positive"})
Suggestion = Literal["tune_rule", "candidate_suppression"]


class ReportWindowError(ValueError):
    """The requested window is invalid (message is safe to return to the client)."""


# ---------------------------------------------------------------- settings


class ReportingPolicy(BaseModel):
    """Tenant setting ``reporting``: ``{"minutes_per_alert": 15}``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minutes_per_alert: int = Field(default=DEFAULT_MINUTES_PER_ALERT, ge=1, le=MAX_MINUTES_PER_ALERT, strict=True)


def resolve_reporting_policy(tenant_settings: Optional[Mapping[str, Any]]) -> ReportingPolicy:
    """The tenant's reporting policy; a missing or invalid section gives the defaults."""
    section = (tenant_settings or {}).get("reporting")
    if not isinstance(section, Mapping):
        return ReportingPolicy()
    try:
        return ReportingPolicy.model_validate(dict(section))
    except ValidationError:
        log.warning("reporting.invalid_tenant_policy")
        return ReportingPolicy()


# ------------------------------------------------------------------ window


@dataclass(frozen=True)
class ReportWindow:
    """Whole UTC days ``start`` .. ``end`` (inclusive)."""

    start: date
    end: date

    @property
    def since(self) -> datetime:
        return datetime.combine(self.start, time.min, tzinfo=UTC)

    @property
    def until(self) -> datetime:
        return datetime.combine(self.end + timedelta(days=1), time.min, tzinfo=UTC)

    @property
    def days(self) -> int:
        return (self.end - self.start).days + 1

    def each_day(self) -> List[date]:
        return [self.start + timedelta(days=i) for i in range(self.days)]


def resolve_window(start: Optional[date], end: Optional[date], *, today: Optional[date] = None) -> ReportWindow:
    """``from``/``to`` query values to a window: default the last 30 days, at most 366."""
    end = end or today or datetime.now(UTC).date()
    start = start or end - timedelta(days=DEFAULT_WINDOW_DAYS - 1)
    if end < start:
        raise ReportWindowError("'to' must not be before 'from'")
    if (end - start).days + 1 > MAX_WINDOW_DAYS:
        raise ReportWindowError(f"at most {MAX_WINDOW_DAYS} days per report")
    return ReportWindow(start, end)


def month_window(month: str) -> ReportWindow:
    """``YYYY-MM`` to the window of that calendar month."""
    try:
        first = datetime.strptime(month, "%Y-%m").date()  # noqa: DTZ007 - only the date part is kept
    except ValueError as exc:
        raise ReportWindowError("month must be YYYY-MM") from exc
    if first.year < 2000:
        raise ReportWindowError("month must be YYYY-MM")
    following = date(first.year + (first.month == 12), first.month % 12 + 1, 1)
    return ReportWindow(first, following - timedelta(days=1))


# -------------------------------------------------------------- pure math


def ratio(numerator: float, denominator: float) -> Optional[float]:
    """``numerator / denominator``; ``None`` (never 0) when the denominator is zero."""
    return None if denominator == 0 else numerator / denominator


def mean_or_none(total: float, count: int) -> Optional[float]:
    return None if count == 0 else total / count


def hours_saved(handled_without_human: int, minutes_per_alert: int) -> float:
    """Estimated analyst hours saved: handled alerts times the per-alert minutes the tenant set."""
    if handled_without_human <= 0 or minutes_per_alert <= 0:
        return 0.0
    return round(handled_without_human * minutes_per_alert / 60.0, 2)


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> Optional[Tuple[float, float]]:
    """95 % Wilson score interval for a proportion; ``None`` without trials."""
    if trials <= 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and trials")
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, round(centre - half, 6)), min(1.0, round(centre + half, 6)))


def severity_name(rank: Optional[int]) -> Optional[str]:
    if rank is None or not 0 <= rank < len(SEVERITIES):
        return None
    return SEVERITIES[rank]


def analyst_class(decision: str) -> Optional[AnalystClass]:
    if decision == "true_positive":
        return "malicious"
    if decision in BENIGN_DECISIONS:
        return "benign"
    return None


def ai_class(verdict: Optional[str], score_band: Optional[str]) -> AiClass:
    """The AI's verdict class: the analysis verdict, else the banded threat score/confidence."""
    if verdict in AI_CLASSES:
        return verdict  # type: ignore[return-value]
    if score_band == "high":
        return "malicious"
    if score_band == "low":
        return "benign"
    return "inconclusive"


def model_key(row: AccuracyGroupRow) -> str:
    """``provider/model`` of the analysis agent (else triage); rules-only and unrecorded alerts apart.

    Self-hosted models are recorded as ``local/<model>`` (the usage id); the
    provider already says where it ran, so ``ollama/local/x`` becomes
    ``ollama/x``, the same key as rows recorded before the ids were aligned.
    """
    for provider, model in ((row.analysis_provider, row.analysis_model), (row.triage_provider, row.triage_model)):
        if model:
            return f"{provider}/{model.removeprefix(LOCAL_PREFIX)}" if provider else model
    return "unrecorded" if row.llm_used else "rules only"


# ------------------------------------------------------------------- value


@dataclass
class ValueSums:
    """Additive counters and duration sums; per day or for the whole window."""

    ingested: int = 0
    handled_without_human: int = 0
    needed_human: int = 0
    auto_closed_benign: int = 0
    auto_contained: int = 0
    auto_contained_dry_run: int = 0
    escalated: int = 0
    human_decided: int = 0
    suppressed_by_rule: int = 0
    verdict_cache_hits: int = 0
    grouped_into_escalation: int = 0
    resolved: int = 0
    resolve_seconds: float = 0.0
    resolved_auto: int = 0
    resolve_auto_seconds: float = 0.0
    resolved_human: int = 0
    resolve_human_seconds: float = 0.0
    verdicts: int = 0
    verdict_seconds: float = 0.0
    escalations: int = 0
    acknowledged: int = 0
    ack_seconds: float = 0.0
    sla_breaches: int = 0
    llm_cost_usd: Decimal = Decimal(0)

    def add(self, other: ValueSums) -> None:
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name))

    @classmethod
    def from_rows(
        cls,
        value: Optional[ValueDayRow] = None,
        escalations: Optional[EscalationDayRow] = None,
        sla_breaches: int = 0,
        llm_cost_usd: Decimal = Decimal(0),
    ) -> ValueSums:
        sums = cls(sla_breaches=sla_breaches, llm_cost_usd=llm_cost_usd)
        if value is not None:
            for f in fields(cls):
                if f.name in ValueDayRow.model_fields and f.name != "day":
                    setattr(sums, f.name, getattr(value, f.name))
        if escalations is not None:
            sums.escalations = escalations.escalations
            sums.acknowledged = escalations.acknowledged
            sums.ack_seconds = escalations.ack_seconds
        return sums


class ValueMetrics(BaseModel):
    alerts_ingested: int
    handled_without_human: int
    needed_human: int
    in_progress: int
    handled_without_human_rate: Optional[float]
    analyst_hours_saved: float
    auto_closed_benign: int
    auto_contained: int
    auto_contained_dry_run: int
    escalated: int
    human_decided: int
    suppressed_by_rule: int
    verdict_cache_hits: int
    grouped_into_escalation: int
    mean_time_to_verdict_s: Optional[float]
    verdicts: int
    mtta_s: Optional[float]
    escalations_created: int
    acknowledged: int
    mttr_s: Optional[float]
    mttr_auto_s: Optional[float]
    mttr_human_s: Optional[float]
    resolved: int
    sla_breaches: int
    llm_cost_usd: float
    llm_cost_per_alert_usd: Optional[float]


def value_metrics(s: ValueSums, minutes_per_alert: int) -> ValueMetrics:
    """Derived value metrics from additive sums (see the module docstring for definitions)."""
    decided = s.handled_without_human + s.needed_human
    cost = float(s.llm_cost_usd)
    return ValueMetrics(
        alerts_ingested=s.ingested,
        handled_without_human=s.handled_without_human,
        needed_human=s.needed_human,
        in_progress=max(0, s.ingested - decided),
        handled_without_human_rate=ratio(s.handled_without_human, decided),
        analyst_hours_saved=hours_saved(s.handled_without_human, minutes_per_alert),
        auto_closed_benign=s.auto_closed_benign,
        auto_contained=s.auto_contained,
        auto_contained_dry_run=s.auto_contained_dry_run,
        escalated=s.escalated,
        human_decided=s.human_decided,
        suppressed_by_rule=s.suppressed_by_rule,
        verdict_cache_hits=s.verdict_cache_hits,
        grouped_into_escalation=s.grouped_into_escalation,
        mean_time_to_verdict_s=mean_or_none(s.verdict_seconds, s.verdicts),
        verdicts=s.verdicts,
        mtta_s=mean_or_none(s.ack_seconds, s.acknowledged),
        escalations_created=s.escalations,
        acknowledged=s.acknowledged,
        mttr_s=mean_or_none(s.resolve_seconds, s.resolved),
        mttr_auto_s=mean_or_none(s.resolve_auto_seconds, s.resolved_auto),
        mttr_human_s=mean_or_none(s.resolve_human_seconds, s.resolved_human),
        resolved=s.resolved,
        sla_breaches=s.sla_breaches,
        llm_cost_usd=round(cost, 6),
        llm_cost_per_alert_usd=None if s.ingested == 0 else round(cost / s.ingested, 6),
    )


class ValueDay(ValueMetrics):
    day: date


class ValueReport(BaseModel):
    start: date = Field(serialization_alias="from")
    end: date = Field(serialization_alias="to")
    generated_at: datetime
    minutes_per_alert: int
    totals: ValueMetrics
    escalations_breached: int
    days: List[ValueDay]
    notes: List[str]

    model_config = ConfigDict(populate_by_name=True)


VALUE_NOTES = (
    "Analyst hours saved is an estimate: alerts handled without a human times the tenant's "
    "reporting.minutes_per_alert, divided by 60. It credits nothing for work prepared on escalated alerts "
    "and assumes each handled alert would otherwise have taken an analyst that long.",
    "Alerts are counted on the day they were ingested; alerts still in progress are left out of the "
    "handled-without-human rate. LLM cost is counted on the day the calls were made.",
    "Duplicate events are dropped at ingestion and never stored; they are counted only in the Prometheus "
    "metric lgsotf_ingest_events_total{outcome=\"duplicate\"}. The report shows alerts closed by a "
    "suppression rule or a cached analyst verdict and alerts grouped into an existing escalation.",
)


def build_value_report(
    window: ReportWindow,
    *,
    value_rows: Sequence[ValueDayRow],
    escalation_rows: Sequence[EscalationDayRow],
    sla_by_day: Mapping[date, int],
    escalations_breached: int,
    cost_by_day: Mapping[date, Decimal],
    minutes_per_alert: int,
    generated_at: datetime,
) -> ValueReport:
    """Assemble the daily series (every day of the window, zeros included) and the totals."""
    values = {r.day: r for r in value_rows}
    escalations = {r.day: r for r in escalation_rows}
    totals = ValueSums()
    days: List[ValueDay] = []
    for day in window.each_day():
        sums = ValueSums.from_rows(
            values.get(day), escalations.get(day), sla_by_day.get(day, 0), cost_by_day.get(day, Decimal(0))
        )
        totals.add(sums)
        days.append(ValueDay(day=day, **value_metrics(sums, minutes_per_alert).model_dump()))
    return ValueReport(
        start=window.start,
        end=window.end,
        generated_at=generated_at,
        minutes_per_alert=minutes_per_alert,
        totals=value_metrics(totals, minutes_per_alert),
        escalations_breached=escalations_breached,
        days=days,
        notes=list(VALUE_NOTES),
    )


# ---------------------------------------------------------------- accuracy


class AccuracyBlock(BaseModel):
    samples: int
    status: Literal["ok", "insufficient_data"]
    confusion_matrix: Dict[str, Dict[str, int]]
    agreement: int
    agreement_rate: Optional[float]
    agreement_ci95: Optional[Tuple[float, float]]
    analyst_malicious: int
    false_negatives: int
    false_negative_rate: Optional[float]
    false_negative_ci95: Optional[Tuple[float, float]]
    analyst_benign: int
    false_positives: int
    false_positive_rate: Optional[float]
    ai_inconclusive: int
    ai_inconclusive_rate: Optional[float]


class ModelAccuracy(BaseModel):
    model: str
    accuracy: AccuracyBlock


class FeedbackRate(BaseModel):
    rate: Optional[float]
    samples: int
    status: Literal["ok", "insufficient_data"]


class FeedbackSummary(BaseModel):
    total: int
    by_decision: Dict[str, int]
    triage_correct: FeedbackRate
    analysis_accurate: FeedbackRate
    correlation_helpful: FeedbackRate
    avg_review_duration_s: Optional[float]


class AccuracyReport(BaseModel):
    start: date = Field(serialization_alias="from")
    end: date = Field(serialization_alias="to")
    generated_at: datetime
    min_samples: int
    low_score_below: float
    high_score_from: float
    overall: AccuracyBlock
    by_model: List[ModelAccuracy]
    feedback: FeedbackSummary
    notes: List[str]

    model_config = ConfigDict(populate_by_name=True)


ACCURACY_NOTES = (
    "Only alerts escalated to an analyst have an analyst decision, so this measures the AI on the alerts it "
    "sent to a human, not on the ones it closed on its own. A low false-negative rate here does not prove "
    "that no threat was auto-closed; use the backtest (lg-sotf eval --from-history) for that question.",
    "The AI verdict is the one on the alert's first escalation, before any analyst input; the analyst "
    "class is the alert's latest decision other than needs_more_info.",
    "Ranges are 95% Wilson intervals. With fewer samples than min_samples the result is marked "
    "insufficient_data: the rates are shown but should not be relied on.",
)


def accuracy_block(pairs: Mapping[Tuple[str, str], int], min_samples: int = MIN_ACCURACY_SAMPLES) -> AccuracyBlock:
    """Accuracy figures from ``{(analyst_class, ai_class): count}``."""
    matrix = {a: {p: 0 for p in AI_CLASSES} for a in ANALYST_CLASSES}
    for (actual, predicted), n in pairs.items():
        if actual in matrix and predicted in matrix[actual] and n > 0:
            matrix[actual][predicted] += n
    samples = sum(sum(row.values()) for row in matrix.values())
    agreement = matrix["malicious"]["malicious"] + matrix["benign"]["benign"]
    analyst_malicious = sum(matrix["malicious"].values())
    analyst_benign = sum(matrix["benign"].values())
    false_negatives = matrix["malicious"]["benign"]
    false_positives = matrix["benign"]["malicious"]
    inconclusive = matrix["malicious"]["inconclusive"] + matrix["benign"]["inconclusive"]
    return AccuracyBlock(
        samples=samples,
        status="ok" if samples >= min_samples else "insufficient_data",
        confusion_matrix=matrix,
        agreement=agreement,
        agreement_rate=ratio(agreement, samples),
        agreement_ci95=wilson_interval(agreement, samples),
        analyst_malicious=analyst_malicious,
        false_negatives=false_negatives,
        false_negative_rate=ratio(false_negatives, analyst_malicious),
        false_negative_ci95=wilson_interval(false_negatives, analyst_malicious),
        analyst_benign=analyst_benign,
        false_positives=false_positives,
        false_positive_rate=ratio(false_positives, analyst_benign),
        ai_inconclusive=inconclusive,
        ai_inconclusive_rate=ratio(inconclusive, samples),
    )


def feedback_rate(rate: Optional[float], samples: int) -> FeedbackRate:
    return FeedbackRate(
        rate=rate, samples=samples, status="ok" if samples >= MIN_FEEDBACK_SAMPLES else "insufficient_data"
    )


def build_accuracy_report(
    window: ReportWindow,
    *,
    groups: Sequence[AccuracyGroupRow],
    feedback: FeedbackStats,
    thresholds: RoutingThresholds,
    generated_at: datetime,
    min_samples: int = MIN_ACCURACY_SAMPLES,
) -> AccuracyReport:
    overall: Dict[Tuple[str, str], int] = {}
    per_model: Dict[str, Dict[Tuple[str, str], int]] = {}
    for g in groups:
        actual = analyst_class(g.decision)
        if actual is None:
            continue
        key = (actual, ai_class(g.verdict, g.score_band))
        overall[key] = overall.get(key, 0) + g.n
        bucket = per_model.setdefault(model_key(g), {})
        bucket[key] = bucket.get(key, 0) + g.n
    by_model = [
        ModelAccuracy(model=name, accuracy=accuracy_block(pairs, min_samples))
        for name, pairs in per_model.items()
    ]
    by_model.sort(key=lambda m: (-m.accuracy.samples, m.model))
    return AccuracyReport(
        start=window.start,
        end=window.end,
        generated_at=generated_at,
        min_samples=min_samples,
        low_score_below=float(thresholds.close_max_threat),
        high_score_from=float(thresholds.response_threshold),
        overall=accuracy_block(overall, min_samples),
        by_model=by_model,
        feedback=FeedbackSummary(
            total=feedback.total,
            by_decision=dict(feedback.by_decision),
            triage_correct=feedback_rate(feedback.triage_accuracy, feedback.triage_rated),
            analysis_accurate=feedback_rate(feedback.analysis_accuracy, feedback.analysis_rated),
            correlation_helpful=feedback_rate(feedback.correlation_helpful_rate, feedback.correlation_rated),
            avg_review_duration_s=feedback.avg_review_duration_s,
        ),
        notes=list(ACCURACY_NOTES),
    )


# -------------------------------------------------------------- detections


class Detection(BaseModel):
    source_id: str
    rule_field: Literal["rule_name", "title"]
    rule: str
    volume: int
    decided: int
    benign: int
    benign_rate: Optional[float]
    malicious: int
    auto_closed: int
    analyst_false_positive: int
    analyst_benign_positive: int
    analyst_true_positive: int
    median_severity: Optional[str]
    max_severity: Optional[str]
    max_confirmed_benign_severity: Optional[str]
    suggestion: Optional[Suggestion]
    reason: str
    can_propose_suppression: bool


class DetectionsReport(BaseModel):
    start: date = Field(serialization_alias="from")
    end: date = Field(serialization_alias="to")
    generated_at: datetime
    detections: List[Detection]
    truncated: bool
    limit: int
    notes: List[str]

    model_config = ConfigDict(populate_by_name=True)


DETECTION_NOTES = (
    "A detection is a source plus its rule name (the alert title when the source sends no rule name).",
    "Suggestions are heuristics over the window; a suppression proposal is created disabled and only an "
    "admin can enable it.",
)


def _pct(value: float) -> str:
    return f"{100 * value:.0f}%"


def detection_suggestion(row: DetectionRow) -> Tuple[Optional[Suggestion], str]:
    """``tune_rule`` / ``candidate_suppression`` (or none) and the reasoning shown to the analyst."""
    confirmed = row.analyst_false_positive + row.analyst_benign_positive
    if row.decided < MIN_DECIDED_FOR_SUGGESTION:
        return None, (
            f"{row.decided} decided alert(s); at least {MIN_DECIDED_FOR_SUGGESTION} are needed before suggesting "
            "a change."
        )
    rate = row.benign / row.decided
    if rate < TUNE_BENIGN_RATE:
        return None, (
            f"{_pct(rate)} of {row.decided} decided alerts were benign and {row.malicious} malicious: the "
            "detection finds real activity often enough to keep as it is."
        )
    median = row.median_severity_rank if row.median_severity_rank is not None else 0
    high = SEVERITIES.index("high")
    if (
        rate >= SUPPRESSION_BENIGN_RATE
        and row.malicious == 0
        and row.analyst_true_positive == 0
        and confirmed >= MIN_CONFIRMED_BENIGN
        and median < high
    ):
        ceiling = severity_name(row.max_confirmed_benign_rank) or "info"
        return "candidate_suppression", (
            f"{_pct(rate)} of {row.decided} decided alerts were benign, {confirmed} confirmed by an analyst, and "
            f"none was malicious. A suppression rule for this detection (severity up to {ceiling}) would close "
            "these without analyst or model time; review what it would hide before enabling it."
        )
    if row.malicious or row.analyst_true_positive:
        why = (
            f"but {row.malicious} were malicious ({row.analyst_true_positive} confirmed by an analyst), so a "
            "suppression would hide real threats"
        )
    elif median >= high:
        why = f"but its median severity is {severity_name(median)}, too high to suppress wholesale"
    elif confirmed < MIN_CONFIRMED_BENIGN:
        why = (
            f"but only {confirmed} were confirmed by an analyst (the rest were closed by automation), which is "
            "not enough evidence for a suppression"
        )
    else:
        why = f"but {_pct(rate)} is below the {_pct(SUPPRESSION_BENIGN_RATE)} bar for a suppression"
    return "tune_rule", (
        f"{_pct(rate)} of {row.decided} decided alerts were benign, {why}. Tune the rule at the source "
        "(exclusions, thresholds, scope) to cut the noise."
    )


def detection_out(row: DetectionRow) -> Detection:
    suggestion, reason = detection_suggestion(row)
    return Detection(
        source_id=row.source_id,
        rule_field=row.rule_field,
        rule=row.rule,
        volume=row.volume,
        decided=row.decided,
        benign=row.benign,
        benign_rate=ratio(row.benign, row.decided),
        malicious=row.malicious,
        auto_closed=row.auto_closed,
        analyst_false_positive=row.analyst_false_positive,
        analyst_benign_positive=row.analyst_benign_positive,
        analyst_true_positive=row.analyst_true_positive,
        median_severity=severity_name(row.median_severity_rank),
        max_severity=severity_name(row.max_severity_rank),
        max_confirmed_benign_severity=severity_name(row.max_confirmed_benign_rank),
        suggestion=suggestion,
        reason=reason,
        can_propose_suppression=row.max_confirmed_benign_rank is not None,
    )


def suppression_match(row: DetectionRow) -> Dict[str, Any]:
    """Rule predicates for a detection: its source and rule, bounded to the analyst-confirmed benign severity.

    Like the suggestions made from false-positive decisions, the rule never
    covers a severity above the highest one an analyst judged benign.
    """
    if row.max_confirmed_benign_rank is None:
        raise ValueError("no analyst-confirmed benign alert bounds the rule's severity")
    severities = list(SEVERITIES[: row.max_confirmed_benign_rank + 1])
    return {"source_id": row.source_id, row.rule_field: row.rule, "severity": {"in": severities}}


def build_detections_report(
    window: ReportWindow, rows: Sequence[DetectionRow], *, limit: int, generated_at: datetime
) -> DetectionsReport:
    return DetectionsReport(
        start=window.start,
        end=window.end,
        generated_at=generated_at,
        detections=[detection_out(r) for r in rows],
        truncated=len(rows) >= limit,
        limit=limit,
        notes=list(DETECTION_NOTES),
    )


# ------------------------------------------------------------------ monthly


class MonthlyReport(BaseModel):
    tenant_id: str
    tenant_name: str
    month: str
    generated_at: datetime
    value: ValueReport
    accuracy: AccuracyReport
    detections: DetectionsReport


# ------------------------------------------------------------------ service

M = TypeVar("M", bound=BaseModel)


class ReportService:
    """Builds the reports from :class:`~lg_sotf.db.repos.reports.ReportsRepo` aggregates, cached in Redis.

    Results are cached per tenant, report kind and window for
    :data:`CACHE_TTL_S` seconds (``{prefix}:t:{tenant}:cache:reports:...``);
    Redis being unavailable only disables the cache.
    """

    def __init__(
        self, repos: Repositories, redis: Any, prefix: str, thresholds: RoutingThresholds, *, ttl_s: int = CACHE_TTL_S
    ) -> None:
        self._repos = repos
        self._redis = redis
        self._prefix = prefix
        self._thresholds = thresholds
        self._ttl = ttl_s

    def cache_key(self, tenant_id: str, kind: str, window: ReportWindow, extra: str = "") -> str:
        return (
            f"{self._prefix}:t:{tenant_id}:cache:reports:{kind}:"
            f"{window.start.isoformat()}:{window.end.isoformat()}{':' + extra if extra else ''}"
        )

    async def _cached(self, key: str, model: Type[M]) -> Optional[M]:
        try:
            raw = await self._redis.get(key)
            return None if raw is None else model.model_validate_json(raw)
        except (RedisError, OSError, TimeoutError, ValueError) as exc:
            log.warning("reports.cache_unavailable", error_type=type(exc).__name__)
            return None

    async def _store(self, key: str, value: BaseModel) -> None:
        try:
            await self._redis.set(key, value.model_dump_json().encode(), ex=self._ttl)
        except (RedisError, OSError, TimeoutError) as exc:
            log.warning("reports.cache_unavailable", error_type=type(exc).__name__)

    async def value(self, tenant_id: str, window: ReportWindow, *, minutes_per_alert: int) -> ValueReport:
        key = self.cache_key(tenant_id, "value", window, f"m{minutes_per_alert}")
        cached = await self._cached(key, ValueReport)
        if cached is not None:
            return cached
        reports = self._repos.reports
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            value_rows = await reports.value_daily(tenant_id, window.since, window.until, conn=conn)
            escalation_rows = await reports.escalations_daily(tenant_id, window.since, window.until, conn=conn)
            sla_by_day, breached = await reports.sla_breaches_daily(tenant_id, window.since, window.until, conn=conn)
            cost_by_day = await reports.llm_cost_daily(tenant_id, window.start, window.end, conn=conn)
        report = build_value_report(
            window,
            value_rows=value_rows,
            escalation_rows=escalation_rows,
            sla_by_day=sla_by_day,
            escalations_breached=breached,
            cost_by_day=cost_by_day,
            minutes_per_alert=minutes_per_alert,
            generated_at=datetime.now(UTC),
        )
        await self._store(key, report)
        return report

    async def accuracy(self, tenant_id: str, window: ReportWindow) -> AccuracyReport:
        key = self.cache_key(tenant_id, "accuracy", window)
        cached = await self._cached(key, AccuracyReport)
        if cached is not None:
            return cached
        t = self._thresholds
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            groups = await self._repos.reports.accuracy_groups(
                tenant_id,
                window.since,
                window.until,
                low_score=t.close_max_threat,
                high_score=t.response_threshold,
                conn=conn,
            )
            feedback = await self._repos.feedback.decision_stats(
                tenant_id, window.since, until=window.until, conn=conn
            )
        report = build_accuracy_report(
            window, groups=groups, feedback=feedback, thresholds=t, generated_at=datetime.now(UTC)
        )
        await self._store(key, report)
        return report

    async def detections(self, tenant_id: str, window: ReportWindow, *, limit: int = DETECTION_LIMIT) -> DetectionsReport:
        key = self.cache_key(tenant_id, "detections", window, f"l{limit}")
        cached = await self._cached(key, DetectionsReport)
        if cached is not None:
            return cached
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            rows = await self._repos.reports.detections(tenant_id, window.since, window.until, limit=limit, conn=conn)
        report = build_detections_report(window, rows, limit=limit, generated_at=datetime.now(UTC))
        await self._store(key, report)
        return report

    async def monthly(
        self, tenant_id: str, tenant_name: str, month: str, *, minutes_per_alert: int
    ) -> MonthlyReport:
        window = month_window(month)
        return MonthlyReport(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            month=month,
            generated_at=datetime.now(UTC),
            value=await self.value(tenant_id, window, minutes_per_alert=minutes_per_alert),
            accuracy=await self.accuracy(tenant_id, window),
            detections=await self.detections(tenant_id, window),
        )
