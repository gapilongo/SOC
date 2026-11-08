"""Shadow agreement report (AI-E1.5b): a candidate's verdicts against production's, alert by alert.

A shadow replay (``lg-sotf shadow-run``) runs a candidate (another model
profile) on alerts production already decided, in shadow mode, and stores
one :class:`Comparison` per alert: what production decided and what the
candidate would have decided. This module turns those rows into the
report. It is pure: no I/O, the same input gives the same report.

The verdict compared is the routing decision after analysis (``close``,
``plan_response`` or ``escalate``): what the platform does with the alert
without a human. Agreement is the share of alerts with a production verdict
on which the candidate *usably* took the same route, with its sample size
and 95% Wilson interval (:mod:`lg_sotf.domain.rates`), overall and per
production route.

A candidate run with no usable verdict is a **failure** and counts as a
disagreement, never as a smaller sample: the run raised (``error``), or its
model answer was unusable or refused and the rules decided instead
(``degraded``). A broken candidate therefore cannot score well by failing
on the hard alerts. The agreement over the usable verdicts alone is shown
next to the headline, never instead of it. The report is not ``enough_data``
below ``min_samples``, above :data:`MAX_FAILURE_RATE` failures, or when any
alert production escalated or responded to failed.

The cases that matter are listed, worst first:

* **potential misses**: production escalated or responded, the candidate
  would have closed the alert with no human;
* **routing differences** between ``escalate`` and ``plan_response``, the
  candidate acting automatically where production wanted a human first;
* **candidate failures**, most severe first;
* **new escalations**: production closed the alert, the candidate would have
  escalated or responded (more analyst work, or a possible catch);
* **plan differences**: both responded automatically, with different actions.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.domain.rates import RateInterval, format_rate, not_enough_data, rate_interval
from lg_sotf.models.vocabulary import ROUTES, SEVERITY_RANK

NO_VERDICT = "none"
"""The candidate's confusion-matrix label when it has no usable verdict (failed or degraded run)."""
LABELS: Tuple[str, ...] = (*ROUTES, NO_VERDICT)
HUMAN_OR_RESPONSE = frozenset({"escalate", "plan_response"})
MIN_AGREEMENT_SAMPLES = 30
MAX_FAILURE_RATE = 0.05
"""Above this share of failed candidate runs the report is not ``enough_data``, whatever n is."""
MAX_LISTED_CASES = 100
MAX_ACTIONS = 20
_COST_DIGITS = 6


class Verdict(BaseModel):
    """One side's verdict on an alert; ``route`` is ``None`` when that side has none (``error`` says why)."""

    model_config = ConfigDict(frozen=True)

    route: Optional[str] = None
    disposition: Optional[str] = None
    confidence: Optional[float] = None
    actions: Tuple[str, ...] = ()
    """Planned response actions as ``action_type:target``, sorted (at most :data:`MAX_ACTIONS`)."""
    tokens: int = 0
    cost_usd: Decimal = Decimal(0)
    latency_ms: int = 0
    """Model and tool time (the sum of the run's trace steps), not queueing or database time."""
    error: Optional[str] = None
    degraded: int = 0
    """Agent steps whose model answer was unusable or refused, so the rules decided instead."""


class Comparison(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str
    severity: str
    production: Verdict
    candidate: Verdict


class ShadowCase(BaseModel):
    """One alert on which the two verdicts differ, as the report lists it."""

    alert_id: str
    severity: str
    production_route: Optional[str]
    candidate_route: Optional[str]
    production_disposition: Optional[str]
    candidate_disposition: Optional[str]
    production_confidence: Optional[float]
    candidate_confidence: Optional[float]
    production_actions: List[str]
    candidate_actions: List[str]
    candidate_error: Optional[str] = None
    candidate_degraded: int = 0


class ShadowCaseList(BaseModel):
    count: int
    items: List[ShadowCase] = Field(description=f"Worst first, at most {MAX_LISTED_CASES}.")


class ShadowClassAgreement(BaseModel):
    production_route: str
    agreement: RateInterval
    text: str


class ShadowDelta(BaseModel):
    """Per-alert means over the usable comparisons; ``delta`` is candidate minus production."""

    production_mean: Optional[float]
    candidate_mean: Optional[float]
    delta: Optional[float]


class ShadowAgreementReport(BaseModel):
    report_id: str
    tenant_id: str
    candidate: str
    alerts: int = Field(description="Alerts replayed.")
    compared: int = Field(description="Alerts with a production verdict and a usable candidate verdict.")
    candidate_failed: int = Field(description="Candidate runs that raised: no verdict.")
    candidate_degraded: int = Field(description="Candidate runs whose model answer was unusable or refused.")
    no_production_verdict: int
    min_samples: int
    max_failure_rate: float
    enough_data: bool
    data_warnings: List[str] = Field(description="Why the report is not enough_data, if it is not.")
    agreement: RateInterval = Field(
        description="Agreement over every alert with a production verdict; failed or degraded runs disagree."
    )
    agreement_text: str
    agreement_usable: RateInterval = Field(description="Agreement over the usable candidate verdicts only.")
    agreement_usable_text: str
    by_class: List[ShadowClassAgreement]
    labels: List[str]
    confusion: Dict[str, Dict[str, int]] = Field(description="Production route -> candidate route -> alerts.")
    potential_misses: ShadowCaseList
    routing_differences: ShadowCaseList = Field(
        description="escalate <-> plan_response, production escalate -> candidate plan_response first."
    )
    candidate_failures: ShadowCaseList
    new_escalations: ShadowCaseList
    plan_differences: ShadowCaseList
    cost_usd: ShadowDelta
    tokens: ShadowDelta
    latency_ms: ShadowDelta
    limitations: List[str]


LIMITATIONS = (
    "Agreement compares the routing decision (close, plan_response, escalate), not the analyst's final outcome.",
    "Production's route is its first decide event; once alert events pass retention.events_days (while the alert "
    "is kept for alerts_days) an alert closed without one reads as close and an open one as no production verdict.",
    "The candidate stops at the first human step; production figures cover every run of the alert, including "
    "re-analysis an analyst asked for, so production cost and latency can be higher for escalated alerts.",
    "Shadow runs answer threat-intelligence lookups from the cache only, so the candidate can see less "
    "threat intelligence than production saw.",
    "Response plans are compared only where both sides responded automatically.",
)


def has_production(c: Comparison) -> bool:
    return c.production.route in ROUTES


def is_usable(c: Comparison) -> bool:
    """The candidate decided this alert itself: a route, no error, and every model answer usable."""
    k = c.candidate
    return k.route in ROUTES and k.error is None and k.degraded == 0


def is_failure(c: Comparison) -> bool:
    """Production decided the alert; the candidate has no usable verdict (it raised, or the rules decided)."""
    return has_production(c) and not is_usable(c)


def is_potential_miss(c: Comparison) -> bool:
    """Production escalated or responded; the candidate would have closed the alert with no human."""
    return c.production.route in HUMAN_OR_RESPONSE and c.candidate.route == "close"


def is_routing_difference(c: Comparison) -> bool:
    """escalate <-> plan_response, either way."""
    return {c.production.route, c.candidate.route} == HUMAN_OR_RESPONSE


def is_new_escalation(c: Comparison) -> bool:
    return c.production.route == "close" and c.candidate.route in HUMAN_OR_RESPONSE


def is_plan_difference(c: Comparison) -> bool:
    both = c.production.route == c.candidate.route == "plan_response"
    return both and set(c.production.actions) != set(c.candidate.actions)


def _case(c: Comparison) -> ShadowCase:
    p, k = c.production, c.candidate
    return ShadowCase(
        alert_id=c.alert_id,
        severity=c.severity,
        production_route=p.route,
        candidate_route=k.route,
        production_disposition=p.disposition,
        candidate_disposition=k.disposition,
        production_confidence=p.confidence,
        candidate_confidence=k.confidence,
        production_actions=list(p.actions),
        candidate_actions=list(k.actions),
        candidate_error=k.error,
        candidate_degraded=k.degraded,
    )


def _severity_first(c: Comparison) -> Tuple[int, str]:
    return -SEVERITY_RANK.get(c.severity, -1), c.alert_id


def _cases(rows: Iterable[Comparison], key: Callable[[Comparison], Tuple[Any, ...]] = _severity_first) -> ShadowCaseList:
    ordered = sorted(rows, key=key)
    return ShadowCaseList(count=len(ordered), items=[_case(c) for c in ordered[:MAX_LISTED_CASES]])


def _human_wanted_first(c: Comparison) -> Tuple[int, int, str]:
    return (0 if c.production.route == "escalate" else 1, *_severity_first(c))


def _failures_first(c: Comparison) -> Tuple[int, int, str]:
    """Failures on alerts production escalated or responded to first, then by severity."""
    return (0 if c.production.route in HUMAN_OR_RESPONSE else 1, *_severity_first(c))


def confusion_matrix(rows: Iterable[Comparison]) -> Dict[str, Dict[str, int]]:
    """Counts by production route (rows) and candidate route (columns: ``none`` = no usable verdict)."""
    matrix = {p: {k: 0 for k in LABELS} for p in LABELS}
    for c in rows:
        candidate = c.candidate.route if is_usable(c) else NO_VERDICT
        matrix[_label(c.production.route)][_label(candidate)] += 1
    return matrix


def _label(route: Optional[str]) -> str:
    return route if route in ROUTES else NO_VERDICT


def rate_text(r: RateInterval, min_samples: int = MIN_AGREEMENT_SAMPLES) -> str:
    """``format_rate`` with the shared small-sample warning below ``min_samples``."""
    if r.n < min_samples:
        return f"{not_enough_data(r.n, min_samples)}: {format_rate(r)}" if r.n else not_enough_data(0, min_samples)
    return format_rate(r)


def _agreement(rows: Sequence[Comparison]) -> RateInterval:
    """Usable verdicts that match production, out of ``rows`` (failures count as disagreement)."""
    return rate_interval(sum(is_usable(c) and c.production.route == c.candidate.route for c in rows), len(rows))


def data_warnings(sample: Sequence[Comparison], min_samples: int = MIN_AGREEMENT_SAMPLES) -> List[str]:
    """Why ``sample`` (the alerts with a production verdict) is not enough to judge the candidate on."""
    failures = [c for c in sample if is_failure(c)]
    warnings: List[str] = []
    if len(sample) < min_samples:
        warnings.append(not_enough_data(len(sample), min_samples))
    if sample and len(failures) / len(sample) > MAX_FAILURE_RATE:
        warnings.append(
            f"{len(failures)} of {len(sample)} candidate runs failed or fell back to rules "
            f"(more than {MAX_FAILURE_RATE:.0%})"
        )
    critical = sum(c.production.route in HUMAN_OR_RESPONSE for c in failures)
    if critical:
        warnings.append(f"the candidate failed on {critical} alert(s) production escalated or responded to")
    return warnings


def _mean(values: Sequence[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


def _delta(production: Sequence[float], candidate: Sequence[float], digits: int = 3) -> ShadowDelta:
    p, k = _mean(production), _mean(candidate)
    return ShadowDelta(
        production_mean=None if p is None else round(p, digits),
        candidate_mean=None if k is None else round(k, digits),
        delta=None if p is None or k is None else round(k - p, digits),
    )


def _deltas(usable: Sequence[Comparison]) -> Dict[str, ShadowDelta]:
    return {
        "cost_usd": _delta(
            [float(c.production.cost_usd) for c in usable], [float(c.candidate.cost_usd) for c in usable], _COST_DIGITS
        ),
        "tokens": _delta([c.production.tokens for c in usable], [c.candidate.tokens for c in usable]),
        "latency_ms": _delta([c.production.latency_ms for c in usable], [c.candidate.latency_ms for c in usable]),
    }


def build_report(
    rows: Sequence[Comparison], *, report_id: str, tenant_id: str, candidate: str,
    min_samples: int = MIN_AGREEMENT_SAMPLES,
) -> ShadowAgreementReport:
    """The agreement report of one shadow replay's comparisons."""
    sample = [c for c in rows if has_production(c)]
    usable = [c for c in sample if is_usable(c)]
    failures = [c for c in sample if is_failure(c)]
    overall, decided = _agreement(sample), _agreement(usable)
    by_class = []
    for route in ROUTES:
        r = _agreement([c for c in sample if c.production.route == route])
        by_class.append(ShadowClassAgreement(production_route=route, agreement=r, text=rate_text(r, min_samples)))
    warnings = data_warnings(sample, min_samples)
    return ShadowAgreementReport(
        report_id=report_id,
        tenant_id=tenant_id,
        candidate=candidate,
        alerts=len(rows),
        compared=len(usable),
        candidate_failed=sum(c.candidate.error is not None or c.candidate.route not in ROUTES for c in failures),
        candidate_degraded=sum(c.candidate.error is None and c.candidate.route in ROUTES for c in failures),
        no_production_verdict=len(rows) - len(sample),
        min_samples=min_samples,
        max_failure_rate=MAX_FAILURE_RATE,
        enough_data=not warnings,
        data_warnings=warnings,
        agreement=overall,
        agreement_text=rate_text(overall, min_samples),
        agreement_usable=decided,
        agreement_usable_text=rate_text(decided, min_samples),
        by_class=by_class,
        labels=list(LABELS),
        confusion=confusion_matrix(rows),
        potential_misses=_cases(c for c in usable if is_potential_miss(c)),
        routing_differences=_cases((c for c in usable if is_routing_difference(c)), _human_wanted_first),
        candidate_failures=_cases(failures, _failures_first),
        new_escalations=_cases(c for c in usable if is_new_escalation(c)),
        plan_differences=_cases(c for c in usable if is_plan_difference(c)),
        **_deltas(usable),
        limitations=list(LIMITATIONS),
    )


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:g}"


def _cell(text: str) -> str:
    """Table-cell text: no pipe, backtick or line break can change the table."""
    return re.sub(r"[|`\r\n]", " ", text)


def _candidate_cell(c: ShadowCase) -> str:
    if c.candidate_error is not None:
        return f"failed: {c.candidate_error}"
    text = f"{c.candidate_route} ({_fmt(c.candidate_confidence)})"
    return text + (f", rules fallback on {c.candidate_degraded} model step(s)" if c.candidate_degraded else "")


def _case_lines(title: str, cases: ShadowCaseList) -> List[str]:
    lines = [f"## {title} ({cases.count})", ""]
    if not cases.items:
        return [*lines, "None.", ""]
    lines += ["| Alert | Severity | Production | Candidate |", "|---|---|---|---|"]
    for c in cases.items:
        production = f"{c.production_route} ({_fmt(c.production_confidence)})"
        candidate = _candidate_cell(c)
        if c.production_actions or c.candidate_actions:
            production += f": {', '.join(c.production_actions) or '-'}"
            candidate += f": {', '.join(c.candidate_actions) or '-'}"
        lines.append(f"| `{_cell(c.alert_id)}` | {_cell(c.severity)} | {_cell(production)} | {_cell(candidate)} |")
    if cases.count > len(cases.items):
        lines.append(f"\n{cases.count - len(cases.items)} more not listed.")
    return [*lines, ""]


def _headline(report: ShadowAgreementReport) -> List[str]:
    lines = [
        f"Report `{_cell(report.report_id)}`, tenant `{_cell(report.tenant_id)}`: {report.alerts} alerts replayed, "
        f"{report.compared} with a usable candidate verdict, {report.candidate_failed} candidate runs failed, "
        f"{report.candidate_degraded} fell back to rules, {report.no_production_verdict} without a production verdict.",
        "",
        f"**Agreement: {report.agreement_text}** (failed and rules-fallback runs count as disagreement; "
        f"over usable verdicts only: {report.agreement_usable_text})",
        "",
    ]
    if report.data_warnings:
        lines += ["**Not enough to judge this candidate on:**", "", *(f"- {w}" for w in report.data_warnings), ""]
    return lines


def render_markdown(report: ShadowAgreementReport) -> str:
    """The report as Markdown (the CLI writes it; the PoV report can embed it)."""
    lines = [
        f"# Shadow agreement: {_cell(report.candidate)}",
        "",
        *_headline(report),
        "| Production route | Agreement |",
        "|---|---|",
        *(f"| {c.production_route} | {c.text} |" for c in report.by_class),
        "",
        "## Confusion matrix (rows: production, columns: candidate; none = no usable verdict)",
        "",
        "| | " + " | ".join(report.labels) + " |",
        "|---" * (len(report.labels) + 1) + "|",
        *(
            f"| **{p}** | " + " | ".join(str(report.confusion[p][k]) for k in report.labels) + " |"
            for p in report.labels
        ),
        "",
    ]
    lines += _case_lines("Potential misses: the candidate would close what production escalated", report.potential_misses)
    lines += _case_lines(
        "Routing differences: escalate and plan_response (the candidate acting where production wanted a human first)",
        report.routing_differences,
    )
    lines += _case_lines("Candidate failures: no usable verdict (error or rules fallback)", report.candidate_failures)
    lines += _case_lines("New escalations: the candidate would escalate what production closed", report.new_escalations)
    lines += _case_lines("Different response plans", report.plan_differences)
    lines += ["## Cost and latency per alert (candidate minus production)", "", "| | Production | Candidate | Delta |",
              "|---|---|---|---|"]
    for name, d in (("LLM cost (USD)", report.cost_usd), ("Tokens", report.tokens), ("Latency (ms)", report.latency_ms)):
        lines.append(f"| {name} | {_fmt(d.production_mean)} | {_fmt(d.candidate_mean)} | {_fmt(d.delta)} |")
    lines += ["", "## Limitations", "", *(f"- {item}" for item in report.limitations), ""]
    return "\n".join(lines)


__all__ = [
    "LABELS",
    "MAX_ACTIONS",
    "MAX_FAILURE_RATE",
    "MIN_AGREEMENT_SAMPLES",
    "NO_VERDICT",
    "Comparison",
    "ShadowAgreementReport",
    "ShadowCase",
    "ShadowCaseList",
    "ShadowClassAgreement",
    "ShadowDelta",
    "Verdict",
    "build_report",
    "confusion_matrix",
    "data_warnings",
    "has_production",
    "is_failure",
    "is_new_escalation",
    "is_plan_difference",
    "is_potential_miss",
    "is_routing_difference",
    "is_usable",
    "rate_text",
    "render_markdown",
]
