"""Shadow agreement report (AI-E1.5b): a candidate's verdicts against production's, alert by alert.

A shadow replay (``lg-sotf shadow-run``) runs a candidate (another model
profile) on alerts production already decided, in shadow mode, and stores
one :class:`Comparison` per alert: what production decided and what the
candidate would have decided. This module turns those rows into the
report. It is pure: no I/O, the same input gives the same report.

The verdict compared is the routing decision after analysis (``close``,
``plan_response`` or ``escalate``): what the platform does with the alert
without a human. Agreement is the share of alerts on which the candidate
takes the same route as production, with its sample size and 95% Wilson
interval (:mod:`lg_sotf.domain.rates`), overall and per production route.

The cases that matter are listed, worst first:

* **potential misses**: production escalated or responded, the candidate
  would have closed the alert with no human. A candidate with any of these
  needs a closer look before it is promoted;
* **new escalations**: production closed the alert, the candidate would have
  escalated or responded (more analyst work, or a possible catch);
* **plan differences**: both responded automatically, with different actions.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from lg_sotf.domain.rates import RateInterval, format_rate, not_enough_data, rate_interval
from lg_sotf.models.vocabulary import ROUTES, SEVERITY_RANK

NO_VERDICT = "none"
"""The confusion-matrix label of an alert without a verdict on that side (a failed candidate run)."""
LABELS: Tuple[str, ...] = (*ROUTES, NO_VERDICT)
HUMAN_OR_RESPONSE = frozenset({"escalate", "plan_response"})
MIN_AGREEMENT_SAMPLES = 30
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


class ShadowCaseList(BaseModel):
    count: int
    items: List[ShadowCase] = Field(description=f"Most severe first, at most {MAX_LISTED_CASES}.")


class ShadowClassAgreement(BaseModel):
    production_route: str
    agreement: RateInterval
    text: str


class ShadowDelta(BaseModel):
    """Per-alert means over the compared alerts; ``delta`` is candidate minus production."""

    production_mean: Optional[float]
    candidate_mean: Optional[float]
    delta: Optional[float]


class ShadowAgreementReport(BaseModel):
    report_id: str
    tenant_id: str
    candidate: str
    alerts: int = Field(description="Alerts replayed.")
    compared: int = Field(description="Alerts with a verdict on both sides: the agreement sample n.")
    candidate_failed: int
    no_production_verdict: int
    min_samples: int
    enough_data: bool
    agreement: RateInterval
    agreement_text: str
    by_class: List[ShadowClassAgreement]
    labels: List[str]
    confusion: Dict[str, Dict[str, int]] = Field(description="Production route -> candidate route -> alerts.")
    potential_misses: ShadowCaseList
    new_escalations: ShadowCaseList
    plan_differences: ShadowCaseList
    cost_usd: ShadowDelta
    tokens: ShadowDelta
    latency_ms: ShadowDelta
    limitations: List[str]


LIMITATIONS = (
    "Agreement compares the routing decision (close, plan_response, escalate), not the analyst's final outcome.",
    "The candidate stops at the first human step; production figures cover every run of the alert, including "
    "re-analysis an analyst asked for, so production cost and latency can be higher for escalated alerts.",
    "Shadow runs answer threat-intelligence lookups from the cache only, so the candidate can see less "
    "threat intelligence than production saw.",
    "Response plans are compared only where both sides responded automatically.",
)


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
    )


def _cases(rows: Iterable[Comparison]) -> ShadowCaseList:
    ordered = sorted(rows, key=lambda c: (-SEVERITY_RANK.get(c.severity, -1), c.alert_id))
    return ShadowCaseList(count=len(ordered), items=[_case(c) for c in ordered[:MAX_LISTED_CASES]])


def is_potential_miss(c: Comparison) -> bool:
    """Production escalated or responded; the candidate would have closed the alert with no human."""
    return c.production.route in HUMAN_OR_RESPONSE and c.candidate.route == "close"


def is_new_escalation(c: Comparison) -> bool:
    return c.production.route == "close" and c.candidate.route in HUMAN_OR_RESPONSE


def is_plan_difference(c: Comparison) -> bool:
    both = c.production.route == c.candidate.route == "plan_response"
    return both and set(c.production.actions) != set(c.candidate.actions)


def confusion_matrix(rows: Iterable[Comparison]) -> Dict[str, Dict[str, int]]:
    """Counts by production route (rows) and candidate route (columns), every label present."""
    matrix = {p: {k: 0 for k in LABELS} for p in LABELS}
    for c in rows:
        matrix[_label(c.production.route)][_label(c.candidate.route)] += 1
    return matrix


def _label(route: Optional[str]) -> str:
    return route if route in ROUTES else NO_VERDICT


def rate_text(r: RateInterval, min_samples: int = MIN_AGREEMENT_SAMPLES) -> str:
    """``format_rate`` with the shared small-sample warning below ``min_samples``."""
    if r.n < min_samples:
        return f"{not_enough_data(r.n, min_samples)}: {format_rate(r)}" if r.n else not_enough_data(0, min_samples)
    return format_rate(r)


def _mean(values: Sequence[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


def _delta(production: Sequence[float], candidate: Sequence[float], digits: int = 3) -> ShadowDelta:
    p, k = _mean(production), _mean(candidate)
    return ShadowDelta(
        production_mean=None if p is None else round(p, digits),
        candidate_mean=None if k is None else round(k, digits),
        delta=None if p is None or k is None else round(k - p, digits),
    )


def build_report(
    rows: Sequence[Comparison], *, report_id: str, tenant_id: str, candidate: str,
    min_samples: int = MIN_AGREEMENT_SAMPLES,
) -> ShadowAgreementReport:
    """The agreement report of one shadow replay's comparisons."""
    compared = [c for c in rows if c.production.route in ROUTES and c.candidate.route in ROUTES]
    agree = sum(c.production.route == c.candidate.route for c in compared)
    overall = rate_interval(agree, len(compared))
    by_class = []
    for route in ROUTES:
        in_class = [c for c in compared if c.production.route == route]
        r = rate_interval(sum(c.candidate.route == route for c in in_class), len(in_class))
        by_class.append(ShadowClassAgreement(production_route=route, agreement=r, text=rate_text(r, min_samples)))
    return ShadowAgreementReport(
        report_id=report_id,
        tenant_id=tenant_id,
        candidate=candidate,
        alerts=len(rows),
        compared=len(compared),
        candidate_failed=sum(c.production.route in ROUTES and c.candidate.route not in ROUTES for c in rows),
        no_production_verdict=sum(c.production.route not in ROUTES for c in rows),
        min_samples=min_samples,
        enough_data=len(compared) >= min_samples,
        agreement=overall,
        agreement_text=rate_text(overall, min_samples),
        by_class=by_class,
        labels=list(LABELS),
        confusion=confusion_matrix(rows),
        potential_misses=_cases(c for c in compared if is_potential_miss(c)),
        new_escalations=_cases(c for c in compared if is_new_escalation(c)),
        plan_differences=_cases(c for c in compared if is_plan_difference(c)),
        cost_usd=_delta(
            [float(c.production.cost_usd) for c in compared], [float(c.candidate.cost_usd) for c in compared],
            _COST_DIGITS,
        ),
        tokens=_delta([c.production.tokens for c in compared], [c.candidate.tokens for c in compared]),
        latency_ms=_delta([c.production.latency_ms for c in compared], [c.candidate.latency_ms for c in compared]),
        limitations=list(LIMITATIONS),
    )


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:g}"


def _cell(text: str) -> str:
    """Table-cell text: no pipe, backtick or line break can change the table."""
    return re.sub(r"[|`\r\n]", " ", text)


def _case_lines(title: str, cases: ShadowCaseList) -> List[str]:
    lines = [f"## {title} ({cases.count})", ""]
    if not cases.items:
        return [*lines, "None.", ""]
    lines += ["| Alert | Severity | Production | Candidate |", "|---|---|---|---|"]
    for c in cases.items:
        production = f"{c.production_route} ({_fmt(c.production_confidence)})"
        candidate = f"{c.candidate_route} ({_fmt(c.candidate_confidence)})"
        if c.production_actions or c.candidate_actions:
            production += f": {', '.join(c.production_actions) or '-'}"
            candidate += f": {', '.join(c.candidate_actions) or '-'}"
        lines.append(f"| `{_cell(c.alert_id)}` | {_cell(c.severity)} | {_cell(production)} | {_cell(candidate)} |")
    if cases.count > len(cases.items):
        lines.append(f"\n{cases.count - len(cases.items)} more not listed.")
    return [*lines, ""]


def render_markdown(report: ShadowAgreementReport) -> str:
    """The report as Markdown (the CLI writes it; the PoV report can embed it)."""
    lines = [
        f"# Shadow agreement: {_cell(report.candidate)}",
        "",
        f"Report `{_cell(report.report_id)}`, tenant `{_cell(report.tenant_id)}`:{report.alerts} alerts replayed, "
        f"{report.compared} compared, {report.candidate_failed} candidate runs failed, "
        f"{report.no_production_verdict} without a production verdict.",
        "",
        f"**Agreement: {report.agreement_text}**",
        "",
        "| Production route | Agreement |",
        "|---|---|",
        *(f"| {c.production_route} | {c.text} |" for c in report.by_class),
        "",
        "## Confusion matrix (rows: production, columns: candidate)",
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
    "is_new_escalation",
    "is_plan_difference",
    "is_potential_miss",
    "rate_text",
    "render_markdown",
]
