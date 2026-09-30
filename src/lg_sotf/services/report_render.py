"""Report exports: CSV (value daily series, detections) and the self-contained monthly HTML report.

Alert-derived text (rule names, titles, source ids) and the tenant name are
untrusted:

* HTML: every value is escaped; the page has no scripts, links or external
  assets. Its only stylesheet is the inline :data:`REPORT_CSS`, allowed by
  hash in :data:`REPORT_CSP` (no ``unsafe-inline``); bars are SVG
  attributes, not ``style`` attributes.
* CSV: a text cell starting with ``=``, ``+``, ``-``, ``@``, a tab or a
  carriage return is prefixed with ``'`` so spreadsheet applications never
  evaluate it as a formula (OWASP "CSV injection"); numbers are written
  unchanged.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from datetime import date
from html import escape
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from lg_sotf.services.reporting import (
    AccuracyBlock,
    Detection,
    DetectionsReport,
    MonthlyReport,
    ValueDay,
    ValueMetrics,
    ValueReport,
)

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
MAX_HTML_DETECTIONS = 25

REPORT_CSS = """
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a;
  background: #ffffff; margin: 0 auto; max-width: 960px; padding: 24px; font-size: 13px; line-height: 1.45; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 28px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #0f172a; }
h3 { font-size: 13px; margin: 16px 0 6px; }
p.meta { color: #475569; margin: 0; }
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.tile { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; break-inside: avoid; }
.tile .label { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
.tile .value { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
.tile .hint { font-size: 11px; color: #475569; }
table { width: 100%; border-collapse: collapse; margin: 6px 0; break-inside: auto; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .03em; color: #475569; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr { break-inside: avoid; }
.warn { border: 1px solid #b45309; background: #fffbeb; color: #78350f; border-radius: 6px; padding: 8px 10px;
  margin: 8px 0; }
.headline { font-size: 26px; font-weight: 700; }
.muted { color: #475569; }
.notes li { margin-bottom: 4px; }
svg.bars { width: 100%; height: auto; }
svg.bars rect.auto { fill: #2a78d6; }
svg.bars rect.human { fill: #eb6834; }
svg.bars text { font-size: 9px; fill: #475569; }
.legend span { display: inline-block; width: 10px; height: 10px; margin: 0 4px 0 12px; vertical-align: middle; }
.legend .auto { background: #2a78d6; }
.legend .human { background: #eb6834; }
.rule { word-break: break-word; }
footer { margin-top: 28px; font-size: 11px; color: #475569; border-top: 1px solid #e2e8f0; padding-top: 8px; }
@media print { body { padding: 0; } h2 { break-after: avoid; } }
""".strip()

REPORT_CSS_HASH = base64.b64encode(hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()).decode("ascii")
REPORT_CSP = (
    f"default-src 'none'; style-src 'sha256-{REPORT_CSS_HASH}'; img-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


# --------------------------------------------------------------------- CSV


def csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    text = value.isoformat() if isinstance(value, date) else str(value)
    if text.startswith(FORMULA_PREFIXES) or text.lstrip().startswith(FORMULA_PREFIXES):
        text = "'" + text
    return text


def to_csv(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return buf.getvalue()


VALUE_COLUMNS: Tuple[str, ...] = ("day", *ValueMetrics.model_fields.keys())


def value_csv(report: ValueReport) -> str:
    """The daily value series, one row per day of the window."""
    return to_csv(VALUE_COLUMNS, ([getattr(d, c) for c in VALUE_COLUMNS] for d in report.days))


DETECTION_COLUMNS: Tuple[str, ...] = tuple(Detection.model_fields.keys())


def detections_csv(report: DetectionsReport) -> str:
    return to_csv(DETECTION_COLUMNS, ([getattr(d, c) for c in DETECTION_COLUMNS] for d in report.detections))


# -------------------------------------------------------------------- HTML


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _int(value: Optional[int]) -> str:
    return "n/a" if value is None else f"{value:,}"


def _pct(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _usd(value: Optional[float]) -> str:
    return "n/a" if value is None else f"${value:,.4f}"


def _duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5_400:
        return f"{seconds / 60:.1f} min"
    if seconds < 172_800:
        return f"{seconds / 3_600:.1f} h"
    return f"{seconds / 86_400:.1f} d"


def _ci(ci: Optional[Tuple[float, float]]) -> str:
    return "" if ci is None else f"95% range {_pct(ci[0])} to {_pct(ci[1])}"


def _tile(label: str, value: str, hint: str = "") -> str:
    hint_html = f'<div class="hint">{_e(hint)}</div>' if hint else ""
    return f'<div class="tile"><div class="label">{_e(label)}</div><div class="value">{_e(value)}</div>{hint_html}</div>'


def _table(headers: Sequence[Tuple[str, bool]], rows: Iterable[Sequence[str]], caption: str) -> str:
    """``rows`` hold already-escaped HTML cells; ``headers`` are ``(text, numeric)``."""
    num = ' class="num"'
    head = "".join(f'<th scope="col"{num if numeric else ""}>{_e(h)}</th>' for h, numeric in headers)
    body: List[str] = []
    for row in rows:
        cells = "".join(f'<td{num if headers[i][1] else ""}>{cell}</td>' for i, cell in enumerate(row))
        body.append(f"<tr>{cells}</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(headers)}" class="muted">No data in this period.</td></tr>')
    return f'<table><caption class="muted">{_e(caption)}</caption><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'


def _bars(days: Sequence[ValueDay]) -> str:
    """Handled without a human (blue) stacked under needed a human (orange) per day, as SVG geometry.

    The two hues are a validated colour-blind-safe pair; a 2 px gap separates the segments and the
    legend names both, so identity never rests on colour alone.
    """
    if not days:
        return ""
    width, height, pad_b = 900, 150, 16
    peak = max(1, *(d.handled_without_human + d.needed_human for d in days))
    step = width / len(days)
    bar = max(1.0, step - 2)
    plot = height - pad_b
    parts: List[str] = []
    label_every = max(1, len(days) // 10)
    for i, d in enumerate(days):
        x = i * step + 1
        auto = plot * d.handled_without_human / peak
        human = plot * d.needed_human / peak
        gap = 2.0 if auto > 0 and human > 0 else 0.0
        if auto > 0:
            parts.append(f'<rect class="auto" x="{x:.1f}" y="{plot - auto:.1f}" width="{bar:.1f}" height="{auto:.1f}"/>')
        if human > 0:
            top = plot - auto - gap - human
            parts.append(f'<rect class="human" x="{x:.1f}" y="{top:.1f}" width="{bar:.1f}" height="{human:.1f}"/>')
        if i % label_every == 0:
            parts.append(f'<text x="{x:.1f}" y="{height - 3}">{_e(d.day.strftime("%d"))}</text>')
    label = f"Alerts handled without a human and alerts that needed a human per day, peak {peak:,}"
    return (
        f'<svg class="bars" viewBox="0 0 {width} {height}" role="img" aria-label="{_e(label)}">{"".join(parts)}</svg>'
        '<div class="legend muted"><span class="auto"></span>Handled without a human'
        '<span class="human"></span>Needed a human</div>'
    )


def _value_section(value: ValueReport) -> str:
    t = value.totals
    tiles = [
        _tile("Handled without a human", _pct(t.handled_without_human_rate),
              f"{t.handled_without_human:,} of {t.handled_without_human + t.needed_human:,} finished alerts"),
        _tile("Analyst hours saved (estimate)", f"{t.analyst_hours_saved:,.1f} h",
              f"{value.minutes_per_alert} min per alert handled"),
        _tile("Alerts ingested", _int(t.alerts_ingested), f"{t.in_progress:,} still in progress"),
        _tile("Auto-closed benign", _int(t.auto_closed_benign)),
        _tile("Auto-contained", _int(t.auto_contained), f"{t.auto_contained_dry_run:,} more in dry-run mode"),
        _tile("Escalated", _int(t.escalated), f"{t.human_decided:,} decided by an analyst"),
        _tile("Mean time to verdict", _duration(t.mean_time_to_verdict_s), f"{t.verdicts:,} verdicts"),
        _tile("MTTA", _duration(t.mtta_s), f"{t.acknowledged:,} of {t.escalations_created:,} escalations claimed"),
        _tile("MTTR", _duration(t.mttr_s), f"{t.resolved:,} resolved"),
        _tile("SLA breaches", _int(t.sla_breaches), f"{value.escalations_breached:,} escalations"),
        _tile("LLM cost per alert", _usd(t.llm_cost_per_alert_usd), f"{_usd(t.llm_cost_usd)} in total"),
        _tile("Suppressed / cached / grouped",
              f"{t.suppressed_by_rule:,} / {t.verdict_cache_hits:,} / {t.grouped_into_escalation:,}",
              "rule, analyst verdict cache, attached to an escalation"),
    ]
    return (
        "<h2>1. Value</h2>"
        f'<div class="tiles">{"".join(tiles)}</div>'
        "<h3>Daily volume</h3>"
        f"{_bars(value.days)}"
    )


def _accuracy_block(block: AccuracyBlock, min_samples: int) -> str:
    warn = ""
    if block.status == "insufficient_data":
        warn = (
            f'<div class="warn">Insufficient data: {block.samples} analyst-decided alert(s), at least {min_samples} '
            "are needed before these rates mean much.</div>"
        )
    m = block.confusion_matrix
    matrix = _table(
        [("Analyst \\ AI", False), ("Malicious", True), ("Benign", True), ("Inconclusive", True)],
        [
            [_e(actual.capitalize()), *(_int(m[actual][p]) for p in ("malicious", "benign", "inconclusive"))]
            for actual in ("malicious", "benign")
        ],
        "Confusion matrix: rows are the analyst's final decision, columns the AI verdict",
    )
    return (
        f"{warn}"
        '<p><span class="headline">'
        f"{_e(_pct(block.false_negative_rate))}</span> false-negative rate: the AI said benign on "
        f"{block.false_negatives:,} of {block.analyst_malicious:,} alerts an analyst confirmed as malicious "
        f"<span class=\"muted\">{_e(_ci(block.false_negative_ci95))}</span></p>"
        f"<p>Agreement {_e(_pct(block.agreement_rate))} ({block.agreement:,} of {block.samples:,}) "
        f"<span class=\"muted\">{_e(_ci(block.agreement_ci95))}</span>; false-positive rate "
        f"{_e(_pct(block.false_positive_rate))} ({block.false_positives:,} of {block.analyst_benign:,} benign); "
        f"AI inconclusive {_e(_pct(block.ai_inconclusive_rate))}.</p>"
        f"{matrix}"
    )


def _accuracy_section(monthly: MonthlyReport) -> str:
    acc = monthly.accuracy
    models = _table(
        [("Model", False), ("Samples", True), ("Agreement", True), ("False-negative rate", True), ("Status", False)],
        [
            [
                _e(m.model),
                _int(m.accuracy.samples),
                _e(_pct(m.accuracy.agreement_rate)),
                _e(_pct(m.accuracy.false_negative_rate)),
                _e(m.accuracy.status.replace("_", " ")),
            ]
            for m in acc.by_model
        ],
        "By model (analysis agent, else triage)",
    )
    fb = acc.feedback
    feedback = _table(
        [("Analyst feedback", False), ("Rate", True), ("Answers", True), ("Status", False)],
        [
            [_e(label), _e(_pct(r.rate)), _int(r.samples), _e(r.status.replace("_", " "))]
            for label, r in (
                ("Triage correct", fb.triage_correct),
                ("Analysis accurate", fb.analysis_accurate),
                ("Correlation helpful", fb.correlation_helpful),
            )
        ],
        f"Structured feedback on {fb.total:,} decisions",
    )
    return "<h2>2. Accuracy on your data</h2>" + _accuracy_block(acc.overall, acc.min_samples) + models + feedback


def _detection_rows(detections: Sequence[Detection]) -> Iterable[Sequence[str]]:
    for d in detections[:MAX_HTML_DETECTIONS]:
        suggestion = {"tune_rule": "Tune rule", "candidate_suppression": "Candidate suppression"}.get(
            d.suggestion or "", "None"
        )
        yield [
            _e(d.source_id),
            f'<span class="rule">{_e(d.rule)}</span>',
            _int(d.volume),
            _e(_pct(d.benign_rate)),
            _int(d.auto_closed),
            _int(d.analyst_false_positive),
            _e(d.median_severity or "n/a"),
            f"<strong>{_e(suggestion)}</strong><br><span class=\"muted\">{_e(d.reason)}</span>",
        ]


def _detections_section(report: DetectionsReport) -> str:
    table = _table(
        [
            ("Source", False),
            ("Rule", False),
            ("Volume", True),
            ("Benign", True),
            ("Auto-closed", True),
            ("Analyst FP", True),
            ("Median severity", False),
            ("Suggestion", False),
        ],
        _detection_rows(report.detections),
        f"Busiest {min(len(report.detections), MAX_HTML_DETECTIONS)} detections by volume",
    )
    return "<h2>3. Detection tuning</h2>" + table


def _notes(monthly: MonthlyReport) -> str:
    notes = [*monthly.value.notes, *monthly.accuracy.notes, *monthly.detections.notes]
    items = "".join(f"<li>{_e(n)}</li>" for n in notes)
    return (
        "<h2>Definitions and limits</h2>"
        f'<ul class="notes">{items}<li>Full metric definitions: docs/reporting.md.</li></ul>'
    )


def monthly_html(monthly: MonthlyReport, *, product: str = "LG-SOTF", version: Optional[str] = None) -> str:
    """The monthly report as one self-contained, print-to-PDF-friendly HTML document."""
    period = f"{monthly.value.start.isoformat()} to {monthly.value.end.isoformat()} (UTC)"
    month_name = date.fromisoformat(f"{monthly.month}-01").strftime("%B %Y")
    title = f"{product} monthly report: {monthly.tenant_name}, {month_name}"
    footer_version = f" {version}" if version else ""
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{_e(title)}</title><style>{REPORT_CSS}</style></head><body>"
        f"<header><h1>{_e(title)}</h1>"
        f'<p class="meta">Tenant {_e(monthly.tenant_name)} ({_e(monthly.tenant_id)}). Period {_e(period)}. '
        f"Generated {_e(monthly.generated_at.strftime('%Y-%m-%d %H:%M UTC'))}.</p></header>"
        f"{_value_section(monthly.value)}"
        f"{_accuracy_section(monthly)}"
        f"{_detections_section(monthly.detections)}"
        f"{_notes(monthly)}"
        f"<footer>{_e(product + footer_version)}: measured on this tenant's own alerts and analyst decisions. "
        "Print this page to PDF from the browser to archive it.</footer>"
        "</body></html>"
    )


