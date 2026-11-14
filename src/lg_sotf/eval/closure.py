"""What closed which alert: the two headline numbers, closure per mechanism, and declared-context coverage.

Every evaluation report and scorecard leads with two numbers:

* **benign closure rate**: expected-benign items automation closed as benign,
  with n and a 95% Wilson interval (the analyst work saved);
* **malicious auto-close**: expected-malicious items automation closed with
  any disposition, with n and the exact one-sided 95% upper bound
  (:func:`lg_sotf.domain.rates.upper_bound`): at 0 of 208 the true rate may
  still be up to 1.4%.

Each automatic close is attributed to one mechanism (:func:`close_mechanism`):

* ``suppression``: an enabled suppression rule matched at the gate;
* ``cache``: an analyst-confirmed benign verdict for the same fingerprint (the
  verdict cache) closed it at the gate;
* ``rules``: triage closed an obvious false positive, or ``decide`` closed on
  triage's and the rules' scores without the deep model;
* ``history``: the deep model's benign verdict closed it while the tenant's
  history said an analyst had already judged one of its entities harmless;
* ``model``: the deep model's benign verdict closed it (corroborated by the
  rules' score or by declared context, as the routing policy requires);
* ``response``: a policy response completed and closed it as malicious.

Every malicious item closed by any mechanism is listed by id. Reports written
before the attribution existed carry no mechanism: their closes are attributed
from the close reason and the recorded decision inputs where that is
unambiguous (``rules`` or ``model``; history cannot be told apart and counts as
``model``), else ``unattributed``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.domain.closure import MODEL_CLOSE_REASON
from lg_sotf.domain.rates import format_rate, rate_interval, upper_bound
from lg_sotf.eval.context import CONTEXT_KINDS, TenantContext, context_matches
from lg_sotf.eval.dataset import Dataset, EvalItem
from lg_sotf.eval.results import ItemResult
from lg_sotf.ingestion.timeparse import FLAG_INVALID, FLAG_MISSING

CLOSE_MECHANISMS = ("rules", "model", "history", "cache", "suppression", "response")
UNATTRIBUTED = "unattributed"
_NORMALIZE_SOURCE = "eval-measure"


def close_mechanism(close_reason: Optional[str], state: Mapping[str, Any]) -> Optional[str]:
    """The mechanism behind an automatic close (see the module docs); None for an analyst's close or none."""
    if close_reason == "suppression_rule":
        return "suppression"
    if close_reason == "verdict_cache":
        return "cache"
    if close_reason == "triage:false_positive":
        return "rules"
    if close_reason == MODEL_CLOSE_REASON:  # a model-led close at the auto_full_audit tier (FIX-1)
        return "model"
    if close_reason == "policy:response":
        return "response"
    if close_reason != "policy:close":
        return None
    analysis = state.get("analysis")
    if not isinstance(analysis, Mapping) or not analysis:
        return "rules"
    history = analysis.get("history") or []
    if any(isinstance(h, Mapping) and h.get("verdict") == "harmless" for h in history):
        return "history"
    return "model"


def item_alert(item: EvalItem, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """The item's alert as the platform normalises it (a dict with the vendor event as ``raw``), or None (email
    items, unusable events)."""
    from lg_sotf.ingestion.normalizers import get_normalizer
    from lg_sotf.ingestion.normalizers.base import NormalizeContext

    if item.source_type == "email":
        return None
    fmt = "webhook" if item.source_type == "webhook" else item.source_type
    config = {"format": "generic", **(item.source_config or {})} if fmt == "webhook" else {}
    ctx = NormalizeContext(_NORMALIZE_SOURCE, item.source_type, config, now=now or datetime.now(UTC))
    try:
        alert = get_normalizer(fmt).normalize(item.alert, ctx)
    except Exception:  # noqa: BLE001 - ingestion reports the same event as an item error; here it has no time
        return None
    out = alert.model_dump(mode="json")
    out["raw"] = dict(item.alert)  # the platform stores the vendor event next to the normalised alert
    return out


def event_time(item: EvalItem) -> Optional[datetime]:
    """When the item's event happened (the normalised ``occurred_at``), if it says."""
    alert = item_alert(item)
    if alert is None or {FLAG_MISSING, FLAG_INVALID} & set(alert.get("flags") or []):
        return None
    return datetime.fromisoformat(str(alert["occurred_at"]).replace("Z", "+00:00"))


def event_time_order(items: Sequence[EvalItem]) -> List[EvalItem]:
    """``items`` sorted by event time, ties in dataset order; an item without a time stays after its predecessor."""
    keyed = []
    last = datetime.min.replace(tzinfo=UTC)
    for index, item in enumerate(items):
        at = event_time(item)
        last = at if at is not None else last
        keyed.append((last, index, item))
    return [item for _, _, item in sorted(keyed, key=lambda row: (row[0], row[1]))]


def context_coverage(dataset: Dataset) -> Dict[str, List[str]]:
    """``{item_id: matched context kinds}`` for a dataset that declares ``tenant_context`` (else empty)."""
    context: Optional[TenantContext] = dataset.tenant_context
    if context is None:
        return {}
    out: Dict[str, List[str]] = {}
    for item in dataset.items:
        alert = item_alert(item)
        out[item.id] = context_matches(context, alert) if alert is not None else []
    return out


def with_context(results: Sequence[ItemResult], coverage: Mapping[str, List[str]]) -> List[ItemResult]:
    """``results`` with each item's matched context filled in (unchanged when there is no coverage)."""
    if not coverage:
        return list(results)
    return [replace(r, context=list(coverage.get(r.item_id, []))) for r in results]


def mechanism_of(r: ItemResult) -> Optional[str]:
    """``r``'s close mechanism; for a report written before attribution, the best reading of what it recorded."""
    if not r.auto_closed or r.close_mechanism is not None:
        return r.close_mechanism
    if r.close_reason != "policy:close":
        return close_mechanism(r.close_reason, {}) or UNATTRIBUTED
    if not r.decision_inputs:
        return UNATTRIBUTED
    return "model" if r.decision_inputs.get("analysis") else "rules"


def _closed_benign(r: ItemResult) -> bool:
    return r.auto_closed and r.disposition == "benign"


def _rate(k: int, n: int) -> Dict[str, Any]:
    return {"k": k, **rate_interval(k, n).model_dump()}


def headline(results: Sequence[ItemResult]) -> Dict[str, Any]:
    """The two headline numbers of a result set."""
    scored = [r for r in results if r.scored]
    benign = [r for r in scored if r.expected == "benign"]
    malicious = [r for r in scored if r.expected == "malicious"]
    closed_malicious = sum(1 for r in malicious if r.auto_closed)
    return {
        "benign_closure": _rate(sum(1 for r in benign if _closed_benign(r)), len(benign)),
        "malicious_auto_close": {
            "k": closed_malicious,
            "n": len(malicious),
            "rate": None if not malicious else closed_malicious / len(malicious),
            "upper_95": upper_bound(closed_malicious, len(malicious)),
        },
    }


def _mechanism_rows(scored: Sequence[ItemResult]) -> List[Dict[str, Any]]:
    benign = [r for r in scored if r.expected == "benign"]
    malicious = [r for r in scored if r.expected == "malicious"]
    closed = {id(r): mechanism_of(r) for r in scored if r.auto_closed}
    mechanisms = [*CLOSE_MECHANISMS, *([UNATTRIBUTED] if UNATTRIBUTED in closed.values() else [])]
    rows = []
    for mechanism in mechanisms:
        rows.append({
            "mechanism": mechanism,
            "benign": _rate(sum(1 for r in benign if closed.get(id(r)) == mechanism), len(benign)),
            "malicious": sum(1 for r in malicious if closed.get(id(r)) == mechanism),
            "other": sum(1 for r in scored if r.expected not in ("benign", "malicious") and closed.get(id(r)) == mechanism),
        })
    return rows


def _coverage(scored: Sequence[ItemResult]) -> Dict[str, Any]:
    benign = [r for r in scored if r.expected == "benign"]
    malicious = [r for r in scored if r.expected == "malicious"]
    covered_benign = [r for r in benign if r.context]
    by_kind = {
        kind: {
            "benign": sum(1 for r in benign if kind in r.context),
            "malicious": sum(1 for r in malicious if kind in r.context),
        }
        for kind in CONTEXT_KINDS
    }
    return {
        "benign_closable_with_context": _rate(len(covered_benign), len(benign)),
        "benign_closed_of_closable": _rate(sum(1 for r in covered_benign if _closed_benign(r)), len(covered_benign)),
        "malicious_matching_context": _rate(sum(1 for r in malicious if r.context), len(malicious)),
        "malicious_matching_ids": [r.item_id for r in malicious if r.context],
        "by_kind": {k: v for k, v in by_kind.items() if v["benign"] or v["malicious"]},
    }


def closure_summary(results: Sequence[ItemResult], *, has_context: bool = False) -> Dict[str, Any]:
    """``report.closure``: the headline, the per-mechanism table, every closed malicious item, context coverage."""
    scored = [r for r in results if r.scored]
    summary: Dict[str, Any] = {
        "headline": headline(results),
        "by_mechanism": _mechanism_rows(scored),
        "malicious_closed": [
            {
                "item_id": r.item_id,
                "mechanism": mechanism_of(r),
                "close_reason": r.close_reason,
                "disposition": r.disposition,
                "severity": r.severity,
                "family": r.family,
            }
            for r in scored
            if r.expected == "malicious" and r.auto_closed
        ],
    }
    if has_context:
        summary["context"] = _coverage(scored)
    return summary


def _pct(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _interval(rate: Mapping[str, Any]) -> str:
    return format_rate(rate_interval(int(rate["k"]), int(rate["n"])))


def malicious_cell(m: Mapping[str, Any]) -> str:
    """``0 of 208 (0.0%; 95% upper bound 1.4%)``."""
    if not m.get("n"):
        return "Not enough data (n=0)"
    return f"{m['k']} of {m['n']} ({_pct(m['rate'])}; 95% upper bound {_pct(m['upper_95'])})"


def headline_lines(summary: Mapping[str, Any]) -> List[str]:
    """The two headline numbers as a Markdown list."""
    h = summary["headline"]
    return [
        f"- **Benign closure rate:** {_interval(h['benign_closure'])}",
        f"- **Malicious auto-close:** {malicious_cell(h['malicious_auto_close'])}",
    ]


def render_closure(summary: Mapping[str, Any]) -> List[str]:
    """The report's "Closure" section: headline, mechanisms, closed malicious items, context coverage."""
    lines = ["## Closure", "", *headline_lines(summary), ""]
    lines += [
        "| Mechanism | Benign closed | Malicious closed |",
        "|---|---|---|",
    ]
    for row in summary["by_mechanism"]:
        lines.append(f"| {row['mechanism']} | {_interval(row['benign'])} | {row['malicious']} |")
    lines.append("")
    closed = summary.get("malicious_closed") or []
    if closed:
        lines.append("Malicious items closed without a human:")
        lines.append("")
        lines += [
            f"- `{c['item_id']}`: {c['mechanism'] or 'unknown'} ({c['close_reason']}), disposition {c['disposition']}, "
            f"severity {c['severity']}" for c in closed
        ]
    else:
        lines.append("No malicious item was closed without a human.")
    lines.append("")
    if "context" in summary:
        lines += _context_lines(summary["context"])
    return lines


def _context_lines(c: Mapping[str, Any]) -> List[str]:
    lines = [
        "### Declared tenant context",
        "",
        f"- Benign closable with context (the alert touches a declared fact): {_interval(c['benign_closable_with_context'])}",
        f"- Of those, closed in this run: {_interval(c['benign_closed_of_closable'])}",
        f"- Malicious that touch declared context too: {_interval(c['malicious_matching_context'])}",
        "",
    ]
    if c.get("by_kind"):
        lines += ["| Context | Benign | Malicious |", "|---|---|---|"]
        lines += [f"| {kind} | {v['benign']} | {v['malicious']} |" for kind, v in c["by_kind"].items()]
        lines.append("")
    return lines
