"""Scorecard: a one-page summary of one model configuration's evaluation reports.

``lg-sotf eval-scorecard REPORT.json [REPORT.json ...]`` reads the JSON reports
of ``lg-sotf eval`` (one per dataset, all from the same provider and models)
and writes the scorecard as Markdown and, optionally, JSON. See
``docs/scorecards/README.md`` for the template and the meaning of each row.

Every rate is shown with its counts (``k of n``) and a 95% Wilson score
interval (``lg_sotf.domain.rates``): with the small synthetic sets an interval is wider than most
differences between models, and the scorecard says so instead of hiding it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.domain.rates import RateInterval, format_rate, rate_interval, wilson_interval
from lg_sotf.eval.closure import closure_summary, malicious_cell
from lg_sotf.eval.dataset import DISPOSITIONS
from lg_sotf.eval.metrics import per_class_intervals
from lg_sotf.eval.results import ItemResult

SCORECARD_VERSION = 1
# report.run keys that may carry prompt identities (AI-E1.2 adds prompt hashes to reports).
PROMPT_KEYS = ("prompt_hashes", "prompts", "prompt_versions")
# Models hosted where customer data may not go (DeepSeek: China). A scorecard of one is internal only unless
# every dataset is synthetic: then no customer data was sent, and the open weights can be self-hosted.
INTERNAL_ONLY_MODELS = ("deepseek",)
NOT_RECORDED = "not recorded in the report"
# A synthetic set this large is a generated corpus (corpus_v1), not a hand-written one.
GENERATED_CORPUS_ITEMS = 200


class ScorecardError(ValueError):
    """The reports cannot make one scorecard; the message is safe to print."""


def proportion(k: int, n: int) -> Dict[str, Any]:
    """``{"k", "n", "rate", "ci95"}``; rate and interval are ``None`` for an empty denominator."""
    interval = wilson_interval(k, n)
    return {
        "k": k,
        "n": n,
        "rate": None if n == 0 else k / n,
        "ci95": None if interval is None else [round(interval[0], 4), round(interval[1], 4)],
    }


@dataclass(frozen=True)
class ScorecardOptions:
    title: Optional[str] = None
    prompt_version: Optional[str] = None
    notes: Sequence[str] = field(default_factory=tuple)
    internal: bool = False


def _items(report: Mapping[str, Any]) -> List[ItemResult]:
    raw = report.get("items")
    if not isinstance(raw, list):
        raise ScorecardError("the report has no item list; was it written by lg-sotf eval?")
    return [ItemResult.from_dict(item) for item in raw]


def _split_cards(items: Sequence[ItemResult]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in sorted({r.split for r in items}):
        scored = [r for r in items if r.split == name and r.scored]
        malicious = [r for r in scored if r.expected == "malicious"]
        missed = [r for r in malicious if r.auto_closed and r.disposition == "benign"]
        out[name] = {
            "items": sum(1 for r in items if r.split == name),
            "malicious_false_negative": proportion(len(missed), len(malicious)),
            "escalation": proportion(sum(1 for r in scored if r.escalated), len(scored)),
        }
    return out


def dataset_card(report: Mapping[str, Any]) -> Dict[str, Any]:
    """The scorecard section of one evaluation report."""
    items = _items(report)
    metrics = report.get("metrics") or {}
    scored = [r for r in items if r.scored]
    malicious = [r for r in scored if r.expected == "malicious"]
    missed = [r for r in malicious if r.auto_closed and r.disposition == "benign"]
    closed = [r for r in scored if r.auto_closed]
    dataset = report.get("dataset") or {}
    return {
        "dataset": {key: dataset.get(key) for key in ("path", "sha256", "items", "synthetic", "splits")},
        "selection": (report.get("run") or {}).get("selection"),
        "closure": report.get("closure") or closure_summary(items),
        "scored": len(scored),
        "errors": len(items) - len(scored),
        "malicious_false_negative": proportion(len(missed), len(malicious)),
        "missed_malicious_ids": [r.item_id for r in missed],
        "auto_close_precision": proportion(sum(1 for r in closed if r.disposition == r.expected), len(closed)),
        "auto_close": proportion(len(closed), len(scored)),
        "escalation": proportion(sum(1 for r in scored if r.escalated), len(scored)),
        "approval_request": proportion(sum(1 for r in scored if r.approval_requested), len(scored)),
        "error": proportion(len(items) - len(scored), len(items)),
        "per_class": {cls: (metrics.get("per_class") or {}).get(cls) for cls in DISPOSITIONS},
        "per_class_intervals": per_class_intervals([(r.expected, r.predicted or "inconclusive") for r in scored]),
        "macro_f1": metrics.get("macro_f1"),
        "cost_per_item_usd": metrics.get("cost_per_alert_usd"),
        "total_cost_usd": metrics.get("total_cost_usd"),
        "tokens_per_item": metrics.get("tokens_per_alert"),
        "llm_calls_per_item": metrics.get("llm_calls_per_alert"),
        "latency_s": metrics.get("latency_s"),
        "splits": _split_cards(items),
    }


def _model(report: Mapping[str, Any]) -> Dict[str, Any]:
    run = report.get("run") or {}
    return {key: run.get(key) for key in ("llm_provider", "fast_model", "deep_model")}


def _prompts(reports: Sequence[Mapping[str, Any]], options: ScorecardOptions) -> Any:
    if options.prompt_version:
        return options.prompt_version
    for report in reports:
        run = report.get("run") or {}
        for key in PROMPT_KEYS:
            if run.get(key):
                return run[key]
    return None


def build_scorecard(reports: Sequence[Mapping[str, Any]], options: ScorecardOptions) -> Dict[str, Any]:
    """One scorecard over ``reports``, which must all come from the same provider and models."""
    if not reports:
        raise ScorecardError("give at least one evaluation report")
    model = _model(reports[0])
    for report in reports[1:]:
        if _model(report) != model:
            raise ScorecardError(f"the reports come from different models: {model} and {_model(report)}")
    cards = [dataset_card(report) for report in reports]
    return {
        "scorecard_version": SCORECARD_VERSION,
        "title": options.title or f"Scorecard v{SCORECARD_VERSION}: {model['fast_model'] or 'unknown model'}",
        "internal_only": _internal_only(model, cards, options),
        "model": model,
        "prompt_version": _prompts(reports, options),
        "lg_sotf_versions": sorted({str(r.get("lg_sotf_version")) for r in reports}),
        "generated_at": sorted(str(r.get("generated_at")) for r in reports),
        "datasets": cards,
        "notes": list(options.notes),
        "limitations": _limitations(reports, cards, model, options),
    }


def _internal_only(model: Mapping[str, Any], cards: Sequence[Mapping[str, Any]], options: ScorecardOptions) -> bool:
    """Asked for, or an internal-only model measured on any dataset that is not synthetic."""
    names = " ".join(str(v or "") for v in model.values()).lower()
    restricted = any(tag in names for tag in INTERNAL_ONLY_MODELS)
    all_synthetic = all((card["dataset"] or {}).get("synthetic") is True for card in cards)
    return options.internal or (restricted and not all_synthetic)


def _limitations(
    reports: Sequence[Mapping[str, Any]],
    cards: Sequence[Mapping[str, Any]],
    model: Mapping[str, Any],
    options: ScorecardOptions,
) -> List[str]:
    out: List[str] = []
    synthetic = [card["dataset"] or {} for card in cards if (card["dataset"] or {}).get("synthetic")]
    if synthetic and all(int(ds.get("items") or 0) < GENERATED_CORPUS_ITEMS for ds in synthetic):
        out.append(
            "The data is synthetic: hand-written alerts with labels assigned by construction, a few dozen items per "
            "set. It shows how the pipeline and model behave on scenarios we wrote, not accuracy on real telemetry."
        )
    elif synthetic:
        out.append(
            "The data is synthetic: generated alerts (attack emulation and benign activity) labelled from the "
            "procedure that produced them. It shows how the pipeline and model behave on realistic alert shapes, "
            "not accuracy on a customer's real telemetry."
        )
    out.append(
        "Small samples: read the 95% Wilson intervals, not the point estimates. Two models whose intervals overlap "
        "have not been shown to differ."
    )
    out.append(
        "Escalated items were not reviewed (the harness never invents an analyst decision). The false-negative rate "
        "counts only malicious items automation closed as benign; an escalated malicious item is not a miss."
    )
    if model.get("llm_provider") == "fake":
        out.append("The fake provider is a keyword heuristic: these numbers measure plumbing and policy, not a model.")
    for card in cards:
        sel = card.get("selection") or {}
        if sel.get("limit") or sel.get("splits") or sel.get("tags"):
            out.append(f"{card['dataset']['path']}: a subset was evaluated ({_selection_text(sel)}).")
        if card["errors"]:
            out.append(f"{card['dataset']['path']}: {card['errors']} items errored and are excluded from every rate.")
    if not _prompts(reports, options):
        out.append("Prompt versions were not recorded; the lg-sotf version identifies the prompts shipped with it.")
    out.extend(options.notes)
    return out


def _selection_text(sel: Mapping[str, Any]) -> str:
    parts = []
    if sel.get("splits"):
        parts.append("splits " + ", ".join(sel["splits"]))
    if sel.get("tags"):
        parts.append("tags " + ", ".join(sel["tags"]))
    if sel.get("limit"):
        parts.append(f"first {sel['limit']} items")
    return "; ".join(parts)


def load_reports(paths: Sequence[str | Path]) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScorecardError(f"cannot read the report {path}: {exc}") from exc
        if not isinstance(data, dict) or "metrics" not in data or "items" not in data:
            raise ScorecardError(f"{path} is not an lg-sotf eval report")
        reports.append(data)
    return reports


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{100 * float(value):.1f}%"


def _num(value: Any, digits: int = 3) -> str:
    return "n/a" if value is None else f"{float(value):.{digits}f}"


def _usd(value: Any) -> str:
    return "n/a" if value is None else f"${float(value):.6f}"


def _ci(prop: Mapping[str, Any]) -> str:
    ci = prop.get("ci95")
    return "n/a" if not ci else f"{_pct(ci[0])} to {_pct(ci[1])}"


def _interval(prop: Mapping[str, Any]) -> RateInterval:
    ci = prop.get("ci95") or (None, None)
    return RateInterval(rate=prop["rate"], n=prop["n"], ci_low=ci[0], ci_high=ci[1])


def _rate(prop: Mapping[str, Any]) -> str:
    """``93.3% (14 of 15; 95% CI 70.2% to 98.8%)``, or ``Not enough data (n=0)``."""
    return format_rate(_interval(prop))


def _label(card: Mapping[str, Any]) -> str:
    return f"`{Path(str(card['dataset'].get('path'))).stem}`"


def _header(card: Mapping[str, Any]) -> List[str]:
    model = card["model"]
    prompts = card["prompt_version"]
    if isinstance(prompts, (dict, list)):
        prompts = json.dumps(prompts, sort_keys=True)
    lines = [f"# {card['title']}", ""]
    if card["internal_only"]:
        lines += ["> **INTERNAL ONLY: not for publication.** Internal comparison only.", ""]
    lines += [
        "| Field | Value |",
        "|---|---|",
        f"| Provider | {model['llm_provider']} |",
        f"| Fast model | {model['fast_model']} |",
        f"| Deep model | {model['deep_model']} |",
        f"| Prompt version | {prompts or NOT_RECORDED + ' (prompt hashes arrive with AI-E1.2)'} |",
        f"| lg-sotf version | {', '.join(card['lg_sotf_versions'])} |",
        f"| Reports generated | {', '.join(card['generated_at'])} |",
        f"| Scorecard format | v{card['scorecard_version']} |",
        "",
    ]
    return lines


def _closure_rate(rate: Mapping[str, Any]) -> str:
    return format_rate(rate_interval(int(rate["k"]), int(rate["n"])))


def _closure(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    """The two headline numbers per dataset, then what closed each item (mechanism) and every closed malicious id."""
    lines = [
        "## Headline: closure",
        "",
        "Benign closure rate: expected-benign items automation closed as benign (95% Wilson interval). Malicious "
        "auto-close: expected-malicious items automation closed with any disposition, with the exact one-sided 95% "
        "upper bound.",
        "",
        "| Dataset | Benign closure rate | Malicious auto-close |",
        "|---|---|---|",
    ]
    for card in cards:
        h = card["closure"]["headline"]
        lines.append(f"| {_label(card)} | {_closure_rate(h['benign_closure'])} | "
                     f"{malicious_cell(h['malicious_auto_close'])} |")
    lines += ["", "| Dataset | Mechanism | Benign closed | Malicious closed |", "|---|---|---|---|"]
    for card in cards:
        for row in card["closure"]["by_mechanism"]:
            lines.append(f"| {_label(card)} | {row['mechanism']} | {_closure_rate(row['benign'])} | {row['malicious']} |")
    lines.append("")
    for card in cards:
        closed = card["closure"].get("malicious_closed") or []
        if closed:
            ids = ", ".join(f"`{c['item_id']}` ({c['mechanism'] or 'unknown'})" for c in closed)
            lines += [f"Malicious closed in {_label(card)}: {ids}.", ""]
    return lines


def _headline(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    lines = [
        "## Malicious false-negative rate",
        "",
        "Expected-malicious items that automation closed as benign without a human. Lower is better; the target is 0.",
        "",
        "| Dataset | Missed | n | Rate | 95% Wilson interval |",
        "|---|---|---|---|---|",
    ]
    for card in cards:
        rows = [(_label(card), card["malicious_false_negative"])]
        rows += [(f"{_label(card)} split `{name}`", s["malicious_false_negative"]) for name, s in card["splits"].items()]
        for label, prop in rows:
            lines.append(f"| {label} | {prop['k']} | {prop['n']} | {_pct(prop['rate'])} | {_ci(prop)} |")
    lines.append("")
    for card in cards:
        if card["missed_malicious_ids"]:
            missed = ", ".join(f"`{i}`" for i in card["missed_malicious_ids"])
            lines += [f"Missed in {_label(card)}: {missed}.", ""]
    return lines


def _automation(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    lines = [
        "## Automation",
        "",
        "Auto-close precision: of the items automation closed on its own, the share whose closing disposition matches "
        "the expected one. Escalation rate: items handed to an analyst.",
        "",
        "| Dataset | Auto-close precision | Auto-close rate | Escalation rate | Approval requests | Errors |",
        "|---|---|---|---|---|---|",
    ]
    for card in cards:
        cells = [_rate(card[key]) for key in ("auto_close_precision", "auto_close", "escalation", "approval_request")]
        lines.append(f"| {_label(card)} | " + " | ".join(cells) + f" | {_rate(card['error'])} |")
    lines.append("")
    return lines


def _per_class(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    lines = [
        "## Per class",
        "",
        "Predicted disposition against the expected one (an escalated item counts as the analysis verdict, "
        "`inconclusive` without one). Precision and recall carry k of n and a 95% Wilson interval; F1 is not a "
        "proportion and has none.",
        "",
        "| Dataset | Class | Precision | Recall | F1 | Support | Predicted |",
        "|---|---|---|---|---|---|---|",
    ]
    for card in cards:
        for cls, s in card["per_class"].items():
            if not s:
                continue
            ci = card["per_class_intervals"][cls]
            precision, recall = (format_rate(RateInterval.model_validate(ci[k])) for k in ("precision", "recall"))
            lines.append(
                f"| {_label(card)} | {cls} | {precision} | {recall} | {_num(s['f1'])} | {s['support']} | "
                f"{s['predicted']} |"
            )
        lines.append(f"| {_label(card)} | macro F1 | | | {_num(card['macro_f1'])} | | |")
    lines.append("")
    return lines


def _cost(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    lines = [
        "## Cost and latency per item",
        "",
        "| Dataset | Cost per item | Total cost | Tokens per item | LLM calls per item | Latency mean / p50 / p95 / max (s) |",
        "|---|---|---|---|---|---|",
    ]
    for card in cards:
        lat = card["latency_s"] or {}
        latency = " / ".join(_num(lat.get(k), 1) for k in ("mean", "p50", "p95", "max"))
        lines.append(
            f"| {_label(card)} | {_usd(card['cost_per_item_usd'])} | {_usd(card['total_cost_usd'])} | "
            f"{_num(card['tokens_per_item'], 0)} | {_num(card['llm_calls_per_item'], 1)} | {latency} |"
        )
    lines.append("")
    return lines


def _datasets(cards: Sequence[Mapping[str, Any]]) -> List[str]:
    lines = [
        "## Datasets",
        "",
        "| Dataset | Path | sha256 | Items | Scored | Synthetic | Splits |",
        "|---|---|---|---|---|---|---|",
    ]
    for card in cards:
        ds = card["dataset"]
        splits = ", ".join(f"{k}: {v}" for k, v in (ds.get("splits") or {}).items())
        lines.append(
            f"| {_label(card)} | `{ds.get('path')}` | `{str(ds.get('sha256'))[:12]}` | {ds.get('items')} | "
            f"{card['scored']} | {'yes' if ds.get('synthetic') else 'no'} | {splits} |"
        )
    lines.append("")
    return lines


def render_scorecard(card: Mapping[str, Any]) -> str:
    """The scorecard as Markdown: header, closure headline, false-negative rate, automation, per class, cost."""
    cards = card["datasets"]
    lines = _header(card) + _closure(cards) + _headline(cards) + _automation(cards) + _per_class(cards) + _cost(cards)
    lines += _datasets(cards)
    lines += ["## Limitations", ""] + [f"- {note}" for note in card["limitations"]] + [""]
    return "\n".join(lines)


def write_scorecard(
    report_paths: Sequence[str | Path],
    output: str | Path,
    options: ScorecardOptions,
    json_output: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Build the scorecard of ``report_paths`` and write it as Markdown (and JSON when asked)."""
    card = build_scorecard(load_reports(report_paths), options)
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_scorecard(card), encoding="utf-8")
    if json_output is not None:
        Path(json_output).write_text(json.dumps(card, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return card
