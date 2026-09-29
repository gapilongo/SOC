"""Evaluation reports: one JSON document (machine-readable, gated) and a Markdown rendering."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf import __version__
from lg_sotf.eval.dataset import DISPOSITIONS, Dataset
from lg_sotf.eval.metrics import compute_metrics, metrics_by_split
from lg_sotf.eval.results import ItemResult

REPORT_SCHEMA_VERSION = 1
FAKE_MODEL_NOTE = (
    "The fake LLM provider is a deterministic keyword heuristic, not a detection model: these metrics "
    "measure the pipeline's plumbing and policy (ingestion, routing, safety rules, escalation), not "
    "model quality."
)
SYNTHETIC_NOTE = (
    "The dataset is synthetic: hand-written alerts with labels assigned by construction. It exercises "
    "the pipeline; it says nothing about accuracy on real customer telemetry."
)
UNREVIEWED_NOTE = (
    "Runs that stopped for analyst review or action approval were recorded as 'unreviewed': the "
    "harness never supplies an analyst decision."
)


def build_report(
    results: Sequence[ItemResult],
    *,
    dataset: Dataset,
    run_info: Optional[Mapping[str, Any]] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    info = dict(run_info or {})
    notes: List[str] = [UNREVIEWED_NOTE]
    if info.get("llm_provider") == "fake":
        notes.insert(0, FAKE_MODEL_NOTE)
    if dataset.synthetic:
        notes.insert(0, SYNTHETIC_NOTE)
    splits = metrics_by_split(results)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "lg_sotf_version": __version__,
        "dataset": {
            "path": dataset.path,
            "sha256": dataset.sha256,
            "items": len(dataset.items),
            "synthetic": dataset.synthetic,
            "description": dataset.meta.get("description"),
            "splits": dataset.splits(),
        },
        "run": info,
        "notes": notes,
        "metrics": compute_metrics(results),
        "splits": {name: {"metrics": m} for name, m in splits.items()},
        "items": [r.as_dict() for r in results],
    }


def write_json(report: Mapping[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8")


def load_report(path: str | Path) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "metrics" not in data:
        raise ValueError(f"{path} is not an evaluation report")
    return data


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{100 * float(value):.1f}%"


def _num(value: Any, digits: int = 3) -> str:
    return "n/a" if value is None else f"{float(value):.{digits}f}"


def _usd(value: Any) -> str:
    return "n/a" if value is None else f"${float(value):.6f}"


def _latency(metrics: Mapping[str, Any]) -> str:
    lat = metrics.get("latency_s") or {}
    return " / ".join(_num(lat.get(k)) for k in ("mean", "p50", "p95", "max"))


def _escape(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


HEADLINE_ROWS = (
    ("Malicious false-negative rate (auto-closed as benign)", "malicious_false_negative_rate", _pct),
    ("Benign auto-close rate", "benign_auto_close_rate", _pct),
    ("Benign routed to response", "benign_auto_response_rate", _pct),
    ("High/critical closed by automation as not malicious", "high_severity_auto_closed_benign", lambda v: _num(v, 0)),
    ("High/critical closed as malicious after a policy response", "high_severity_auto_closed_malicious",
     lambda v: _num(v, 0)),
    ("Escalation rate (analyst review requested)", "escalation_rate", _pct),
    ("Approval request rate", "approval_request_rate", _pct),
    ("Inconclusive rate", "inconclusive_rate", _pct),
    ("Model refusal rate", "model_refusal_rate", _pct),
    ("Error rate", "error_rate", _pct),
    ("Accuracy (predicted vs expected)", "accuracy", _pct),
    ("Macro F1", "macro_f1", _num),
    ("Cohen's kappa (predicted vs expected)", "kappa_vs_expected", _num),
    ("Route accuracy (labelled items)", "route_accuracy", _pct),
    ("Escalation accuracy (labelled items)", "escalation_accuracy", _pct),
    ("Cost per alert", "cost_per_alert_usd", _usd),
    ("Tokens per alert", "tokens_per_alert", lambda v: _num(v, 0)),
    ("LLM calls per alert", "llm_calls_per_alert", lambda v: _num(v, 1)),
)


def render_markdown(report: Mapping[str, Any], gate: Optional[Mapping[str, Any]] = None) -> str:
    m = report["metrics"]
    ds = report["dataset"]
    run = report.get("run") or {}
    lines: List[str] = ["# LG-SOTF evaluation report", ""]
    lines.append(f"Generated {report['generated_at']} by lg-sotf {report['lg_sotf_version']}.")
    lines.append("")
    for note in report.get("notes") or []:
        lines.append(f"> {note}")
        lines.append("")
    lines.append("## Run")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Dataset | `{_escape(ds.get('path'))}` ({ds['items']} items, sha256 `{str(ds.get('sha256'))[:12]}`) |")
    lines.append(f"| Synthetic | {'yes' if ds.get('synthetic') else 'no'} |")
    lines.append(f"| Splits | {', '.join(f'{k}: {v}' for k, v in (ds.get('splits') or {}).items())} |")
    for key in ("llm_provider", "fast_model", "deep_model", "isolation", "tenant_id", "concurrency", "duration_s"):
        if run.get(key) is not None:
            lines.append(f"| {key} | {_escape(run[key])} |")
    if run.get("tenants"):
        tenants = ", ".join(f"{k}: {v}" for k, v in run["tenants"].items())
        lines.append(f"| tenants | {_escape(tenants)} |")
    if run.get("selection"):
        sel = run["selection"]
        lines.append(
            f"| selection | splits {_escape(sel.get('splits') or 'all')}, tags {_escape(sel.get('tags') or 'none')}, "
            f"limit {_escape(sel.get('limit') or 'none')} |"
        )
    lines.append("")
    if gate is not None:
        lines.append("## Gate")
        lines.append("")
        lines.append(f"**{'PASSED' if gate['passed'] else 'FAILED'}** ({gate['checked']} checks).")
        lines.append("")
        for v in gate["violations"]:
            lines.append(f"- {_escape(v['message'])}")
        if gate["violations"]:
            lines.append("")
    lines.append("## Headline metrics")
    lines.append("")
    split_names = list((report.get("splits") or {}).keys())
    header = "| Metric | All | " + " | ".join(split_names) + " |"
    lines.append(header)
    lines.append("|---|---|" + "---|" * len(split_names))
    for label, key, fmt in HEADLINE_ROWS:
        cells = [fmt(m.get(key))]
        for name in split_names:
            cells.append(fmt(report["splits"][name]["metrics"].get(key)))
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    latency_cells = [_latency(m)] + [_latency(report["splits"][n]["metrics"]) for n in split_names]
    lines.append("| Latency mean / p50 / p95 / max (s) | " + " | ".join(latency_cells) + " |")
    lines.append("")
    lines.append(
        f"Items: {m['items']} ({m['scored']} scored, {m['errors']} errors); "
        f"expected malicious {m['malicious_items']}, benign {m['benign_items']}. "
        f"Total LLM cost {_usd(m.get('total_cost_usd'))} "
        f"(including {_usd(m.get('errored_cost_usd'))} spent on items that errored)."
    )
    lines.append("")
    if m.get("missed_malicious_ids"):
        lines.append("Missed malicious items: " + ", ".join(f"`{i}`" for i in m["missed_malicious_ids"]) + ".")
        lines.append("")
    lines.append("## Per class")
    lines.append("")
    lines.append("| Class | Precision | Recall | F1 | Support | Predicted |")
    lines.append("|---|---|---|---|---|---|")
    for cls, s in m["per_class"].items():
        lines.append(
            f"| {cls} | {_num(s['precision'])} | {_num(s['recall'])} | {_num(s['f1'])} | {s['support']} | {s['predicted']} |"
        )
    lines.append("")
    lines.append("## Confusion matrix (rows: expected, columns: predicted)")
    lines.append("")
    matrix = m["confusion_matrix"]
    cols = list(next(iter(matrix.values())).keys()) if matrix else list(DISPOSITIONS)
    lines.append("| Expected \\ Predicted | " + " | ".join(cols) + " |")
    lines.append("|---|" + "---|" * len(cols))
    for expected, row in matrix.items():
        lines.append(f"| {expected} | " + " | ".join(str(row[c]) for c in cols) + " |")
    lines.append("")
    iak = m.get("inter_annotator_kappa") or {}
    lines.append("## Inter-annotator agreement")
    lines.append("")
    if iak.get("pairs"):
        lines.append("| Annotators | Items | Kappa |")
        lines.append("|---|---|---|")
        for pair, v in iak["pairs"].items():
            lines.append(f"| {_escape(pair)} | {v['items']} | {_num(v['kappa'])} |")
        lines.append("")
        lines.append(f"Mean pairwise kappa: {_num(iak.get('mean'))}.")
    else:
        lines.append("Not computed: no two annotators labelled at least two common items.")
    lines.append("")
    lines.append("## Items")
    lines.append("")
    lines.append("| Item | Split | Expected | Predicted | Status | Route | Review | Tokens | Latency (s) | Note |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for item in report.get("items") or []:
        mark = ""
        if item["status"] == "error":
            mark = _escape(item.get("error") or "error")
        elif item["expected"] == "malicious" and item["status"] == "closed" and item.get("disposition") == "benign":
            mark = "MISSED"
        lines.append(
            f"| `{_escape(item['item_id'])}` | {_escape(item['split'])} | {item['expected']} | "
            f"{item.get('predicted') or 'n/a'} | {item['status']} | {item.get('route') or 'n/a'} | "
            f"{item.get('review') or ''} | {item.get('total_tokens', 0)} | {_num(item.get('latency_s'))} | {mark} |"
        )
    lines.append("")
    return "\n".join(lines)


def summary_lines(report: Mapping[str, Any], gate: Optional[Mapping[str, Any]] = None) -> List[str]:
    """A short plain-text summary for the terminal."""
    m = report["metrics"]
    out = [
        f"items {m['items']} (scored {m['scored']}, errors {m['errors']})",
        f"malicious false-negative rate {_pct(m['malicious_false_negative_rate'])}"
        f" ({m['malicious_false_negatives']} of {m['malicious_items']})",
        f"benign auto-close rate {_pct(m['benign_auto_close_rate'])}; escalation rate {_pct(m['escalation_rate'])};"
        f" inconclusive rate {_pct(m['inconclusive_rate'])}",
        f"macro F1 {_num(m['macro_f1'])}; kappa vs expected {_num(m['kappa_vs_expected'])}",
        f"cost per alert {_usd(m['cost_per_alert_usd'])}; latency p95 {_num((m.get('latency_s') or {}).get('p95'))} s",
    ]
    for name, split in (report.get("splits") or {}).items():
        sm = split["metrics"]
        out.append(
            f"split {name}: {sm['items']} items, malicious FNR {_pct(sm['malicious_false_negative_rate'])}, "
            f"escalation {_pct(sm['escalation_rate'])}"
        )
    if gate is not None:
        out.append(f"gate {'PASSED' if gate['passed'] else 'FAILED'} ({gate['checked']} checks)")
        out.extend(f"  - {v['message']}" for v in gate["violations"])
    return out
