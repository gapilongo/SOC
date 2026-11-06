"""Evaluation metrics: pure functions over :class:`~lg_sotf.eval.results.ItemResult` lists.

Definitions (``scored`` = items that did not error; rates are fractions in
``[0, 1]``; a rate whose denominator is zero is ``None``, never 0):

* ``malicious_false_negative_rate`` (headline): expected-malicious items the
  platform *closed on its own* as benign, over scored expected-malicious
  items. An escalated malicious alert is not a false negative: a human sees
  it.
* ``benign_auto_close_rate``: expected-benign items closed as benign without
  a human, over scored expected-benign items (the analyst work saved).
* ``benign_auto_response_rate``: expected-benign items the policy routed to
  a response plan (automation treating noise as a threat).
* ``high_severity_auto_closed_benign`` (safety property): high/critical
  items automation closed with a disposition other than ``malicious``. The
  routing policy never closes a high/critical alert as benign on its own;
  only a suppression rule or an analyst-confirmed verdict can, and an
  evaluation tenant has neither, so this should be 0.
  ``high_severity_auto_closed_malicious``: high/critical items closed as
  ``malicious`` after a policy response whose actions completed (autonomy
  ``auto`` for a non-containment action, or rule-corroborated containment).
  That is correct behaviour, reported so it can be watched, not gated at 0.
* ``escalation_rate``: scored items for which analyst review was requested.
  ``approval_request_rate``: scored items waiting for action approval.
* ``inconclusive_rate``: scored items whose predicted disposition is
  ``inconclusive``.
* ``per_class``: precision, recall and F1 of ``predicted`` against the
  expected disposition, per class; ``macro_f1`` averages the classes that
  appear in either column.
* ``kappa_vs_expected``: Cohen's kappa between predicted and expected.
  ``inter_annotator_kappa``: Cohen's kappa for every annotator pair that
  labelled at least two common items (items with several ``labels``).
* Cost and latency: per-alert means over scored items; latency also
  p50/p95/max. ``total_cost_usd`` and ``total_tokens`` include errored items
  (model calls made before a failure are still billed);
  ``errored_cost_usd`` is their share.
"""

from __future__ import annotations

import math
from itertools import combinations
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.eval.dataset import DISPOSITIONS
from lg_sotf.eval.results import ItemResult
from lg_sotf.models.vocabulary import HIGH_SEVERITIES

Pair = Tuple[str, str]


def ratio(numerator: int, denominator: int) -> Optional[float]:
    return None if denominator == 0 else numerator / denominator


def confusion_matrix(pairs: Iterable[Pair], classes: Sequence[str] = DISPOSITIONS) -> Dict[str, Dict[str, int]]:
    """``matrix[expected][predicted]`` counts; labels outside ``classes`` are added as extra rows/columns."""
    pairs = list(pairs)
    labels = list(classes)
    for expected, predicted in pairs:
        for label in (expected, predicted):
            if label not in labels:
                labels.append(label)
    matrix = {e: {p: 0 for p in labels} for e in labels}
    for expected, predicted in pairs:
        matrix[expected][predicted] += 1
    return matrix


def per_class_scores(pairs: Iterable[Pair], classes: Sequence[str] = DISPOSITIONS) -> Dict[str, Dict[str, Any]]:
    """Precision, recall, F1 and support per class. Undefined values (0/0) are ``None``."""
    pairs = list(pairs)
    out: Dict[str, Dict[str, Any]] = {}
    for cls in classes:
        tp = sum(1 for e, p in pairs if e == cls and p == cls)
        fp = sum(1 for e, p in pairs if e != cls and p == cls)
        fn = sum(1 for e, p in pairs if e == cls and p != cls)
        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        if precision is None or recall is None:
            f1: Optional[float] = None
        elif precision + recall == 0:
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)
        out[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": tp + fn,
            "predicted": tp + fp,
        }
    return out


def macro_f1(scores: Mapping[str, Mapping[str, Any]]) -> Optional[float]:
    """Mean F1 over classes that occur as expected or predicted; a class with undefined F1 counts as 0."""
    present = [s for s in scores.values() if s["support"] or s["predicted"]]
    if not present:
        return None
    return sum(float(s["f1"] or 0.0) for s in present) / len(present)


def cohen_kappa(a: Sequence[str], b: Sequence[str]) -> Optional[float]:
    """Cohen's kappa of two equally long label sequences.

    ``None`` for fewer than two items. When both raters use a single, identical
    label throughout (expected agreement 1), agreement is perfect and kappa
    is 1.0; otherwise ``(p_o - p_e) / (1 - p_e)``.
    """
    if len(a) != len(b):
        raise ValueError("label sequences must have the same length")
    n = len(a)
    if n < 2:
        return None
    labels = sorted(set(a) | set(b))
    observed = sum(1 for x, y in zip(a, b, strict=True) if x == y) / n
    expected = sum((a.count(label) / n) * (b.count(label) / n) for label in labels)
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1 - expected)


def inter_annotator_kappa(results: Sequence[ItemResult]) -> Dict[str, Any]:
    """Pairwise Cohen's kappa for annotators sharing at least two items, and their mean."""
    annotators = sorted({name for r in results for name in r.labels})
    pairs: Dict[str, Dict[str, Any]] = {}
    for first, second in combinations(annotators, 2):
        common = [r for r in results if first in r.labels and second in r.labels]
        if len(common) < 2:
            continue
        kappa = cohen_kappa([r.labels[first] for r in common], [r.labels[second] for r in common])
        pairs[f"{first}|{second}"] = {"items": len(common), "kappa": kappa}
    values = [p["kappa"] for p in pairs.values() if p["kappa"] is not None]
    return {"pairs": pairs, "mean": (sum(values) / len(values)) if values else None}


def percentile(values: Sequence[float], q: float) -> Optional[float]:
    """Linear-interpolated percentile (``q`` in [0, 100]); ``None`` for no values."""
    if not values:
        return None
    if not 0 <= q <= 100:
        raise ValueError("q must be between 0 and 100")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * q / 100
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(ordered[low])
    return float(ordered[low] + (ordered[high] - ordered[low]) * (rank - low))


def _mean(values: Sequence[float]) -> Optional[float]:
    return (sum(values) / len(values)) if values else None


def compute_metrics(results: Sequence[ItemResult]) -> Dict[str, Any]:
    """Every metric of one result set (see the module docstring for definitions)."""
    total = len(results)
    scored = [r for r in results if r.scored]
    errors = total - len(scored)
    malicious = [r for r in scored if r.expected == "malicious"]
    benign = [r for r in scored if r.expected == "benign"]
    pairs: List[Pair] = [(r.expected, r.predicted or "inconclusive") for r in scored]
    scores = per_class_scores(pairs)

    missed = [r for r in malicious if r.auto_closed and r.disposition == "benign"]
    benign_closed = [r for r in benign if r.auto_closed and r.disposition == "benign"]
    benign_response = [r for r in benign if r.route == "plan_response"]
    routed = [r for r in scored if r.expected_route is not None]
    escalation_labelled = [r for r in scored if r.expected_escalation is not None]
    latencies = [r.latency_s for r in scored]

    return {
        "items": total,
        "scored": len(scored),
        "errors": errors,
        "error_rate": ratio(errors, total),
        "malicious_items": len(malicious),
        "benign_items": len(benign),
        "malicious_false_negatives": len(missed),
        "malicious_false_negative_rate": ratio(len(missed), len(malicious)),
        "missed_malicious_ids": [r.item_id for r in missed],
        "benign_auto_close_rate": ratio(len(benign_closed), len(benign)),
        "benign_auto_response_rate": ratio(len(benign_response), len(benign)),
        "high_severity_auto_closed_benign": sum(
            1 for r in scored if r.auto_closed and r.severity in HIGH_SEVERITIES and r.disposition != "malicious"
        ),
        "high_severity_auto_closed_malicious": sum(
            1 for r in scored if r.auto_closed and r.severity in HIGH_SEVERITIES and r.disposition == "malicious"
        ),
        "auto_close_rate": ratio(sum(1 for r in scored if r.auto_closed), len(scored)),
        "escalation_rate": ratio(sum(1 for r in scored if r.escalated), len(scored)),
        "approval_request_rate": ratio(sum(1 for r in scored if r.approval_requested), len(scored)),
        "inconclusive_rate": ratio(sum(1 for _, p in pairs if p == "inconclusive"), len(scored)),
        "model_refusal_rate": ratio(sum(1 for r in scored if r.model_refused), len(scored)),
        "accuracy": ratio(sum(1 for e, p in pairs if e == p), len(pairs)),
        "per_class": scores,
        "macro_f1": macro_f1(scores),
        "confusion_matrix": confusion_matrix(pairs),
        "kappa_vs_expected": cohen_kappa([e for e, _ in pairs], [p for _, p in pairs]),
        "inter_annotator_kappa": inter_annotator_kappa(results),
        "route_accuracy": ratio(sum(1 for r in routed if r.route == r.expected_route), len(routed)),
        "route_labelled_items": len(routed),
        "escalation_accuracy": ratio(
            sum(1 for r in escalation_labelled if (r.escalated or r.approval_requested) == r.expected_escalation),
            len(escalation_labelled),
        ),
        "escalation_labelled_items": len(escalation_labelled),
        "total_cost_usd": round(sum(r.cost_usd for r in results), 6),
        "errored_cost_usd": round(sum(r.cost_usd for r in results if not r.scored), 6),
        "total_tokens": sum(r.total_tokens for r in results),
        "cost_per_alert_usd": _mean([r.cost_usd for r in scored]),
        "tokens_per_alert": _mean([float(r.total_tokens) for r in scored]),
        "llm_calls_per_alert": _mean([float(r.llm_calls) for r in scored]),
        "latency_s": {
            "mean": _mean(latencies),
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "max": max(latencies) if latencies else None,
        },
    }


def metrics_by_split(results: Sequence[ItemResult]) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[ItemResult]] = {}
    for r in results:
        groups.setdefault(r.split, []).append(r)
    return {name: compute_metrics(group) for name, group in sorted(groups.items())}
