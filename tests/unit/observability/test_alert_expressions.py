"""OBS-1: the ratio alerts in docs/operations.md aggregate before they divide.

``rate(x{outcome="error"}) / rate(x)`` divides series by series: PromQL
matches the two sides one to one on their full label sets, so the error
series is divided by itself and the "ratio" is 1 whenever any error occurs
(the alert pages on a single failed call). Both sides must be summed first.

promtool is not a dependency of this repository, so this test evaluates the
documented expressions with a small evaluator for the PromQL subset they use
(``sum [by (...)]``, ``rate(selector[range])`` read as given per-second rates,
``/`` with one-to-one matching, ``> threshold``) on sample series, and checks
that the evaluator reproduces the original bug.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

import pytest

pytestmark = pytest.mark.unit

OPERATIONS = Path(__file__).resolve().parents[3] / "docs" / "operations.md"

Labels = Tuple[Tuple[str, str], ...]
Vector = Dict[Labels, float]
Series = List[Tuple[Mapping[str, str], float]]

_VECTOR = re.compile(
    r"(?P<sum>sum(?:\s+by\s*\((?P<by>[^)]*)\))?\s*\(\s*)?"
    r"rate\((?P<name>[a-z_:]+)(?:\{(?P<matchers>[^}]*)\})?\[\d+[smhd]\]\)"
    r"(?(sum)\s*\))"
)
_ALERT = re.compile(r"(?P<left>.+?)\s+/\s+(?P<right>.+?)\s+>\s+(?P<threshold>[0-9.]+)")
_MATCHER = re.compile(r'\s*(?P<label>[a-z_]+)\s*(?P<op>=~|!~|!=|=)\s*"(?P<value>[^"]*)"\s*')

# The expression shipped before OBS-1 (docs/operations.md, "LLM errors").
BUGGY_LLM_ERRORS = (
    'rate(lgsotf_llm_calls_total{mode="live",outcome=~"error|invalid_output"}[10m]) '
    '/ rate(lgsotf_llm_calls_total{mode="live"}[10m]) > 0.1'
)


def _matches(labels: Mapping[str, str], matchers: str) -> bool:
    for part in filter(None, (p.strip() for p in matchers.split(","))):
        m = _MATCHER.fullmatch(part)
        assert m, f"unsupported matcher {part!r}"
        value = labels.get(m["label"], "")
        op = m["op"]
        ok = {
            "=": value == m["value"],
            "!=": value != m["value"],
            "=~": re.fullmatch(m["value"], value) is not None,
            "!~": re.fullmatch(m["value"], value) is None,
        }[op]
        if not ok:
            return False
    return True


def _vector(text: str, series: Series) -> Vector:
    """One side of the division: ``rate(selector)`` (per-second rates as given), optionally summed."""
    m = _VECTOR.fullmatch(text.strip())
    assert m, f"unsupported vector expression {text!r}"
    selected = [
        (labels, rate)
        for labels, rate in series
        if labels["__name__"] == m["name"] and _matches(labels, m["matchers"] or "")
    ]
    if not m["sum"]:
        # rate() drops the metric name and keeps every other label.
        return {tuple(sorted((k, v) for k, v in labels.items() if k != "__name__")): rate for labels, rate in selected}
    by = [b.strip() for b in (m["by"] or "").split(",") if b.strip()]
    out: Vector = {}
    for labels, rate in selected:
        key = tuple(sorted((k, labels.get(k, "")) for k in by))
        out[key] = out.get(key, 0.0) + rate
    return out


def evaluate(expr: str, series: Series) -> Vector:
    """``left / right > threshold`` with PromQL's default one-to-one matching on identical label sets."""
    m = _ALERT.fullmatch(expr.strip())
    assert m, f"unsupported alert expression {expr!r}"
    left, right = _vector(m["left"], series), _vector(m["right"], series)
    ratios = {labels: value / right[labels] for labels, value in left.items() if right.get(labels)}
    return {labels: ratio for labels, ratio in ratios.items() if ratio > float(m["threshold"])}


def documented(alert: str) -> str:
    """The condition column of one row of the "Alerts to create" table (``\\|`` unescaped)."""
    for line in OPERATIONS.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"| {alert} |"):
            cell = re.split(r"(?<!\\)\|", line)[2].strip()
            return cell.strip("`").replace("\\|", "|")
    raise AssertionError(f"alert {alert!r} not in {OPERATIONS.name}")


def llm_calls(success: float, error: float, invalid: float, *, shadow_error: float = 0.0) -> Series:
    """Per-second call rates for two agents of one model, plus a failing shadow pipeline."""
    def calls(agent: str, outcome: str, mode: str) -> Dict[str, str]:
        return {"__name__": "lgsotf_llm_calls_total", "model": "m1", "agent": agent, "outcome": outcome, "mode": mode}

    series: Series = [
        (calls(agent, outcome, "live"), rate * share)
        for agent, share in (("triage", 0.6), ("analysis", 0.4))
        for outcome, rate in (("success", success), ("error", error), ("invalid_output", invalid))
    ]
    series.append((calls("triage", "error", "shadow"), shadow_error))
    return series


def _single(result: Vector) -> Optional[float]:
    assert len(result) <= 1, f"the alert must yield one aggregated series, got {result}"
    return next(iter(result.values()), None)


def test_the_evaluator_reproduces_the_one_to_one_matching_bug() -> None:
    # 2 % of calls fail, yet every failing series is divided by itself: ratio 1, the alert pages.
    fired = evaluate(BUGGY_LLM_ERRORS, llm_calls(success=9.8, error=0.1, invalid=0.1))
    assert fired and set(fired.values()) == {1.0}


@pytest.mark.parametrize(
    ("success", "error", "invalid", "expected"),
    [
        (9.8, 0.1, 0.1, None),  # 2 % errors: below the 10 % threshold, no page
        (9.5, 0.3, 0.2, None),  # 5 %
        (8.5, 1.0, 0.5, 0.15),  # 15 %: pages, with the true ratio as its value
        (0.0, 1.0, 0.0, 1.0),  # every call fails
        (10.0, 0.0, 0.0, None),  # no errors at all
    ],
)
def test_llm_errors_alert_pages_on_the_aggregate_error_ratio(
    success: float, error: float, invalid: float, expected: Optional[float]
) -> None:
    expr = documented("LLM errors")
    # Shadow runs of a candidate pipeline never count, however badly they fail.
    value = _single(evaluate(expr, llm_calls(success, error, invalid, shadow_error=50.0)))
    assert value == pytest.approx(expected) if expected is not None else value is None


def test_llm_errors_alert_selects_live_calls_on_both_sides() -> None:
    m = _ALERT.fullmatch(documented("LLM errors"))
    assert m
    for side in (m["left"], m["right"]):
        assert side.startswith("sum(") and 'mode="live"' in side, side


def _runs(**rates: float) -> Series:
    return [({"__name__": "lgsotf_runs_total", "outcome": outcome}, rate) for outcome, rate in rates.items()]


def test_run_failures_alert_pages_on_the_aggregate_failure_ratio() -> None:
    expr = documented("Run failures")
    # 0.7 of 10 runs per second failed or were dead-lettered: 7 %, above the 5 % threshold.
    paging = _runs(completed=9.0, waiting=0.3, failed=0.5, dead_lettered=0.2, skipped=0.0)
    assert _single(evaluate(expr, paging)) == pytest.approx(0.07)
    # 0.3 of 9.6: about 3 %, no page (the unaggregated form gave 1 for each failing outcome).
    calm = _runs(completed=9.0, waiting=0.3, failed=0.1, dead_lettered=0.2, skipped=0.0)
    assert _single(evaluate(expr, calm)) is None
