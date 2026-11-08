"""Shadow agreement report maths (AI-E1.5b): agreement with n and CI, confusion matrix, the cases that matter."""

from __future__ import annotations

from decimal import Decimal
from typing import Optional, Sequence

import pytest

from lg_sotf.domain.rates import rate_interval
from lg_sotf.domain.shadow_agreement import (
    LABELS,
    MAX_LISTED_CASES,
    NO_VERDICT,
    Comparison,
    Verdict,
    build_report,
    confusion_matrix,
    rate_text,
    render_markdown,
)

pytestmark = pytest.mark.unit


def row(
    alert_id: str, production: Optional[str], candidate: Optional[str], *, severity: str = "medium",
    production_actions: Sequence[str] = (), candidate_actions: Sequence[str] = (), error: Optional[str] = None,
    production_cost: str = "0", candidate_cost: str = "0", production_ms: int = 0, candidate_ms: int = 0,
) -> Comparison:
    return Comparison(
        alert_id=alert_id,
        severity=severity,
        production=Verdict(route=production, actions=tuple(production_actions), cost_usd=Decimal(production_cost),
                           latency_ms=production_ms, tokens=production_ms),
        candidate=Verdict(route=candidate, actions=tuple(candidate_actions), cost_usd=Decimal(candidate_cost),
                          latency_ms=candidate_ms, tokens=candidate_ms, error=error),
    )


def report(rows: Sequence[Comparison], min_samples: int = 30):  # type: ignore[no-untyped-def]
    return build_report(rows, report_id="shr_" + "a" * 32, tenant_id="t1", candidate="cand", min_samples=min_samples)


def test_confusion_matrix_counts_every_pair_and_lists_every_label() -> None:
    rows = [
        row("a1", "escalate", "close"),
        row("a2", "escalate", "escalate"),
        row("a3", "escalate", "escalate"),
        row("a4", "close", "plan_response"),
        row("a5", "plan_response", None, error="TimeoutError"),
        row("a6", None, "close"),
    ]
    matrix = confusion_matrix(rows)
    assert list(matrix) == list(LABELS) and all(list(r) == list(LABELS) for r in matrix.values())
    assert matrix["escalate"] == {"escalate": 2, "plan_response": 0, "close": 1, NO_VERDICT: 0}
    assert matrix["close"]["plan_response"] == 1
    assert matrix["plan_response"][NO_VERDICT] == 1
    assert matrix[NO_VERDICT]["close"] == 1
    assert sum(sum(r.values()) for r in matrix.values()) == len(rows)


def test_agreement_counts_failures_as_disagreement_with_n_and_wilson_interval() -> None:
    rows = [
        row("a1", "escalate", "close"),
        row("a2", "escalate", "escalate"),
        row("a3", "close", "close"),
        row("a4", "plan_response", "plan_response"),
        row("a5", "escalate", None, error="RuntimeError"),
        row("a6", None, "close"),
    ]
    r = report(rows)
    assert (r.alerts, r.compared, r.candidate_failed, r.no_production_verdict) == (6, 4, 1, 1)
    assert r.agreement == rate_interval(3, 5)
    assert r.agreement.n == 5 and r.agreement.ci_low is not None and r.agreement.ci_high is not None
    assert r.agreement.ci_low < 0.6 < r.agreement.ci_high
    assert r.agreement_usable == rate_interval(3, 4)
    by_class = {c.production_route: c.agreement for c in r.by_class}
    assert by_class["escalate"] == rate_interval(1, 3)
    assert by_class["close"] == rate_interval(1, 1)
    assert by_class["plan_response"] == rate_interval(1, 1)
    assert not r.enough_data
    assert r.agreement_text.startswith("Not enough data (n=5; at least 30 needed): 60.0% (3 of 5; 95% CI")
    assert [c.alert_id for c in r.candidate_failures.items] == ["a5"]


def test_rate_text_uses_the_shared_wording() -> None:
    assert rate_text(rate_interval(0, 0)) == "Not enough data (n=0; at least 30 needed)"
    assert rate_text(rate_interval(28, 30)).startswith("93.3% (28 of 30; 95% CI ")
    assert rate_text(rate_interval(28, 30), min_samples=31).startswith("Not enough data (n=30; at least 31 needed)")


def test_new_potential_misses_are_listed_most_severe_first() -> None:
    rows = [
        row("low-1", "escalate", "close", severity="low"),
        row("crit-1", "escalate", "close", severity="critical"),
        row("resp-1", "plan_response", "close", severity="high"),
        row("agree", "escalate", "escalate", severity="critical"),
        row("more-work", "close", "escalate", severity="high"),
        row("failed", "escalate", None, error="TimeoutError", severity="critical"),
    ]
    r = report(rows)
    assert r.potential_misses.count == 3
    assert [c.alert_id for c in r.potential_misses.items] == ["crit-1", "resp-1", "low-1"]
    assert all(c.candidate_route == "close" for c in r.potential_misses.items)
    assert [c.alert_id for c in r.new_escalations.items] == ["more-work"]
    text = render_markdown(r)
    assert text.index("Potential misses") < text.index("New escalations") < text.index("Different response plans")
    assert text.index("`crit-1`") < text.index("`resp-1`") < text.index("`low-1`")


def test_listing_is_capped_but_counts_everything() -> None:
    rows = [row(f"a{i:03}", "escalate", "close") for i in range(MAX_LISTED_CASES + 5)]
    r = report(rows)
    assert r.potential_misses.count == MAX_LISTED_CASES + 5
    assert len(r.potential_misses.items) == MAX_LISTED_CASES
    assert "5 more not listed." in render_markdown(r)


def test_plan_differences_only_where_both_responded_automatically() -> None:
    rows = [
        row("same", "plan_response", "plan_response", production_actions=["block_ip:203.0.113.7"],
            candidate_actions=["block_ip:203.0.113.7"]),
        row("differs", "plan_response", "plan_response", production_actions=["block_ip:203.0.113.7"],
            candidate_actions=["block_ip:203.0.113.7", "isolate_host:ws-1"]),
        # Production responded after an analyst confirmed: not an automatic plan to compare.
        row("after-analyst", "escalate", "escalate", production_actions=["block_ip:203.0.113.7"]),
    ]
    r = report(rows)
    assert [c.alert_id for c in r.plan_differences.items] == ["differs"]
    assert r.plan_differences.items[0].candidate_actions == ["block_ip:203.0.113.7", "isolate_host:ws-1"]


def test_cost_and_latency_deltas_are_per_alert_means_over_compared_alerts() -> None:
    rows = [
        row("a1", "close", "close", production_cost="0.010", candidate_cost="0.002", production_ms=1000,
            candidate_ms=400),
        row("a2", "close", "escalate", production_cost="0.030", candidate_cost="0.004", production_ms=3000,
            candidate_ms=600),
        row("failed", "close", None, error="X", production_cost="9", candidate_cost="9", production_ms=9, candidate_ms=9),
    ]
    r = report(rows)
    assert (r.cost_usd.production_mean, r.cost_usd.candidate_mean, r.cost_usd.delta) == (0.02, 0.003, -0.017)
    assert (r.latency_ms.production_mean, r.latency_ms.candidate_mean, r.latency_ms.delta) == (2000, 500, -1500)
    assert r.tokens.delta == -1500
    empty = report([])
    assert empty.cost_usd.delta is None and empty.agreement.rate is None


def test_markdown_cells_cannot_break_the_table() -> None:
    r = report([row("evil|`id`\nrow", "escalate", "close")])
    line = next(t for t in render_markdown(r).splitlines() if "evil" in t)
    assert line.count("|") == 5 and "\n" not in line
