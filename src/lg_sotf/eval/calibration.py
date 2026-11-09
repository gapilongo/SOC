"""Offline policy simulator (AI-E1.9): re-decide recorded alerts under each routing policy, without a model.

An evaluation report records, per item, what ``decide`` saw
(``decision_inputs``: the confidence, the triage, correlation and analysis
digests' scores, the verdict). :func:`simulate` rebuilds the workflow state
``decide`` reads from those inputs and calls the real
:func:`lg_sotf.domain.routing.decide` (and, for the correlation cap, the real
:func:`~lg_sotf.domain.routing.correlated_confidence`) under the thresholds of
each policy in :data:`POLICIES`. Nothing is re-implemented and no model is
called, so a simulation answers one question only: *with these model
outputs*, what would each policy have done. A policy that changes which
alerts reach analysis (event-time correlation, a declared scanner) changes the
model outputs too; that needs a new run, not this simulator.

Reports written before ``decision_inputs`` existed (scorecard v2) pass the
inputs recovered from the alert timelines (``node.completed`` digests) as a
separate file: ``{"_meta": {...}, "items": {item_id: inputs}}``.

``python -m lg_sotf.eval.calibration REPORT [--inputs FILE]`` prints the
policy table (overall and per family) with 95% Wilson intervals.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.domain.rates import RateInterval, format_rate, rate_interval
from lg_sotf.domain.routing import (
    LLM_NORMALIZED_FLAG,
    REFUSAL_DIGESTS,
    Decision,
    RoutingThresholds,
    decide,
    llm_normalized,
    refused_by,
)

#: The AI-E1.9 policy switches (``settings.routing``); every policy below sets all of them.
POLICY_KNOBS: Tuple[str, ...] = ("benign_verdict_precedence", "context_corroboration", "cap_correlated_confidence")
#: Policy name -> the switches it turns on (RUN.md's hypotheses 3, 4 and 5; 1 and 2 need a new run).
POLICIES: Dict[str, Tuple[str, ...]] = {
    "1.2 policy": (),
    "P3 benign verdict precedence": ("benign_verdict_precedence",),
    "P4 tenant-context corroboration": ("context_corroboration",),
    "P5 correlation cap": ("cap_correlated_confidence",),
    "P3+P4": ("benign_verdict_precedence", "context_corroboration"),
    "P3+P4+P5": POLICY_KNOBS,
}


def policy_thresholds(knobs: Iterable[str], base: Optional[Mapping[str, Any]] = None) -> RoutingThresholds:
    """``base`` routing settings with exactly ``knobs`` of :data:`POLICY_KNOBS` on."""
    on = set(knobs)
    unknown = on - set(POLICY_KNOBS)
    if unknown:
        raise ValueError(f"unknown policy switches: {', '.join(sorted(unknown))}")
    return RoutingThresholds.from_settings({**dict(base or {}), **{k: k in on for k in POLICY_KNOBS}})


def _number(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def decision_inputs(state: Mapping[str, Any]) -> Dict[str, Any]:
    """What ``decide`` reads from a finished run's state, small enough for every report item."""
    triage = state.get("triage") or {}
    correlation = state.get("correlation") or {}
    analysis = state.get("analysis") or {}
    return {
        "severity": state.get("severity"),
        "confidence": _number(state.get("confidence")),
        "more_info_loops": int(state.get("more_info_loops", 0) or 0),
        "refused_by": refused_by(state),
        "llm_normalized": llm_normalized(state),
        "triage": {
            "confidence": _number(triage.get("confidence")),
            "rule_confidence": _number(triage.get("rule_confidence")),
            "rule_fp": [str(s)[:64] for s in (triage.get("rule_fp") or [])][:20],
            "rule_tp": [str(s)[:64] for s in (triage.get("rule_tp") or [])][:20],
        },
        "correlation": {
            "score": _number(correlation.get("score")),
            "related_count": correlation.get("related_count"),
            "burst": correlation.get("burst"),
        },
        "analysis": {
            "verdict": analysis.get("verdict"),
            "threat_score": _number(analysis.get("threat_score")),
            "rule_threat_score": _number(analysis.get("rule_threat_score")),
        }
        if analysis
        else None,
    }


def _present(digest: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in digest.items() if v is not None}


def decide_state(inputs: Mapping[str, Any], thresholds: RoutingThresholds) -> Dict[str, Any]:
    """The state ``decide`` reads, rebuilt from ``inputs``."""
    triage = _present(inputs.get("triage") or {})
    confidence = _number(inputs.get("confidence"))
    state: Dict[str, Any] = {
        "severity": inputs.get("severity"),
        "more_info_loops": int(inputs.get("more_info_loops") or 0),
        "triage": triage,
        "correlation": _present(inputs.get("correlation") or {}),
    }
    if confidence is not None:
        state["confidence"] = confidence
    analysis = inputs.get("analysis")
    if isinstance(analysis, Mapping) and analysis:
        state["analysis"] = _present(analysis)
    if inputs.get("llm_normalized"):
        state["alert"] = {"flags": [LLM_NORMALIZED_FLAG]}
    refused = inputs.get("refused_by")
    if refused in REFUSAL_DIGESTS:
        state[refused] = {**state.get(refused, {}), "llm_refusal": {"reason": "recorded"}}
    return state


def simulate(inputs: Mapping[str, Any], thresholds: RoutingThresholds) -> Decision:
    """``decide`` on one item's recorded inputs under ``thresholds``."""
    return decide(decide_state(inputs, thresholds), thresholds)


@dataclass(frozen=True)
class PolicyOutcome:
    """One policy on one group of items: automatic closes and response plans, with n and a 95% Wilson interval."""

    policy: str
    group: str
    benign_auto_close: RateInterval
    malicious_auto_close: RateInterval
    benign_response_plan: RateInterval
    malicious_response_plan: RateInterval
    closed_ids: Tuple[str, ...]


def load_inputs(report: Mapping[str, Any], extra: Optional[Mapping[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """``{item_id: decision inputs}``: from the report's items, else from ``extra["items"]`` (older reports)."""
    from_file = (extra or {}).get("items") or {}
    out: Dict[str, Dict[str, Any]] = {}
    for item in report.get("items") or []:
        inputs = item.get("decision_inputs") or from_file.get(item.get("item_id"))
        if isinstance(inputs, Mapping) and inputs:
            out[str(item["item_id"])] = dict(inputs)
    return out


def _outcome(policy: str, group: str, rows: Sequence[Tuple[Mapping[str, Any], Decision]]) -> PolicyOutcome:
    benign = [(item, d) for item, d in rows if item.get("expected") == "benign"]
    malicious = [(item, d) for item, d in rows if item.get("expected") == "malicious"]
    closed = [str(item["item_id"]) for item, d in rows if d.route == "close"]
    return PolicyOutcome(
        policy=policy,
        group=group,
        benign_auto_close=rate_interval(sum(d.route == "close" for _, d in benign), len(benign)),
        malicious_auto_close=rate_interval(sum(d.route == "close" for _, d in malicious), len(malicious)),
        benign_response_plan=rate_interval(sum(d.route == "plan_response" for _, d in benign), len(benign)),
        malicious_response_plan=rate_interval(sum(d.route == "plan_response" for _, d in malicious), len(malicious)),
        closed_ids=tuple(sorted(closed)),
    )


def run_policies(
    report: Mapping[str, Any],
    inputs: Mapping[str, Mapping[str, Any]],
    policies: Optional[Mapping[str, Sequence[str]]] = None,
    base: Optional[Mapping[str, Any]] = None,
) -> List[PolicyOutcome]:
    """Every policy on every item with inputs (that ``decide`` decided), overall (``all``) and per family."""
    decided = [i for i in report.get("items") or [] if i.get("item_id") in inputs and i.get("decision_code")]
    outcomes: List[PolicyOutcome] = []
    for name, knobs in (policies or POLICIES).items():
        thresholds = policy_thresholds(knobs, base)
        rows = [(item, simulate(inputs[item["item_id"]], thresholds)) for item in decided]
        outcomes.append(_outcome(name, "all", rows))
        for family in sorted({str(item.get("family")) for item in decided if item.get("family")}):
            outcomes.append(_outcome(name, family, [r for r in rows if r[0].get("family") == family]))
    return outcomes


def mismatches(report: Mapping[str, Any], inputs: Mapping[str, Mapping[str, Any]], base: Optional[Mapping[str, Any]] = None,
               knobs: Sequence[str] = ()) -> List[Tuple[str, Optional[str], str]]:
    """Items whose recorded decision code the simulator does not reproduce under the run's own policy."""
    thresholds = policy_thresholds(knobs, base)
    out: List[Tuple[str, Optional[str], str]] = []
    for item in report.get("items") or []:
        item_id = item.get("item_id")
        if item_id in inputs and item.get("decision_code"):
            code = simulate(inputs[item_id], thresholds).code
            if code != item["decision_code"]:
                out.append((str(item_id), item.get("decision_code"), code))
    return out


def render_table(outcomes: Sequence[PolicyOutcome], group: str = "all") -> str:
    lines = [
        "| Policy | Benign auto-closed | Malicious auto-closed | Benign response plans | Malicious response plans |",
        "|---|---|---|---|---|",
    ]
    for o in outcomes:
        if o.group == group:
            cells = (o.benign_auto_close, o.malicious_auto_close, o.benign_response_plan, o.malicious_response_plan)
            lines.append(f"| {o.policy} | " + " | ".join(format_rate(c) for c in cells) + " |")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lg_sotf.eval.calibration", description=__doc__.split("\n")[0])
    parser.add_argument("report", help="an lg-sotf eval report (JSON)")
    parser.add_argument("--inputs", help="decision inputs for a report written without them (JSON)")
    parser.add_argument("--run-policy", default="1.2 policy", choices=sorted(POLICIES),
                        help="the policy the run used, to check the simulator reproduces its decisions")
    args = parser.parse_args(argv)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    extra = json.loads(Path(args.inputs).read_text(encoding="utf-8")) if args.inputs else None
    inputs = load_inputs(report, extra)
    wrong = mismatches(report, inputs, knobs=POLICIES[args.run_policy])
    out = [f"{len(inputs)} items with decision inputs; the {args.run_policy} reproduces "
           f"{len(inputs) - len(wrong)} decisions"]
    out += [f"  not reproduced: {item_id} recorded {recorded}, simulated {code}" for item_id, recorded, code in wrong[:20]]
    outcomes = run_policies(report, inputs)
    for group in ["all", *sorted({o.group for o in outcomes} - {"all"})]:
        out.append(f"\n### {group}\n\n{render_table(outcomes, group)}")
    sys.stdout.write("\n".join(out) + "\n")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
