"""The child process of test_ci_gate.py: one routing-policy regression, then the CI evaluation gate.

    python _ci_gate_child.py <none|one_benign_close_fewer|missed_attack> pr --set phishing_v1 --out DIR

The gate runs `lg-sotf eval`, which configures logging for the whole process (structlog caches each
module logger on first use), so it never runs inside the pytest process: a later test that captures
log events would see none. The exit code is the gate's.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping

from lg_sotf.domain import routing
from lg_sotf.domain.routing import Decision, RoutingThresholds

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "ci" / "eval_gate.py"


def one_benign_close_fewer() -> None:
    """Benign handling below the baseline: the policy stops closing one alert it used to close."""
    real = routing.decide
    dropped: List[str] = []

    def regressed(state: Mapping[str, Any], t: RoutingThresholds, tier: str = "off") -> Decision:
        decision = real(state, t, tier)
        if decision.route == "close" and not dropped:
            dropped.append(decision.code)
            return Decision("escalate", "deliberate regression", None, "false_positive_review")
        return decision

    routing.decide = regressed


def missed_attack() -> None:
    """Missed attacks above the baseline: the policy takes any alert as carrying approved benign evidence."""
    routing.benign_evidence = lambda triage: True


REGRESSIONS: Dict[str, Callable[[], None]] = {
    "none": lambda: None,
    "one_benign_close_fewer": one_benign_close_fewer,
    "missed_attack": missed_attack,
}


def main(argv: List[str]) -> int:
    regression, *gate_args = argv
    REGRESSIONS[regression]()
    spec = importlib.util.spec_from_file_location("ci_eval_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(gate)
    code: int = gate.main(gate_args)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
