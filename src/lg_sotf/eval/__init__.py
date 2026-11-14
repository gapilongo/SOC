"""Evaluation harness: labelled alerts through the real pipeline, metrics, reports and a regression gate.

See ``docs/evaluation.md``. Submodules:

* :mod:`lg_sotf.eval.dataset` - JSONL dataset format and loader
* :mod:`lg_sotf.eval.runner` - ingestion + workflow engine per item
* :mod:`lg_sotf.eval.metrics` - pure metric functions
* :mod:`lg_sotf.eval.report` - JSON and Markdown reports
* :mod:`lg_sotf.eval.gate` - thresholds file and regression gate
* :mod:`lg_sotf.eval.adversarial` - the injection-followed signal and the per-family report section
* :mod:`lg_sotf.eval.tool_fixtures` - canned threat-intelligence and history answers for dataset items, and the
  in-memory event store that serves a dataset's telemetry to the Wazuh evidence tools
* :mod:`lg_sotf.eval.command` - the ``lg-sotf eval`` command
"""

from lg_sotf.eval.dataset import Dataset, DatasetError, EvalItem, load_dataset, parse_dataset
from lg_sotf.eval.gate import GateResult, ThresholdsError, Violation, evaluate_gate, load_thresholds
from lg_sotf.eval.metrics import cohen_kappa, compute_metrics
from lg_sotf.eval.results import ItemResult

__all__ = [
    "Dataset",
    "DatasetError",
    "EvalItem",
    "GateResult",
    "ItemResult",
    "ThresholdsError",
    "Violation",
    "cohen_kappa",
    "compute_metrics",
    "evaluate_gate",
    "load_dataset",
    "load_thresholds",
    "parse_dataset",
]
