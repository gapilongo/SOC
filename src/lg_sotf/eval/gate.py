"""Regression gate: compare a report with a thresholds file (and optionally a baseline report).

Thresholds file (YAML or JSON)::

    version: 1
    min_items: 60                      # fewer scored items fails the gate
    metrics:                           # absolute bounds
      error_rate: {max: 0}
      malicious_false_negative_rate: {max: 0.0}
      benign_auto_close_rate: {min: 0.2}
      per_class.malicious.recall: {min: 0.9}
      latency_s.p95: {max: 60}
      splits.adversarial.malicious_false_negative_rate: {max: 0}
    regressions:                       # only checked when a baseline report is given
      malicious_false_negative_rate: {max_increase: 0}
      benign_auto_close_rate: {max_decrease: 0.05}

Metric paths are dotted paths into the report's ``metrics`` object;
``splits.<name>.<path>`` reads that split's metrics and
``families.<name>.<path>`` that adversarial family's. A metric that is missing
or undefined (``null``, e.g. a rate with no items in its denominator) fails
its bound unless the bound sets ``allow_missing: true``, so a dataset change
cannot silently turn a gate off.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml

BOUND_KEYS = frozenset({"min", "max", "allow_missing"})
REGRESSION_KEYS = frozenset({"max_increase", "max_decrease", "allow_missing"})


class ThresholdsError(ValueError):
    """The thresholds file is malformed."""


@dataclass(frozen=True)
class Violation:
    metric: str
    kind: str  # below_min | above_max | missing | regressed | too_few_items
    actual: Optional[float]
    limit: Optional[float]
    message: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateResult:
    passed: bool
    checked: int
    violations: List[Violation]

    def as_dict(self) -> Dict[str, Any]:
        return {"passed": self.passed, "checked": self.checked, "violations": [v.as_dict() for v in self.violations]}


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ThresholdsError(f"{where} must be a finite number")
    return float(value)


def validate_thresholds(data: Any) -> Dict[str, Any]:
    """Validate a parsed thresholds mapping and return it normalised."""
    if not isinstance(data, Mapping):
        raise ThresholdsError("thresholds must be a mapping")
    unknown = set(data) - {"version", "min_items", "metrics", "regressions", "description"}
    if unknown:
        raise ThresholdsError(f"unknown top-level keys: {', '.join(sorted(map(str, unknown)))}")
    version = data.get("version", 1)
    if version != 1:
        raise ThresholdsError(f"unsupported thresholds version {version!r}")
    out: Dict[str, Any] = {"version": 1, "metrics": {}, "regressions": {}}
    if "min_items" in data:
        min_items = data["min_items"]
        if isinstance(min_items, bool) or not isinstance(min_items, int) or min_items < 0:
            raise ThresholdsError("min_items must be a non-negative integer")
        out["min_items"] = min_items
    for section, allowed in (("metrics", BOUND_KEYS), ("regressions", REGRESSION_KEYS)):
        raw = data.get(section) or {}
        if not isinstance(raw, Mapping):
            raise ThresholdsError(f"{section} must be a mapping of metric path to bounds")
        for path, bound in raw.items():
            if not isinstance(path, str) or not path:
                raise ThresholdsError(f"{section}: metric paths must be non-empty strings")
            if not isinstance(bound, Mapping) or not bound:
                raise ThresholdsError(f"{section}.{path} must be a mapping such as {{max: 0.05}}")
            extra = set(bound) - allowed
            if extra:
                raise ThresholdsError(f"{section}.{path}: unknown keys {', '.join(sorted(map(str, extra)))}")
            clean: Dict[str, Any] = {}
            for key, value in bound.items():
                if key == "allow_missing":
                    if not isinstance(value, bool):
                        raise ThresholdsError(f"{section}.{path}.allow_missing must be true or false")
                    clean[key] = value
                else:
                    clean[key] = _number(value, f"{section}.{path}.{key}")
                    if key.startswith("max_") and clean[key] < 0:
                        raise ThresholdsError(f"{section}.{path}.{key} must not be negative")
            if not set(clean) - {"allow_missing"}:
                raise ThresholdsError(f"{section}.{path} sets no bound")
            if "min" in clean and "max" in clean and clean["min"] > clean["max"]:
                raise ThresholdsError(f"{section}.{path}: min is greater than max")
            out[section][path] = clean
    return out


def load_thresholds(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ThresholdsError(f"cannot read thresholds {p}: {exc.strerror or exc}") from None
    except yaml.YAMLError as exc:
        raise ThresholdsError(f"thresholds {p} is not valid YAML/JSON: {exc}") from None
    return validate_thresholds(data)


def resolve_metric(report: Mapping[str, Any], path: str) -> Any:
    """Look a dotted metric path up in a report; ``KeyError`` when absent."""
    parts = path.split(".")
    node: Any
    if parts[0] in ("splits", "families"):
        if len(parts) < 3:
            raise KeyError(path)
        node = report[parts[0]][parts[1]]["metrics"]
        parts = parts[2:]
    else:
        node = report["metrics"]
    for part in parts:
        if not isinstance(node, Mapping) or part not in node:
            raise KeyError(path)
        node = node[part]
    return node


def _value(report: Mapping[str, Any], path: str) -> Optional[float]:
    try:
        value = resolve_metric(report, path)
    except KeyError:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def evaluate_gate(
    report: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    baseline: Optional[Mapping[str, Any]] = None,
    tolerance: float = 1e-9,
) -> GateResult:
    """Check ``report`` against validated ``thresholds``; regressions need ``baseline``."""
    violations: List[Violation] = []
    checked = 0
    min_items = thresholds.get("min_items")
    if min_items is not None:
        checked += 1
        scored = _value(report, "scored") or 0.0
        if scored < min_items:
            violations.append(
                Violation("scored", "too_few_items", scored, float(min_items), f"{int(scored)} scored items < {min_items}")
            )
    for path, bound in (thresholds.get("metrics") or {}).items():
        checked += 1
        actual = _value(report, path)
        if actual is None:
            if not bound.get("allow_missing"):
                violations.append(Violation(path, "missing", None, None, f"{path} is missing or undefined"))
            continue
        if "min" in bound and actual < bound["min"] - tolerance:
            violations.append(
                Violation(path, "below_min", actual, bound["min"], f"{path} = {actual:.4g} < min {bound['min']:.4g}")
            )
        if "max" in bound and actual > bound["max"] + tolerance:
            violations.append(
                Violation(path, "above_max", actual, bound["max"], f"{path} = {actual:.4g} > max {bound['max']:.4g}")
            )
    if baseline is not None:
        for path, bound in (thresholds.get("regressions") or {}).items():
            checked += 1
            actual = _value(report, path)
            before = _value(baseline, path)
            if actual is None or before is None:
                if not bound.get("allow_missing"):
                    violations.append(
                        Violation(path, "missing", actual, before, f"{path} is missing in the report or the baseline")
                    )
                continue
            if "max_increase" in bound and actual - before > bound["max_increase"] + tolerance:
                violations.append(
                    Violation(
                        path,
                        "regressed",
                        actual,
                        before + bound["max_increase"],
                        f"{path} rose from {before:.4g} to {actual:.4g} (allowed +{bound['max_increase']:.4g})",
                    )
                )
            if "max_decrease" in bound and before - actual > bound["max_decrease"] + tolerance:
                violations.append(
                    Violation(
                        path,
                        "regressed",
                        actual,
                        before - bound["max_decrease"],
                        f"{path} fell from {before:.4g} to {actual:.4g} (allowed -{bound['max_decrease']:.4g})",
                    )
                )
    return GateResult(passed=not violations, checked=checked, violations=violations)
