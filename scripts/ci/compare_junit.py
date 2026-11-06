#!/usr/bin/env python3
"""Compare two pytest JUnit reports: the same test ids with the same outcomes.

    python scripts/ci/compare_junit.py junit.xml junit-parallel.xml

The parallel integration tier (``pytest -n 4 --dist loadfile``) must run
exactly what the serial run runs, with the same results. Exits 1 and lists
the differences otherwise.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Dict, List

OUTCOMES = ("failure", "error", "skipped")


def outcomes(path: Path) -> Dict[str, str]:
    """``classname::name`` -> ``passed`` / ``failure`` / ``error`` / ``skipped`` (an error in teardown wins)."""
    root = ET.parse(path).getroot()  # noqa: S314 - our own pytest reports, not untrusted input
    results: Dict[str, str] = {}
    for case in root.iter("testcase"):
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        found = [child.tag for child in case if child.tag in OUTCOMES]
        outcome = "error" if "error" in found else (found[0] if found else "passed")
        if results.get(test_id) != "error":
            results[test_id] = outcome
    return results


def differences(serial: Dict[str, str], parallel: Dict[str, str]) -> List[str]:
    lines = [f"only in the serial run: {t}" for t in sorted(serial.keys() - parallel.keys())]
    lines += [f"only in the parallel run: {t}" for t in sorted(parallel.keys() - serial.keys())]
    lines += [
        f"{t}: serial {serial[t]}, parallel {parallel[t]}"
        for t in sorted(serial.keys() & parallel.keys())
        if serial[t] != parallel[t]
    ]
    return lines


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    serial, parallel = outcomes(Path(argv[1])), outcomes(Path(argv[2]))
    for label, results in (("serial", serial), ("parallel", parallel)):
        totals = Counter(results.values())
        print(f"{label}: {len(results)} tests, " + ", ".join(f"{k} {totals[k]}" for k in ("passed", *OUTCOMES)))
    diff = differences(serial, parallel)
    for line in diff:
        print(line)
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
