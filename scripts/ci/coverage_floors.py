#!/usr/bin/env python3
"""Per-package coverage floors (roadmap G10): fail when a guarded package drops below its floor.

Reads a coverage.py JSON report (``pytest --cov-report=json:coverage.json``) and compares the
combined line+branch coverage of each guarded package with its floor. Floors only go up: when a
package is comfortably above its floor, the output says so and the floor should be raised in the
same PR. Lowering a floor needs code-owner review (.github/CODEOWNERS).

    python scripts/ci/coverage_floors.py coverage.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Tuple

# package path under src/lg_sotf/ -> floor (combined line+branch %, one point below the measured
# baseline of 2026-11-05: runtime 82.49, security 98.02; api/auth 90.34 on 2026-11-14, SEC6.5).
FLOORS: Dict[str, float] = {
    "runtime/": 81.4,
    "security/": 97.0,
    "api/auth/": 89.3,
}
RAISE_HINT_MARGIN = 2.0


def package_coverage(report: dict, prefix: str) -> Tuple[float, int]:
    covered = total = files = 0
    for name, data in report["files"].items():
        rel = name.replace("\\", "/").split("lg_sotf/", 1)[-1]
        if not rel.startswith(prefix):
            continue
        summary = data["summary"]
        covered += summary["covered_lines"] + summary.get("covered_branches", 0)
        total += summary["num_statements"] + summary.get("num_branches", 0)
        files += 1
    return (100.0 * covered / total if total else 100.0), files


def main(path: str) -> int:
    report = json.loads(Path(path).read_text())
    failed = False
    for prefix, floor in FLOORS.items():
        pct, files = package_coverage(report, prefix)
        if files == 0:
            print(f"FAIL {prefix}: no files in the report (was the package moved? update FLOORS)")
            failed = True
        elif pct < floor:
            print(f"FAIL {prefix}: {pct:.2f}% is below its floor {floor:.1f}%")
            failed = True
        elif pct >= floor + RAISE_HINT_MARGIN:
            print(f"ok   {prefix}: {pct:.2f}% (floor {floor:.1f}%; raise it to {pct - 1:.1f})")
        else:
            print(f"ok   {prefix}: {pct:.2f}% (floor {floor:.1f}%)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
