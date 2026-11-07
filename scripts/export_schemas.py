#!/usr/bin/env python3
"""Write the published JSON Schemas under ``schemas/`` from the Pydantic models that define them.

    python scripts/export_schemas.py            # rewrite every schema file
    python scripts/export_schemas.py --check    # exit 1 if a committed file differs from its model

Keys are sorted and each file ends with a newline, so a diff shows only real
contract changes. ``tests/unit/models/test_evidence_fact.py`` runs the check;
``scripts/ci/schema_compat.py`` then decides whether the change needs a
version bump (docs/evidence-facts.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
REGENERATE = "python scripts/export_schemas.py"


def builders() -> Dict[str, Callable[[], Dict[str, Any]]]:
    """Schema file (relative to the repository root) -> the function that builds it."""
    from lg_sotf.models.evidence_fact import evidence_fact_json_schema

    return {"schemas/evidence-fact/v1.json": evidence_fact_json_schema}


def render(schema: Dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def stale() -> list[str]:
    """Schema files whose committed text differs from what the model generates."""
    out = []
    for rel, build in builders().items():
        path = REPO_ROOT / rel
        if not path.exists() or path.read_text(encoding="utf-8") != render(build()):
            out.append(rel)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a committed schema differs from its model")
    args = parser.parse_args(argv)
    if args.check:
        bad = stale()
        for rel in bad:
            print(f"{rel} is stale; regenerate with: {REGENERATE}", file=sys.stderr)
        return 1 if bad else 0
    for rel, build in builders().items():
        path = REPO_ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(build()), encoding="utf-8")
        print(f"wrote {rel}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
