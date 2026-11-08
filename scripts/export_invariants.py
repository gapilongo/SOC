#!/usr/bin/env python3
"""Write ``docs/invariants.md`` from the invariant registry (``src/lg_sotf/invariants/registry.py``).

    python scripts/export_invariants.py            # rewrite docs/invariants.md
    python scripts/export_invariants.py --check    # exit 1 if the committed file differs

``tests/deploy/test_invariants.py`` runs the same comparison in CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = REPO_ROOT / "docs" / "invariants.md"
REGENERATE = "python scripts/export_invariants.py"


def main(argv: list[str] | None = None) -> int:
    from lg_sotf.invariants.registry import render_markdown

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if docs/invariants.md is stale; write nothing")
    args = parser.parse_args(argv)
    text = render_markdown()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
        if current != text:
            print(f"{OUTPUT.relative_to(REPO_ROOT)} is stale; regenerate with: {REGENERATE}", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(text)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
