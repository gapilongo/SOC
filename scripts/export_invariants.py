#!/usr/bin/env python3
"""Write ``docs/invariants.md`` and the invariants table of ``docs/ai-system-card.md`` from the registry.

    python scripts/export_invariants.py            # rewrite both
    python scripts/export_invariants.py --check    # exit 1 if either committed file differs

The registry is ``src/lg_sotf/invariants/registry.py``. The system card holds
only the summary table, between the ``invariants:begin`` and ``invariants:end``
markers; the rest of the card is written by hand.
``tests/deploy/test_invariants.py`` and ``tests/deploy/test_ai_system_card.py``
run the same comparisons in CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = REPO_ROOT / "docs" / "invariants.md"
CARD = REPO_ROOT / "docs" / "ai-system-card.md"
REGENERATE = "python scripts/export_invariants.py"
CARD_BEGIN = (
    "<!-- invariants:begin (generated from src/lg_sotf/invariants/registry.py by "
    "scripts/export_invariants.py; do not edit) -->"
)
CARD_END = "<!-- invariants:end -->"


def summary_table(page: str) -> str:
    """The summary table of the invariants page: its first run of Markdown table rows."""
    lines = page.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| ID |"))
    end = start
    while end < len(lines) and lines[end].startswith("|"):
        end += 1
    return "\n".join(lines[start:end])


def card_with_table(card: str, table: str) -> str:
    """``card`` with the text between its invariants markers replaced by ``table``."""
    head, found_begin, rest = card.partition(CARD_BEGIN)
    _, found_end, tail = rest.partition(CARD_END)
    if not found_begin or not found_end:
        raise ValueError(f"{CARD.name} is missing the invariants:begin/end markers")
    return f"{head}{CARD_BEGIN}\n{table}\n{CARD_END}{tail}"


def main(argv: list[str] | None = None) -> int:
    from lg_sotf.invariants.registry import render_markdown

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a generated file is stale; write nothing")
    args = parser.parse_args(argv)
    text = render_markdown()
    card_current = CARD.read_text(encoding="utf-8")
    outputs = {OUTPUT: text, CARD: card_with_table(card_current, summary_table(text))}
    if args.check:
        stale = [path for path, want in outputs.items() if not path.exists() or path.read_text(encoding="utf-8") != want]
        for path in stale:
            print(f"{path.relative_to(REPO_ROOT)} is stale; regenerate with: {REGENERATE}", file=sys.stderr)
        return 1 if stale else 0
    for path, want in outputs.items():
        path.write_text(want, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)} ({len(want)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
