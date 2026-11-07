"""Changelog fragments: check them, or fold them into CHANGELOG.md.

Every pull request adds its own file under ``changelog.d/`` instead of editing
``CHANGELOG.md``, so parallel pull requests never conflict on the changelog. A
fragment is Markdown with one or more Keep a Changelog section headings::

    ### Added

    - The thing that was added, written for an operator.

At release time ``python scripts/changelog.py fold`` moves every fragment into
the ``## [Unreleased]`` section of ``CHANGELOG.md`` (appending to the matching
``###`` section, creating it in the standard order if needed) and deletes the
fragments. ``python scripts/changelog.py check`` validates the fragments and is
run by the deploy tests.

Usage:
    python scripts/changelog.py check
    python scripts/changelog.py fold
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAGMENTS = ROOT / "changelog.d"
CHANGELOG = ROOT / "CHANGELOG.md"

SECTIONS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
_HEADING = re.compile(r"^### (.+?)\s*$")
_UNRELEASED = "## [Unreleased]"


class FragmentError(ValueError):
    """A fragment does not follow the format."""


def fragment_paths(directory: Path = FRAGMENTS) -> list[Path]:
    """Return the fragment files, in a stable order (README.md excluded)."""
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.md") if p.name.lower() != "readme.md")


def parse_fragment(text: str, name: str = "fragment") -> dict[str, str]:
    """Split a fragment into ``{section: body}``; raise FragmentError if invalid."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = _HEADING.match(line)
        if match:
            title = match.group(1)
            if title not in SECTIONS:
                raise FragmentError(f"{name}:{lineno}: unknown section {title!r}; use one of {', '.join(SECTIONS)}")
            current = title
            sections.setdefault(current, [])
            continue
        if line.startswith("#"):
            raise FragmentError(f"{name}:{lineno}: only '### <Section>' headings are allowed")
        if current is None:
            if line.strip():
                raise FragmentError(f"{name}:{lineno}: text before the first '### <Section>' heading")
            continue
        sections[current].append(line)
    bodies = {k: "\n".join(v).strip("\n") for k, v in sections.items()}
    if not bodies:
        raise FragmentError(f"{name}: no '### <Section>' heading")
    for title, body in bodies.items():
        if not body.strip():
            raise FragmentError(f"{name}: section {title!r} is empty")
    return bodies


def check(directory: Path = FRAGMENTS) -> list[str]:
    """Return a list of problems with the fragments (empty when all are valid)."""
    problems = []
    for path in fragment_paths(directory):
        try:
            parse_fragment(path.read_text(encoding="utf-8"), path.name)
        except FragmentError as exc:
            problems.append(str(exc))
    return problems


def fold_text(changelog: str, fragments: list[dict[str, str]]) -> str:
    """Return ``changelog`` with every fragment folded into [Unreleased]."""
    lines = changelog.splitlines()
    try:
        start = lines.index(_UNRELEASED)
    except ValueError as exc:
        raise FragmentError(f"CHANGELOG.md has no '{_UNRELEASED}' heading") from exc
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    unreleased = lines[start + 1 : end]

    # Existing Unreleased content, by section, in file order.
    preamble: list[str] = []
    existing: dict[str, list[str]] = {}
    order: list[str] = []
    current: str | None = None
    for line in unreleased:
        match = _HEADING.match(line)
        if match:
            current = match.group(1)
            if current not in existing:
                existing[current] = []
                order.append(current)
            continue
        if current is None:
            preamble.append(line)
        else:
            existing[current].append(line)

    for fragment in fragments:
        for title, body in fragment.items():
            if title not in existing:
                existing[title] = []
                order.append(title)
            block = existing[title]
            while block and not block[-1].strip():
                block.pop()
            block.append("")
            block.extend(body.splitlines())

    def rank(title: str) -> int:
        return SECTIONS.index(title) if title in SECTIONS else len(SECTIONS)

    out: list[str] = []
    while preamble and not preamble[-1].strip():
        preamble.pop()
    out.extend(preamble)
    for title in sorted(order, key=rank):
        body = existing[title]
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        out.extend(["", f"### {title}", ""])
        out.extend(body)
    out.append("")

    result = lines[: start + 1] + out + lines[end:]
    text = "\n".join(result)
    return text if text.endswith("\n") else text + "\n"


def fold(directory: Path = FRAGMENTS, changelog: Path = CHANGELOG) -> int:
    """Fold every fragment into ``changelog`` and delete it. Return the count."""
    paths = fragment_paths(directory)
    problems = check(directory)
    if problems:
        raise FragmentError("\n".join(problems))
    parsed = [parse_fragment(p.read_text(encoding="utf-8"), p.name) for p in paths]
    if not parsed:
        return 0
    changelog.write_text(fold_text(changelog.read_text(encoding="utf-8"), parsed), encoding="utf-8")
    for path in paths:
        path.unlink()
    return len(paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "fold"))
    args = parser.parse_args(argv)
    if args.command == "check":
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"{len(fragment_paths())} fragment(s), {len(problems)} problem(s)")
        return 1 if problems else 0
    try:
        count = fold()
    except FragmentError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"folded {count} fragment(s) into CHANGELOG.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
