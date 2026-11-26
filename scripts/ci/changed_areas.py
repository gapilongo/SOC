#!/usr/bin/env python3
"""Which CI jobs a pull request needs, from the paths it changes (docs/testing.md, "What a pull request runs").

    python3 scripts/ci/changed_areas.py                 # in ci.yml: reads the event, writes $GITHUB_OUTPUT
    python3 scripts/ci/changed_areas.py PATH [PATH...]  # prints what a pull request changing these paths runs

Outputs, each ``true`` or ``false``:

``backend``
    The backend suites: the tests in parallel, the upgrade rehearsal, the Wazuh contract tests.
``stack``
    What is built from the tree: the backend image and its smoke test, the frontend build and image, the
    browser suite and the SBOMs.
``cve_gate``
    The image CVE gate blocks this pull request, because it changes what goes into an image or how the
    image is scanned (a Dockerfile, a lock file, ``.trivyignore``, a workflow, this script). On any other
    pull request the scan only warns (docs/security.md, section 9).

Only a pull request skips anything. A push to main, the weekly schedule and a manual run run every job and
gate on the CVE scan: the release train reads every gate's result on the commit it tags.

A path is prose (``docs``: the changelog fragments, prose and pictures under ``docs/``, Markdown at the
repository root and under ``.github/``), the web UI (``frontend``: ``src/lg_front/``) or anything else. A change of prose only runs neither
``backend`` nor ``stack``; a change of the web UI (and prose) only runs ``stack``; one path of any other
kind runs everything, and so does any doubt about the diff. The lint job and the unit and deploy tiers
always run, so the tests that pin the documentation still see a prose-only change.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional

OUTPUTS = ("backend", "stack", "cve_gate")
EVERYTHING: Dict[str, bool] = {name: True for name in OUTPUTS}

FRONTEND_ROOT = "src/lg_front/"
# Under docs/ only prose and pictures are prose: docs/openapi.json feeds the API and frontend contracts,
# and docs/tools/export_feedback.sql is run by an integration test.
PROSE_SUFFIXES = frozenset({".md", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp4", ".webm"})
IMAGE_INPUT_NAMES = frozenset({"package-lock.json", "package.json", ".trivyignore", ".dockerignore"})


def area(path: str) -> str:
    """``frontend``, ``docs`` or ``other`` for one repository path."""
    pure = PurePosixPath(path)
    suffix = pure.suffix.lower()
    if path.startswith(FRONTEND_ROOT):
        return "frontend"
    if path.startswith("changelog.d/"):
        return "docs"
    if path.startswith("docs/") and suffix in PROSE_SUFFIXES:
        return "docs"
    # Markdown elsewhere is prose only where nothing reads it as data: the repository root and .github/.
    if suffix == ".md" and (len(pure.parts) == 1 or pure.parts[0] == ".github"):
        return "docs"
    return "other"


def is_image_input(path: str) -> bool:
    """Whether ``path`` decides what an image contains or how it is scanned."""
    name = PurePosixPath(path).name
    return (
        name.startswith("Dockerfile")
        or name in IMAGE_INPUT_NAMES
        or (name.startswith("requirements") and name.endswith(".txt"))
        or path.startswith(".github/workflows/")
        or path == "scripts/ci/changed_areas.py"
    )


def classify(paths: Iterable[str]) -> Dict[str, bool]:
    """The outputs for a pull request that changes ``paths``; no path at all runs everything."""
    changed = [p for p in paths if p]
    if not changed:
        return dict(EVERYTHING)
    areas = {area(p) for p in changed}
    return {
        "backend": "other" in areas,
        "stack": areas != {"docs"},
        "cve_gate": any(is_image_input(p) for p in changed),
    }


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout  # noqa: S603, S607


def pull_request_paths(head_sha: str) -> Optional[List[str]]:
    """What the checked-out merge commit changes against the base branch; None when that cannot be told.

    ``actions/checkout`` checks out the pull request's merge commit: its first parent is the base
    branch, its second the pull request's head. Anything else (another checkout, a shallow clone
    without the parents) is not classified.
    """
    try:
        if not head_sha or _git("rev-parse", "--verify", "--quiet", "HEAD^2").strip() != head_sha:
            return None
        # --no-renames: a file moved out of src/ into docs/ still counts as a change under src/.
        listing = _git("diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD")
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p for p in listing.split("\0") if p]


def decide(event: str, head_sha: str) -> Dict[str, bool]:
    if event != "pull_request":
        print(f"event {event or '(none)'}: every job runs and the CVE gate blocks")
        return dict(EVERYTHING)
    paths = pull_request_paths(head_sha)
    if paths is None:
        print("cannot tell what this pull request changes: every job runs and the CVE gate blocks")
        return dict(EVERYTHING)
    counts = {name: sum(1 for p in paths if area(p) == name) for name in ("docs", "frontend", "other")}
    print(f"{len(paths)} changed paths: " + ", ".join(f"{n} {name}" for name, n in counts.items()))
    return classify(paths)


def main(argv: List[str]) -> int:
    if len(argv) > 1:
        result = classify(argv[1:])
    else:
        result = decide(os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("PR_HEAD_SHA", ""))
    lines = [f"{name}={'true' if result[name] else 'false'}" for name in OUTPUTS]
    print("\n".join(lines))
    output = os.environ.get("GITHUB_OUTPUT")
    if output and len(argv) == 1:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
