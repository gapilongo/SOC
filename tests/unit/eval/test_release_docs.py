"""Release documents agree with each other and (once aligned) with the package version."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lg_sotf import __version__

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]


def changelog_version() -> str:
    match = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert match, "CHANGELOG.md has no release heading"
    return match.group(1)


def test_security_policy_supports_the_changelog_release_line() -> None:
    major, minor, _ = changelog_version().split(".")
    assert f"| {major}.{minor}.x" in (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_package_version_matches_the_changelog() -> None:
    assert __version__ == changelog_version()
