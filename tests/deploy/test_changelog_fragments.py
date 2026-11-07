"""Changelog fragments (changelog.d/) are valid and fold into CHANGELOG.md."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("changelog_script", ROOT / "scripts" / "changelog.py")
assert _spec and _spec.loader
changelog = importlib.util.module_from_spec(_spec)
sys.modules["changelog_script"] = changelog
_spec.loader.exec_module(changelog)

BASE = """# Changelog

Intro.

## [Unreleased]

### Added

- Existing addition.

### Fixed

- Existing fix.

## [1.0.0] - 2026-01-01

### Added

- Old thing.
"""


def test_every_committed_fragment_is_valid() -> None:
    assert changelog.check() == []


def test_the_fragment_readme_is_not_a_fragment() -> None:
    assert all(p.name != "README.md" for p in changelog.fragment_paths())


def test_fold_appends_to_existing_sections_and_creates_missing_ones_in_order() -> None:
    folded = changelog.fold_text(
        BASE,
        [
            {"Added": "- New addition."},
            {"Security": "- New security note.", "Fixed": "- New fix."},
        ],
    )
    unreleased = folded.split("## [Unreleased]")[1].split("## [1.0.0]")[0]
    assert unreleased.index("### Added") < unreleased.index("### Fixed")
    assert unreleased.index("### Fixed") < unreleased.index("### Security")
    assert "- Existing addition.\n\n- New addition." in unreleased
    assert "- Existing fix.\n\n- New fix." in unreleased
    assert "### Security\n\n- New security note." in unreleased
    # Released sections are untouched.
    assert folded.split("## [1.0.0] - 2026-01-01")[1] == BASE.split("## [1.0.0] - 2026-01-01")[1]


def test_fold_moves_fragments_and_deletes_them(tmp_path: Path) -> None:
    frags = tmp_path / "changelog.d"
    frags.mkdir()
    (frags / "README.md").write_text("# not a fragment\n")
    (frags / "AI-E1.3.md").write_text("### Added\n\n- Trace store.\n")
    target = tmp_path / "CHANGELOG.md"
    target.write_text(BASE)

    assert changelog.fold(frags, target) == 1
    assert "- Trace store." in target.read_text()
    assert [p.name for p in frags.iterdir()] == ["README.md"]


@pytest.mark.parametrize(
    "text",
    [
        "- No heading.\n",
        "### Improved\n\n- Unknown section.\n",
        "## Added\n\n- Wrong heading level.\n",
        "### Added\n\n",
        "",
    ],
)
def test_malformed_fragments_are_rejected(text: str) -> None:
    with pytest.raises(changelog.FragmentError):
        changelog.parse_fragment(text)


def test_fold_refuses_when_a_fragment_is_invalid(tmp_path: Path) -> None:
    frags = tmp_path / "changelog.d"
    frags.mkdir()
    (frags / "bad.md").write_text("### Improved\n\n- x\n")
    target = tmp_path / "CHANGELOG.md"
    target.write_text(BASE)
    with pytest.raises(changelog.FragmentError):
        changelog.fold(frags, target)
    assert target.read_text() == BASE
    assert (frags / "bad.md").exists()
