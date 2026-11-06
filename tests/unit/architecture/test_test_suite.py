"""Rules for the test suite itself (roadmap Q2).

* Tests share helpers through ``_support.py`` modules, never by importing a
  ``conftest`` or another ``test_*`` module: such imports re-register
  fixtures, hide where a helper lives and make module order matter.
* A unit test never requests a real-service fixture (tests/unit/conftest.py).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from tests.unit._support import SERVICE_FIXTURES, UNIT_ROOT, service_fixture_offenders

pytestmark = pytest.mark.unit

TESTS_ROOT = UNIT_ROOT.parent
BANNED = re.compile(r"^tests(\.\w+)*\.(conftest|test_\w+)$")


def banned_imports(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules = [node.module]
        elif isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        else:
            continue
        found += [f"{path.relative_to(TESTS_ROOT.parent)}:{node.lineno}: {m}" for m in modules if BANNED.match(m)]
    return found


def test_no_test_imports_a_conftest_or_another_test_module() -> None:
    offenders = [line for path in sorted(TESTS_ROOT.rglob("*.py")) for line in banned_imports(path)]
    assert offenders == [], "move the shared helper into the nearest _support.py:\n" + "\n".join(offenders)


@pytest.mark.parametrize(
    "module",
    ["tests.integration.api.conftest", "tests.conftest", "tests.unit.agents.test_triage", "tests.deploy.test_compose"],
)
def test_the_ban_matches_conftest_and_test_modules(module: str) -> None:
    assert BANNED.match(module)


@pytest.mark.parametrize("module", ["tests.integration.api._support", "tests.fixtures.microsoft", "tests.unit.services.fakes"])
def test_the_ban_allows_support_modules(module: str) -> None:
    assert not BANNED.match(module)


def _item(path: Path, *fixtures: str) -> SimpleNamespace:
    return SimpleNamespace(path=path, nodeid=f"{path.name}::test_x", fixturenames=["request", *fixtures])


def test_unit_items_requesting_service_fixtures_are_reported() -> None:
    unit = UNIT_ROOT / "db" / "test_x.py"
    integration = TESTS_ROOT / "integration" / "db" / "test_x.py"
    items = [_item(unit, "repos", "db"), _item(unit, "make_settings"), _item(integration, "db")]
    assert service_fixture_offenders(items) == ["test_x.py::test_x: db, repos"]
    assert {"db", "repos", "redis_client", "migrated_database_url"} <= SERVICE_FIXTURES
