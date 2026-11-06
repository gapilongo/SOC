"""Import isolation: every package root imports on its own, and import budgets hold.

Each package under ``src/lg_sotf`` (plus ``lg_sotf.settings`` and ``lg_sotf.cli``) is
imported in a fresh interpreter. A package that only imports because some other
module happened to be loaded first, or that has an import cycle reachable only
from its own root, fails here instead of in production.

``BUDGETS`` lists ``(module, must_not_load)`` pairs: importing ``module`` in a fresh
interpreter must not put ``must_not_load`` (or any of its submodules, which would
load it too) in ``sys.modules``. Refactor steps add an entry when they cut a
dependency, so the cut stays cut.

The interpreters run concurrently, so the whole file costs about as much as the
slowest single import.
"""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

import lg_sotf

pytestmark = pytest.mark.unit

PACKAGE_DIR = Path(lg_sotf.__file__).resolve().parent
SRC_DIR = PACKAGE_DIR.parent
TIMEOUT_S = 120

# (module, must_not_load). Add an entry when a step removes a dependency.
BUDGETS: list[tuple[str, str]] = [
    # F3: the egress policy is a leaf; importing it used to load every pull connector and db.repos.
    ("lg_sotf.net.egress", "lg_sotf.db"),
    ("lg_sotf.net.egress", "lg_sotf.ingestion"),
    # F7: compliance operations take the owner DSN from lg_sotf.db, not from a process role.
    ("lg_sotf.compliance.ops", "lg_sotf.runtime"),
    # C1: phishing policy is pure; it used to sit in core, next to the engine and the agents.
    ("lg_sotf.domain.phishing", "lg_sotf.db"),
    ("lg_sotf.domain.phishing", "langchain_core"),
    # C3: response planning extracts indicators from domain, not from the agents (and their LLM stack).
    ("lg_sotf.services.response", "lg_sotf.agents"),
    # C4: the checkpointer lives in db but stays out of db/__init__ and migrate's import time, so API
    # processes and Alembic runs (revision 0009 imports migrate) do not load langgraph.
    ("lg_sotf.db", "langgraph"),
    ("lg_sotf.db.migrate", "langgraph"),
    # C7: notification webhooks sign with lg_sotf.security.signing, not through the response connectors.
    ("lg_sotf.integrations.channels", "lg_sotf.services"),
]

# Imports nothing but ``sys`` before the module under test, and reports one loaded
# name per line, so the probe itself cannot put a forbidden module in sys.modules.
_BUDGET_PROBE = """
import sys
module, forbidden = sys.argv[1], sys.argv[2:]
__import__(module)
loaded = [name for name in forbidden if name in sys.modules]
print("\\n".join(["--loaded--", *loaded]))
"""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


def package_roots() -> list[str]:
    """``lg_sotf.<pkg>`` for every top-level package, plus the settings and cli modules."""
    packages = sorted(p.name for p in PACKAGE_DIR.iterdir() if (p / "__init__.py").is_file())
    return [f"lg_sotf.{name}" for name in [*packages, "settings", "cli"]]


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC_DIR), env.get("PYTHONPATH")]))
    return env


def _run(args: list[str]) -> Result:
    proc = subprocess.run(
        [sys.executable, *args], capture_output=True, text=True, timeout=TIMEOUT_S, env=_env(), check=False
    )
    return Result(proc.returncode, proc.stdout, proc.stderr)


def run_all(commands: dict[str, list[str]]) -> dict[str, Result]:
    """Run each command in its own interpreter, concurrently."""
    workers = max(1, min(len(commands), os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {key: pool.submit(_run, args) for key, args in commands.items()}
        return {key: future.result() for key, future in futures.items()}


def budget_violations(budgets: list[tuple[str, str]]) -> list[str]:
    """Return one message per ``(module, must_not_load)`` pair that does not hold."""
    grouped: dict[str, list[str]] = {}
    for module, forbidden in budgets:
        grouped.setdefault(module, []).append(forbidden)
    results = run_all({module: ["-c", _BUDGET_PROBE, module, *names] for module, names in grouped.items()})
    problems: list[str] = []
    for module, result in sorted(results.items()):
        if result.returncode != 0:
            problems.append(f"import {module} failed:\n{result.stderr.strip()}")
            continue
        lines = result.stdout.splitlines()
        loaded = lines[lines.index("--loaded--") + 1 :]
        problems.extend(f"import {module} loads {name}" for name in loaded)
    return problems


@pytest.fixture(scope="module")
def root_imports() -> dict[str, Result]:
    return run_all({module: ["-c", f"import {module}"] for module in package_roots()})


@pytest.mark.parametrize("module", package_roots())
def test_package_root_imports_in_isolation(module: str, root_imports: dict[str, Result]) -> None:
    result = root_imports[module]
    assert result.returncode == 0, f"import {module} failed in a fresh interpreter:\n{result.stderr.strip()}"


def test_package_roots_cover_known_packages() -> None:
    roots = package_roots()
    assert {"lg_sotf.api", "lg_sotf.db", "lg_sotf.services", "lg_sotf.settings", "lg_sotf.cli"} <= set(roots)


def test_import_budgets_hold() -> None:
    problems = budget_violations(BUDGETS)
    assert not problems, "\n".join(problems)


def test_budget_checker_detects_a_loaded_module() -> None:
    # json imports json.decoder; collections does not import json.
    assert budget_violations([("json", "json.decoder"), ("collections", "json")]) == ["import json loads json.decoder"]
