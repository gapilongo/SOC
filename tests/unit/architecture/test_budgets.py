"""Module and function size budgets for ``src/lg_sotf``.

A module may have at most ``MODULE_BUDGET`` lines and a function (or method) at
most ``FUNCTION_BUDGET`` lines, from its ``def`` line to its last line. Today's
offenders are pinned at their exact sizes in ``budgets_allowlist.txt``:

    services/response.py<TAB>2707                  (module)
    services/review.py::ReviewService.decide<TAB>164   (function)

This is a ratchet. The test fails when:

* a new module or function goes over budget;
* a pinned entry grows;
* a pinned entry shrinks and its number is not lowered to match (the message
  prints the new number, so the fix is a one-line edit);
* a pinned entry is back within budget or no longer exists (delete the line).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.unit.architecture._support import baseline_path, read_entries, source_files, walk_scoped

pytestmark = pytest.mark.unit

MODULE_BUDGET = 800
FUNCTION_BUDGET = 80
ALLOWLIST = baseline_path("budgets_allowlist.txt")


def module_sizes() -> dict[str, int]:
    """Line count of every module, keyed by package-relative path."""
    return {src.rel: len(src.text.splitlines()) for src in source_files()}


def functions_in(rel: str, tree: ast.Module) -> dict[str, int]:
    """Line count of every function in one module, keyed by ``path::qualname``.

    Two defs with the same qualname in one module (a property setter, a
    conditional definition) keep the larger size, which is the one a budget cares about.
    """
    sizes: dict[str, int] = {}
    for node, qual in walk_scoped(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            assert node.end_lineno is not None
            key = f"{rel}::{qual}"
            sizes[key] = max(sizes.get(key, 0), node.end_lineno - node.lineno + 1)
    return sizes


def function_sizes() -> dict[str, int]:
    """Line count of every function under ``src/lg_sotf``."""
    sizes: dict[str, int] = {}
    for src in source_files():
        sizes.update(functions_in(src.rel, src.tree))
    return sizes


def load_allowlist(path: Path) -> dict[str, int]:
    """Parse ``key<TAB>lines`` entries, rejecting duplicates and malformed lines."""
    pinned: dict[str, int] = {}
    for line in read_entries(path):
        key, sep, number = line.rpartition("\t")
        assert sep and number.isdigit(), f"{path.name}: expected 'key<TAB>lines', got {line!r}"
        assert key not in pinned, f"{path.name}: duplicate entry {key}"
        pinned[key] = int(number)
    return pinned


def budget_problems(sizes: dict[str, int], pinned: dict[str, int], budget: int, kind: str) -> list[str]:
    """Compare measured ``sizes`` with the ``pinned`` allowlist entries of one kind."""
    problems: list[str] = []
    for key, lines in sorted(sizes.items()):
        if lines <= budget:
            continue
        allowed = pinned.get(key)
        if allowed is None:
            problems.append(f"new oversized {kind}: {key} has {lines} lines (budget {budget}); split it")
        elif lines > allowed:
            problems.append(f"{kind} grew: {key} has {lines} lines, pinned at {allowed}; split it instead")
        elif lines < allowed:
            problems.append(f"{kind} shrank: {key} is now {lines} lines; lower its pinned number: {key}\t{lines}")
    for key, allowed in sorted(pinned.items()):
        lines = sizes.get(key)
        if lines is None:
            problems.append(f"{kind} no longer exists: delete the allowlist line {key}\t{allowed}")
        elif lines <= budget:
            problems.append(f"{kind} is within budget ({lines} lines): delete the allowlist line {key}\t{allowed}")
    return problems


def _split_allowlist() -> tuple[dict[str, int], dict[str, int]]:
    pinned = load_allowlist(ALLOWLIST)
    modules = {key: n for key, n in pinned.items() if "::" not in key}
    functions = {key: n for key, n in pinned.items() if "::" in key}
    return modules, functions


def test_module_size_budget() -> None:
    modules, _ = _split_allowlist()
    problems = budget_problems(module_sizes(), modules, MODULE_BUDGET, "module")
    assert not problems, "\n".join(problems)


def test_function_size_budget() -> None:
    _, functions = _split_allowlist()
    problems = budget_problems(function_sizes(), functions, FUNCTION_BUDGET, "function")
    assert not problems, "\n".join(problems)


def test_budget_problems_reports_every_drift() -> None:
    sizes = {"a.py": 900, "b.py": 850, "c.py": 1000, "d.py": 900, "e.py": 10}
    pinned = {"a.py": 900, "b.py": 900, "c.py": 950, "e.py": 820, "gone.py": 900}
    problems = budget_problems(sizes, pinned, 800, "module")
    assert problems == [
        "module shrank: b.py is now 850 lines; lower its pinned number: b.py\t850",
        "module grew: c.py has 1000 lines, pinned at 950; split it instead",
        "new oversized module: d.py has 900 lines (budget 800); split it",
        "module is within budget (10 lines): delete the allowlist line e.py\t820",
        "module no longer exists: delete the allowlist line gone.py\t900",
    ]


def test_function_sizes_use_dotted_qualnames() -> None:
    sample = """
@decorator
async def top(x):
    def inner():
        return 1
    return inner()


class Service:
    def method(self):
        pass
"""
    assert functions_in("m.py", ast.parse(sample)) == {
        "m.py::top": 4,
        "m.py::top.inner": 2,
        "m.py::Service.method": 2,
    }
