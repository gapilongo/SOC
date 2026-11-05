"""Shared helpers for the architecture tests: source discovery, AST walking, baselines.

Paths are POSIX and relative to ``src/lg_sotf`` (``services/response.py``), so
baselines and failure messages read the same way the roadmap does. A code
location is ``path::qualname``; module-level code has the qualname ``<module>``.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT / "src" / "lg_sotf"
HERE = Path(__file__).resolve().parent

MODULE_LEVEL = "<module>"

ScopeNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


@dataclass(frozen=True)
class SourceFile:
    rel: str
    text: str
    tree: ast.Module


@lru_cache(maxsize=1)
def source_files() -> tuple[SourceFile, ...]:
    """Every ``*.py`` under ``src/lg_sotf``, parsed once per test session."""
    files: list[SourceFile] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(PACKAGE_ROOT).as_posix()
        files.append(SourceFile(rel=rel, text=text, tree=ast.parse(text, filename=rel)))
    return tuple(files)


def walk_scoped(tree: ast.AST, prefix: str = "") -> Iterator[tuple[ast.AST, str]]:
    """Yield ``(node, qualname)`` for every node, where qualname names the enclosing def/class.

    Nested scopes are dotted (``ResponseService.plan.inner``). A def or class node
    itself is reported with its own qualname, so a decorator or default argument is
    attributed to the function it decorates.
    """
    for child in ast.iter_child_nodes(tree):
        if isinstance(child, ScopeNode):
            qual = f"{prefix}.{child.name}" if prefix else child.name
            yield child, qual
            yield from walk_scoped(child, qual)
        else:
            yield child, prefix or MODULE_LEVEL
            yield from walk_scoped(child, prefix)


def iter_calls(tree: ast.AST) -> Iterator[tuple[ast.Call, str]]:
    """Yield ``(call, qualname)`` for every call expression in ``tree``."""
    for node, qual in walk_scoped(tree):
        if isinstance(node, ast.Call):
            yield node, qual


def attr_name(call: ast.Call) -> Optional[str]:
    """The method name of ``obj.name(...)``, or None for a plain function call."""
    return call.func.attr if isinstance(call.func, ast.Attribute) else None


def in_dir(rel: str, *prefixes: str) -> bool:
    """True when ``rel`` sits under one of the package-relative directory ``prefixes``."""
    return any(rel.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def baseline_path(name: str) -> Path:
    return HERE / name


def read_entries(path: Path) -> list[str]:
    """Non-empty, non-comment lines of a data file, stripped."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def ratchet_problems(name: str, found: Iterable[str], baseline: Iterable[str]) -> list[str]:
    """Compare occurrences with a shrink-only baseline, one line per occurrence.

    Both sides are multisets: a function with two raw-SQL calls appears twice in the
    baseline, so a third call in the same function is still a new occurrence.
    """
    have = Counter(found)
    allowed = Counter(baseline)
    problems: list[str] = []
    for entry, count in sorted((have - allowed).items()):
        problems.extend(
            f"new {name}: {entry} (move it behind the proper owner; do not add it to the baseline)"
            for _ in range(count)
        )
    for entry, count in sorted((allowed - have).items()):
        problems.extend(f"stale {name} baseline line, delete it: {entry}" for _ in range(count))
    return problems
