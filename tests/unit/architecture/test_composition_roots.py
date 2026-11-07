"""Only the composition roots build the process's SecretBox (D7, docs/adr/0006-encryption-keys-validated-at-startup.md).

``SecretBox.from_settings`` and ``load_secret_box`` may be called only from
``security/crypto.py`` (where they live), ``api/app.py``, ``runtime/*.py`` and
``cli.py``. Every other component receives the box from its caller, so each
process validates its keys once, at startup. There is no allowlist.
"""

from __future__ import annotations

import ast

import pytest

from tests.unit.architecture._support import MODULE_LEVEL, iter_calls, source_files

pytestmark = pytest.mark.unit

ROOTS = ("security/crypto.py", "api/app.py", "cli.py")


def is_root(rel: str) -> bool:
    return rel in ROOTS or (rel.startswith("runtime/") and rel.count("/") == 1)


def box_builders(rel: str, tree: ast.Module) -> list[str]:
    """``SecretBox.from_settings(...)`` and ``load_secret_box(...)`` calls, as ``path::qualname``."""
    found: list[str] = []
    for call, qual in iter_calls(tree):
        func = call.func
        if isinstance(func, ast.Name):
            builds = func.id == "load_secret_box"
        elif isinstance(func, ast.Attribute):
            on_box = isinstance(func.value, ast.Name) and func.value.id == "SecretBox"
            builds = func.attr == "load_secret_box" or (func.attr == "from_settings" and on_box)
        else:
            builds = False
        if builds:
            found.append(f"{rel}::{qual or MODULE_LEVEL}")
    return found


def test_only_the_composition_roots_build_a_secret_box() -> None:
    outside = [loc for src in source_files() if not is_root(src.rel) for loc in box_builders(src.rel, src.tree)]
    assert not outside, f"build the SecretBox in a composition root and inject it (ADR-0006): {outside}"


def test_the_roots_do_build_it() -> None:
    builders = {loc.split("::")[0] for src in source_files() for loc in box_builders(src.rel, src.tree)}
    assert {"api/app.py", "runtime/worker.py", "runtime/scheduler.py", "security/crypto.py"} <= builders


def test_the_scan_sees_every_spelling() -> None:
    sample = ast.parse(
        "from lg_sotf.security import crypto\n"
        "a = SecretBox.from_settings(s)\n"
        "def f():\n    return load_secret_box(s)\n"
        "class C:\n    def g(self):\n        return crypto.load_secret_box(s)\n"
        "b = RoutingThresholds.from_settings(s)\n"
    )
    assert box_builders("x.py", sample) == ["x.py::<module>", "x.py::f", "x.py::C.g"]
    assert is_root("runtime/worker.py") and not is_root("runtime/sub/x.py") and not is_root("services/x.py")
