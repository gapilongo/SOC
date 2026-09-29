"""Every lg_sotf module imports, so a deleted module that something still needs fails CI.

``KNOWN_BROKEN`` lists legacy modules that still import code this wave
removed (``core.state``, ``audit.metrics``) and are being ported by their
owners (API/app initializer, human-loop agents). The xfail is strict: once a
module imports again the test fails until it is taken off the list.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import List

import pytest

import lg_sotf

# Alembic's env script only runs inside an alembic command context.
NOT_IMPORTABLE_BY_DESIGN = frozenset({"lg_sotf.db.migrations.env"})
KNOWN_BROKEN = {
    "lg_sotf.app_initializer": "imports lg_sotf.audit.metrics and lg_sotf.core.state (removed); port to WorkflowEngine.create",
    "lg_sotf.api": "imports lg_sotf.app_initializer",
    "lg_sotf.agents.human_loop": "imports lg_sotf.core.state (removed); fold into services.escalation",
}


def _modules() -> List[str]:
    names = {"lg_sotf"}
    for info in pkgutil.walk_packages(lg_sotf.__path__, "lg_sotf.", onerror=lambda name: None):
        names.add(info.name)
    names.update(KNOWN_BROKEN)
    return sorted(names - NOT_IMPORTABLE_BY_DESIGN)


def _param(name: str) -> object:
    if name in KNOWN_BROKEN:
        return pytest.param(name, marks=pytest.mark.xfail(reason=KNOWN_BROKEN[name], raises=ImportError, strict=True))
    return name


@pytest.mark.parametrize("module", [_param(m) for m in _modules()])
def test_module_imports(module: str) -> None:
    importlib.import_module(module)


def test_engine_modules_do_not_import_removed_packages() -> None:
    for removed in ("lg_sotf.core.state", "lg_sotf.audit.metrics", "lg_sotf.audit.tracer", "lg_sotf.config"):
        with pytest.raises(ImportError):
            importlib.import_module(removed)
