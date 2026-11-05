"""Snapshot: the committed ``docs/openapi.json`` is what the app publishes today.

The document churns on FastAPI or pydantic upgrades and on version bumps;
regenerating is one command (``REGENERATE``) and the diff is reviewed.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "export_openapi.py"


def _exporter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_openapi", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_openapi_matches_the_app() -> None:
    exporter = _exporter()
    text = exporter.render(exporter.build_openapi())
    committed_path: Path = exporter.OUTPUT
    assert committed_path.exists(), f"docs/openapi.json is missing; create it with: {exporter.REGENERATE}"
    committed = committed_path.read_text(encoding="utf-8")
    if committed == text:
        return
    old, new = json.loads(committed), json.loads(text)
    paths = sorted(set(old.get("paths", {})) ^ set(new.get("paths", {})))
    changed = sorted(
        p for p in set(old.get("paths", {})) & set(new.get("paths", {})) if old["paths"][p] != new["paths"][p]
    )
    schemas_old, schemas_new = (
        old.get("components", {}).get("schemas", {}),
        new.get("components", {}).get("schemas", {}),
    )
    changed_schemas = sorted(k for k in set(schemas_old) | set(schemas_new) if schemas_old.get(k) != schemas_new.get(k))
    raise AssertionError(
        "docs/openapi.json is out of date with the app.\n"
        f"  paths added/removed: {paths}\n"
        f"  paths changed: {changed}\n"
        f"  schemas changed: {changed_schemas}\n"
        f"  info.version: {old.get('info', {}).get('version')} -> {new.get('info', {}).get('version')}\n"
        f"If the API change is intended, regenerate and review the diff: {exporter.REGENERATE}"
    )
