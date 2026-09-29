"""docs/configuration.md documents every setting and matches the generator (no drift).

Lives with the evaluation tests because both guard product documentation
against the code.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, Type

import pytest
from pydantic import BaseModel

from lg_sotf.core.routing import RoutingThresholds
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
DOC = ROOT / "docs" / "configuration.md"
GENERATOR = ROOT / "docs" / "tools" / "settings_reference.py"


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("settings_reference", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def leaf_paths(model: Type[BaseModel], prefix: str = "") -> Iterator[str]:
    for name, field in model.model_fields.items():
        annotation: Any = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            yield from leaf_paths(annotation, f"{prefix}{name}.")
        else:
            yield f"{prefix}{name}"


def all_paths() -> list[str]:
    return [
        *leaf_paths(Settings),
        *leaf_paths(RoutingThresholds, "routing."),
        *leaf_paths(IngestionOptions, "ingestion."),
    ]


def env_name(path: str) -> str:
    return "LG_SOTF_" + "__".join(p.upper() for p in path.split("."))


def test_every_setting_has_a_row_with_its_environment_variable() -> None:
    text = DOC.read_text(encoding="utf-8")
    missing = [p for p in all_paths() if f"| `{p}` | `{env_name(p)}` |" not in text]
    assert not missing, f"undocumented settings (run python docs/tools/settings_reference.py --write): {missing}"


def test_generator_covers_exactly_the_settings(generator: ModuleType) -> None:
    assert sorted(generator.documented_paths()) == sorted(all_paths())
    described = set(generator.DESCRIPTIONS)
    assert set(all_paths()) <= described
    stale = described - set(all_paths()) - {"agents", "routing", "tools", "ingestion"}
    assert not stale, f"descriptions for settings that no longer exist: {sorted(stale)}"


def test_generated_block_is_up_to_date(generator: ModuleType) -> None:
    text = DOC.read_text(encoding="utf-8")
    assert generator.current_block(text) == generator.render(), (
        "docs/configuration.md is stale: run python docs/tools/settings_reference.py --write"
    )


def test_generator_refuses_an_undescribed_field(generator: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(generator.DESCRIPTIONS, "worker.concurrency")
    with pytest.raises(KeyError, match="worker.concurrency"):
        generator.render()


def test_documented_environment_variables_are_the_ones_settings_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(env_name("llm.deep.model"), "claude-opus-5-5")
    monkeypatch.setenv(env_name("llm.deep.max_concurrency"), "3")
    monkeypatch.setenv(env_name("routing.response_threshold"), "91")
    monkeypatch.setenv(env_name("ingestion.page_size"), "77")
    s = Settings(_env_file=None)
    assert s.llm.deep.max_concurrency == 3
    assert RoutingThresholds.from_settings(s.routing).response_threshold == 91
    assert IngestionOptions.from_settings(s).page_size == 77


def test_partial_tier_override_keeps_the_tier_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(env_name("llm.deep.model"), "claude-opus-5-5")
    s = Settings(_env_file=None)
    defaults = Settings.model_construct().llm.deep
    assert (s.llm.deep.max_tokens, s.llm.deep.timeout_s) == (defaults.max_tokens, defaults.timeout_s)
