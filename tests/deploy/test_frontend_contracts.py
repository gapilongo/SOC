"""The analyst web app's copies of backend vocabularies match the backend.

The frontend (src/lg_front) cannot import Python, so a few vocabularies are
repeated in TypeScript. These checks parse the TS source and compare keys and
values with the backend, never the wording of descriptions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple, get_args

from lg_sotf.api.schemas import SourceType
from lg_sotf.integrations.config import KINDS, TICKETING_KINDS
from lg_sotf.services.response import GUARDRAIL_REASONS
from tests.deploy._support import REPO_ROOT

# The vocabularies are the SOC module's (ADR 0015): its helpers and its API slice.
SOC_SRC = REPO_ROOT / "src" / "lg_front" / "src" / "modules" / "soc"
GUARDRAILS_TS = SOC_SRC / "lib" / "guardrails.ts"
TYPES_TS = SOC_SRC / "api" / "types.ts"

# blocked_reason codes written by the approval paths rather than by a guardrail.
REVIEWER_REASONS = ("rejected_by_reviewer", "rejected_with_remaining")
REVIEWER_SOURCES = (
    REPO_ROOT / "src" / "lg_sotf" / "services" / "response" / "__init__.py",
    REPO_ROOT / "src" / "lg_sotf" / "services" / "review.py",
)

_STRING = re.compile(r"""'([^'\\]*)'|"([^"\\]*)\"""")
_KEY = re.compile(r"""^\s*(?:([A-Za-z_][A-Za-z0-9_]*)|'([^']+)'|"([^"]+)")\s*:""", re.MULTILINE)


def _ts_array(path: Path, name: str) -> List[str]:
    """String values of ``export const NAME[: type] = [ ... ]`` (with or without ``as const``)."""
    match = re.search(rf"export const {name}\b[^=]*=\s*\[(.*?)\]", path.read_text(encoding="utf-8"), re.DOTALL)
    assert match, f"{path.relative_to(REPO_ROOT)}: no array named {name}"
    return [a or b for a, b in _STRING.findall(match.group(1))]


def _ts_object_keys(path: Path, name: str) -> List[str]:
    """Keys of ``export const NAME[: type] = { ... };`` (one entry per line)."""
    match = re.search(rf"export const {name}\b[^=]*=\s*\{{(.*?)\n\}};", path.read_text(encoding="utf-8"), re.DOTALL)
    assert match, f"{path.relative_to(REPO_ROOT)}: no object named {name}"
    return [a or b or c for a, b, c in _KEY.findall(match.group(1))]


def _assert_same_values(ts_name: str, ts_values: List[str], backend: Tuple[str, ...]) -> None:
    assert len(ts_values) == len(set(ts_values)), f"{ts_name} has duplicates: {ts_values}"
    assert set(ts_values) == set(backend), (
        f"{ts_name} differs from the backend: missing {sorted(set(backend) - set(ts_values))}, "
        f"extra {sorted(set(ts_values) - set(backend))}"
    )


def test_every_guardrail_reason_has_a_description() -> None:
    keys = _ts_object_keys(GUARDRAILS_TS, "GUARDRAIL_REASONS")
    assert len(keys) == len(set(keys)), f"duplicate keys in guardrails.ts: {keys}"
    missing = sorted(set(GUARDRAIL_REASONS) - set(keys))
    assert not missing, f"lib/guardrails.ts has no description for {missing} (analysts would see the raw code)"


def test_reviewer_reasons_have_a_description() -> None:
    backend = "\n".join(p.read_text(encoding="utf-8") for p in REVIEWER_SOURCES)
    keys = set(_ts_object_keys(GUARDRAILS_TS, "GUARDRAIL_REASONS"))
    for reason in REVIEWER_REASONS:
        assert f'"{reason}"' in backend, f"the backend no longer writes {reason}; update REVIEWER_REASONS"
        assert reason in keys, f"lib/guardrails.ts has no description for {reason}"


def test_source_types_match_the_api_schema() -> None:
    _assert_same_values("SOURCE_TYPES", _ts_array(TYPES_TS, "SOURCE_TYPES"), get_args(SourceType))


def test_integration_kinds_match_the_backend() -> None:
    _assert_same_values("INTEGRATION_KINDS", _ts_array(TYPES_TS, "INTEGRATION_KINDS"), KINDS)


def test_ticketing_kinds_match_the_backend() -> None:
    _assert_same_values("TICKETING_KINDS", _ts_array(TYPES_TS, "TICKETING_KINDS"), TICKETING_KINDS)
