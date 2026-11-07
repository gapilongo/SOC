"""Evidence fact schema v1 (INT9.2): the model, the published JSON Schema and the examples agree.

The committed ``schemas/evidence-fact/v1.json`` is generated from the model, so
the two cannot drift. Every example is checked twice: by the model in strict
mode, and against the committed JSON Schema by a small 2020-12 validator that
covers the keywords the file uses, so the published file itself is tested.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from lg_sotf.models.evidence_fact import (
    EVIDENCE_FACT,
    FACT_KINDS,
    SCHEMA_ID,
    SCHEMA_VERSION,
    evidence_fact_json_schema,
    fact_expires_at,
    parse_fact,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "schemas" / "evidence-fact"
EXAMPLES = sorted((SCHEMA_DIR / "examples").glob("*.json"))


def _exporter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_schemas", REPO_ROOT / "scripts" / "export_schemas.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _published() -> Dict[str, Any]:
    data = json.loads((SCHEMA_DIR / "v1.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _example(name: str) -> Dict[str, Any]:
    data = json.loads((SCHEMA_DIR / "examples" / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


# ------------------------------------------------- a small 2020-12 validator


def _errors(value: Any, schema: Dict[str, Any], root: Dict[str, Any], path: str = "") -> List[str]:  # noqa: C901
    if "$ref" in schema:
        target: Any = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        return _errors(value, target, root, path)
    if "anyOf" in schema:
        ok = any(not _errors(value, s, root, path) for s in schema["anyOf"])
        return [] if ok else [f"{path}: matches no anyOf branch"]
    if "oneOf" in schema:
        hits = sum(not _errors(value, s, root, path) for s in schema["oneOf"])
        return [] if hits == 1 else [f"{path}: matches {hits} oneOf branches"]
    kinds = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list,
             "object": dict, "null": type(None)}
    if "type" in schema and not isinstance(value, kinds[schema["type"]]) or (
            isinstance(value, bool) and schema.get("type") in ("integer", "number")):
        return [f"{path}: not {schema['type']}"]
    errs: List[str] = []
    if "const" in schema and value != schema["const"]:
        errs.append(f"{path}: not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not in enum")
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            errs.append(f"{path}: length")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: pattern")
        if schema.get("format") == "date-time":
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                errs.append(f"{path}: date-time without offset")
        if schema.get("format") == "uuid":
            uuid.UUID(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not schema.get("minimum", value) <= value <= schema.get("maximum", value):
            errs.append(f"{path}: out of range")
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            errs.append(f"{path}: item count")
        for i, item in enumerate(value):
            errs += _errors(item, schema.get("items", {}), root, f"{path}/{i}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        errs += [f"{path}/{k}: required" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            errs += [f"{path}/{k}: not allowed" for k in value if k not in props]
        for key, item in value.items():
            if key in props:
                errs += _errors(item, props[key], root, f"{path}/{key}")
    return errs


def _schema_errors(fact: Dict[str, Any]) -> List[str]:
    schema = _published()
    return _errors(fact, schema, schema)


# ------------------------------------------------------------ the contract


def test_published_schema_is_generated_from_the_model() -> None:
    exporter = _exporter()
    assert exporter.stale() == [], f"regenerate with: {exporter.REGENERATE}"
    assert _published() == evidence_fact_json_schema()


def test_schema_is_2020_12_and_its_id_carries_the_semver_version() -> None:
    schema = _published()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == SCHEMA_ID == f"urn:lg-sotf:schema:evidence-fact:{SCHEMA_VERSION}"
    assert re.fullmatch(r"1\.\d+\.\d+", SCHEMA_VERSION), "v1.json publishes major 1 only"
    assert set(schema["discriminator"]["mapping"]) == set(FACT_KINDS)
    for name in schema["discriminator"]["mapping"].values():
        fact = schema["$defs"][name.rsplit("/", 1)[-1]]
        assert fact["properties"]["schema_version"]["pattern"] == r"^1\.\d+\.\d+$"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_every_example_is_valid_under_the_model_and_the_published_schema(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    fact = EVIDENCE_FACT.validate_json(text, strict=True)
    assert fact.kind == path.name.split(".")[0]
    assert _schema_errors(json.loads(text)) == []
    # What the model writes back is valid under the schema too.
    assert _schema_errors(fact.model_dump(mode="json")) == []


def test_there_is_an_example_for_every_kind() -> None:
    assert {p.name.split(".")[0] for p in EXAMPLES} == set(FACT_KINDS)


def test_tenant_id_is_internal_never_serialized_and_not_in_the_schema() -> None:
    fact = parse_fact({**_example("reputation.ip.json"), "tenant_id": "test-only-tenant"})
    assert fact.tenant_id == "test-only-tenant"
    dumped = fact.model_dump(mode="json")
    assert "tenant_id" not in dumped and "tenant_id" not in fact.model_dump_json()
    assert "tenant_id" not in json.dumps(_published())
    schema = _published()
    leaked = {**dumped, "tenant_id": "test-only-tenant"}
    assert _errors(leaked, schema["$defs"]["ReputationFact"], schema) == ["/tenant_id: not allowed"]
    assert _schema_errors(leaked)


def test_kind_selects_the_typed_value() -> None:
    lineage = _example("process_lineage.json")
    with pytest.raises(ValidationError):
        parse_fact({**lineage, "kind": "reputation"})
    assert _schema_errors({**lineage, "kind": "reputation"})


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        ({"kind": "dns_lookup"}, "/kind"),
        ({"observed_at": "2026-11-07T09:14:03"}, "/observed_at"),
        ({"schema_version": "2.0.0"}, "/schema_version"),
        ({"confidence": 1.5}, "/confidence"),
        ({"subject": {"type": "mailbox", "value": "x"}}, "/subject/type"),
        ({"provenance": {"input_hash": "ABC"}}, "/provenance/input_hash"),
        ({"claim": "free text from the tool"}, "/claim"),
        ({"redactions": [{"path": "value", "reason": "secret"}]}, "/redactions/0/path"),
    ],
)
def test_invalid_facts_are_refused_by_the_model_and_the_schema(change: Dict[str, Any], pointer: str) -> None:
    fact = {**_example("reputation.ip.json"), **change}
    with pytest.raises(ValidationError):
        parse_fact(fact)
    assert _schema_errors(fact), pointer


def test_optional_fields_may_be_left_out() -> None:
    minimal = copy.deepcopy(_example("reputation.file.json"))
    for key in ("schema_version", "ttl_seconds"):
        minimal.pop(key)
    fact = parse_fact(minimal)
    assert fact.schema_version == SCHEMA_VERSION and fact.provenance is None and fact.redactions == []
    assert _schema_errors(minimal) == []


def test_ttl_gives_the_expiry() -> None:
    fact = parse_fact(_example("reputation.ip.json"))
    assert fact_expires_at(fact) == datetime(2026, 11, 7, 9, 14, 3, tzinfo=UTC) + timedelta(days=1)
    assert fact_expires_at(parse_fact({**_example("related_alert.json")})) is None


def test_the_validator_used_here_rejects_what_it_should() -> None:
    """Guard for the helper itself: a wrong type, a missing field and a bad oneOf all fail."""
    schema = _published()
    assert _errors("x", {"type": "integer"}, schema)
    assert _errors({}, {"type": "object", "required": ["a"]}, schema)
    assert _errors(1, {"oneOf": [{"type": "integer"}, {"type": "number"}]}, schema)
