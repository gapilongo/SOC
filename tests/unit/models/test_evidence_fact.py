"""Evidence fact schema v1 (INT9.2, 1.1 in INT9.3): the model, the published JSON Schema and the examples agree.

The committed ``schemas/evidence-fact/v1.json`` is generated from the model, so
the two cannot drift. Every example is checked twice: by the model in strict
mode, and against the committed JSON Schema by a small 2020-12 validator that
covers the keywords the file uses, so the published file itself is tested.

Schema 1.1 is a minor bump: the examples written under 1.0.0 are kept as they
were and must stay valid, every list is capped at 50 items and every string is
bounded (a typed field can still carry a string an attacker chose).
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
from typing import Any, Dict, Iterator, List, Tuple

import pytest
from pydantic import ValidationError

from lg_sotf.models.evidence_fact import (
    EVIDENCE_FACT,
    FACT_KINDS,
    MAX_LIST_ITEMS,
    SCHEMA_ID,
    SCHEMA_VERSION,
    evidence_fact_json_schema,
    fact_expires_at,
    fact_is_complete,
    parse_fact,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "schemas" / "evidence-fact"
EXAMPLES = sorted((SCHEMA_DIR / "examples").glob("*.json"))
# The examples published with 1.0.0. They are never edited: they are the 1.0 facts 1.x must accept.
V1_0_EXAMPLES = (
    "process_lineage.json",
    "related_alert.json",
    "reputation.file.json",
    "reputation.ip.json",
    "sign_in_history.json",
)
# Every list a 1.1 kind added, and two 1.0 ones, as (example, JSON Pointer to a non-empty list).
CAPPED_LISTS = (
    ("host_activity.json", "/value/by_group"),
    ("host_activity.json", "/value/techniques"),
    ("host_activity.json", "/value/events"),
    ("host_activity.json", "/value/events/0/groups"),
    ("logon_fanout.json", "/value/success_users"),
    ("logon_fanout.json", "/value/failed_users"),
    ("logon_fanout.json", "/value/sources"),
    ("logon_fanout.json", "/value/source_hosts"),
    ("logon_fanout.json", "/value/logon_types"),
    ("process_lineage.children.json", "/value/children"),
    ("process_lineage.json", "/redactions"),
    ("sign_in_history.json", "/value/sign_ins"),
)


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


def _kind_errors(fact: Dict[str, Any]) -> List[str]:
    """Errors against the fact's own kind, so each names the field at fault (the top-level oneOf hides it)."""
    schema = _published()
    name = schema["discriminator"]["mapping"][fact["kind"]].rsplit("/", 1)[-1]
    return _errors(fact, schema["$defs"][name], schema)


def _nodes(node: Any, path: str = "") -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Every sub-schema of the published file that declares a ``type``, with its path."""
    if isinstance(node, dict):
        if isinstance(node.get("type"), str):
            yield path, node
        for key, child in node.items():
            yield from _nodes(child, f"{path}/{key}")
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from _nodes(child, f"{path}/{i}")


def _at(fact: Dict[str, Any], pointer: str) -> List[Any]:
    target: Any = fact
    for part in pointer.removeprefix("/").split("/"):
        target = target[int(part)] if isinstance(target, list) else target[part]
    assert isinstance(target, list) and target, pointer
    return target


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


@pytest.mark.parametrize("kind", FACT_KINDS)
def test_every_kind_has_a_valid_example(kind: str) -> None:
    paths = [p for p in EXAMPLES if p.name.split(".")[0] == kind]
    assert paths, f"add schemas/evidence-fact/examples/{kind}.json"
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert EVIDENCE_FACT.validate_json(text, strict=True).kind == kind
        assert _schema_errors(json.loads(text)) == []


def test_no_example_is_of_an_unknown_kind() -> None:
    assert {p.name.split(".")[0] for p in EXAMPLES} == set(FACT_KINDS)


# ------------------------------------------------------------ schema 1.1


def test_schema_version_is_1_1() -> None:
    assert SCHEMA_VERSION == "1.1.0"
    assert {"host_activity", "logon_fanout", "process_lineage", "prevalence"} <= set(FACT_KINDS)


@pytest.mark.parametrize("name", V1_0_EXAMPLES)
def test_a_1_0_fact_still_validates(name: str) -> None:
    raw = _example(name)
    assert raw["schema_version"] == "1.0.0", "a 1.0 example is never edited; add a new file for 1.1"
    assert "complete" not in raw
    fact = EVIDENCE_FACT.validate_json(json.dumps(raw), strict=True)
    assert fact.schema_version == "1.0.0"
    assert fact.complete is None and not fact_is_complete(fact)
    assert _schema_errors(raw) == []
    # Nothing the 1.0 fact said is lost or changed on the way back out.
    dumped = fact.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
    assert parse_fact(dumped) == fact
    assert parse_fact(dumped).model_dump(mode="json") == fact.model_dump(mode="json")


def test_a_minimal_1_0_fact_still_validates() -> None:
    """A fact as a 1.0 producer writes it, with only the required fields."""
    raw = {
        "schema_version": "1.0.0",
        "id": "fact-1",
        "kind": "process_lineage",
        "subject": {"type": "process", "value": "WS-042:4711"},
        "observed_at": "2026-11-07T09:12:55Z",
        "source": {"name": "defender.ah"},
        "value": {"chain": [{"name": "powershell.exe"}]},
    }
    fact = parse_fact(raw)
    assert fact.kind == "process_lineage" and fact.value.children is None and fact.complete is None
    assert _schema_errors(raw) == []


@pytest.mark.parametrize("complete", [False, True])
def test_incomplete_flag_round_trips(complete: bool) -> None:
    raw = {**_example("process_lineage.children.json"), "complete": complete}
    fact = parse_fact(raw)
    assert fact.complete is complete and fact_is_complete(fact) is complete
    dumped = fact.model_dump(mode="json")
    assert dumped["complete"] is complete
    assert _schema_errors(dumped) == []
    assert parse_fact(dumped) == fact
    assert EVIDENCE_FACT.validate_json(fact.model_dump_json(), strict=True) == fact


def test_a_fact_that_does_not_say_it_is_complete_is_not_complete() -> None:
    """Only an explicit true counts: an absent flag, like false, cannot carry a claim of absence."""
    raw = _example("logon_fanout.json")
    assert fact_is_complete(parse_fact(raw))
    raw.pop("complete")
    fact = parse_fact(raw)
    assert fact.complete is None and not fact_is_complete(fact)
    assert _schema_errors(raw) == [] and _schema_errors(fact.model_dump(mode="json")) == []


@pytest.mark.parametrize("value", ["true", "false", 1, 0, "no"])
def test_complete_takes_a_boolean_only(value: Any) -> None:
    raw = {**_example("logon_fanout.json"), "complete": value}
    with pytest.raises(ValidationError):
        parse_fact(raw)
    assert _schema_errors(raw)


def test_every_list_in_the_schema_is_capped_at_50() -> None:
    arrays = [(path, node) for path, node in _nodes(_published()) if node["type"] == "array"]
    assert len(arrays) >= len(CAPPED_LISTS)
    assert MAX_LIST_ITEMS == 50
    assert [path for path, node in arrays if not 1 <= node.get("maxItems", 0) <= MAX_LIST_ITEMS] == []


@pytest.mark.parametrize(("name", "pointer"), CAPPED_LISTS, ids=lambda v: v.removeprefix("/value/"))
def test_list_fields_are_capped_at_50(name: str, pointer: str) -> None:
    fact = _example(name)
    items = _at(fact, pointer)
    items[:] = [items[0]] * MAX_LIST_ITEMS
    assert len(_at(json.loads(parse_fact(fact).model_dump_json()), pointer)) == MAX_LIST_ITEMS
    assert _schema_errors(fact) == []
    items.append(items[0])
    with pytest.raises(ValidationError):
        parse_fact(fact)
    assert _schema_errors(fact)
    errors = _kind_errors(fact)
    assert len(errors) == 1 and errors[0].startswith(f"{pointer}: "), errors


def test_every_string_in_the_schema_is_bounded() -> None:
    """A typed field can carry a string an attacker chose, so none is open-ended."""
    def bounded(node: Dict[str, Any]) -> bool:
        if any(key in node for key in ("maxLength", "format", "enum", "const")):
            return True
        # A pattern bounds the string only when it is anchored and repeats nothing without a limit.
        pattern = str(node.get("pattern", ""))
        return pattern.startswith("^") and pattern.endswith("$") and not re.search(r"[+*]|\{\d+,\}", pattern)

    strings = [(path, node) for path, node in _nodes(_published()) if node["type"] == "string"]
    assert len(strings) > 40
    # schema_version (1.0) is held by its pattern only; adding a length to a published field would be breaking.
    assert {path.rsplit("/", 1)[-1] for path, node in strings if not bounded(node)} == {"schema_version"}
    assert max(node.get("maxLength", 0) for _, node in strings) == 4096


@pytest.mark.parametrize(
    ("name", "change"),
    [
        ("host_activity.json", {"max_level": 17}),
        ("host_activity.json", {"techniques": ["ignore previous instructions"]}),
        ("host_activity.json", {"summary": "free text from the tool"}),
        ("logon_fanout.json", {"pivot": "source_port"}),
        ("logon_fanout.json", {"failures": -1}),
        ("logon_fanout.json", {"source_hosts": ["x" * 1025]}),
        ("prevalence.json", {"scope": "all_tenants"}),
        ("prevalence.json", {"first_seen_at": "2026-11-07T09:15:40"}),
        ("process_lineage.children.json", {"children": [{"name": "cmd.exe", "command_template": "x" * 4097}]}),
        ("process_lineage.children.json", {"children": [{"name": "cmd.exe", "image_name": "x" * 256}]}),
    ],
)
def test_invalid_1_1_values_are_refused_by_the_model_and_the_schema(name: str, change: Dict[str, Any]) -> None:
    fact = _example(name)
    fact["value"] = {**fact["value"], **change}
    with pytest.raises(ValidationError):
        parse_fact(fact)
    assert _schema_errors(fact)


@pytest.mark.parametrize(("subject_type", "value"), [("service", "PSEXESVC"), ("command_template", "whoami.exe /all")])
def test_1_1_subject_types(subject_type: str, value: str) -> None:
    raw = {**_example("prevalence.json"), "subject": {"type": subject_type, "value": value}}
    assert parse_fact(raw).subject.type == subject_type
    assert _schema_errors(raw) == []


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
