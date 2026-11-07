"""The advertised alert summary schema (roadmap T3.4): derived from AlertSummary, never validated."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Iterator, List, Optional

import pytest

from lg_sotf.api.schemas import AlertDetailOut, AlertOut
from lg_sotf.api.summary_schema import ALERT_SUMMARY_SCHEMA, json_schema_of
from lg_sotf.core.state import AlertSummary, DecisionDigest

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 1, tzinfo=UTC)


def _objects(schema: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(schema, dict):
        yield schema
        for value in schema.values():
            yield from _objects(value)
    elif isinstance(schema, list):
        for value in schema:
            yield from _objects(value)


def test_schema_lists_every_alert_summary_key() -> None:
    assert set(ALERT_SUMMARY_SCHEMA["properties"]) == set(AlertSummary.__annotations__)
    assert ALERT_SUMMARY_SCHEMA["type"] == "object" and "required" not in ALERT_SUMMARY_SCHEMA


def test_schema_stays_open_for_keys_added_later() -> None:
    """Tolerant reader: no object in the advertised schema forbids unknown keys."""
    assert all(o.get("additionalProperties") is not False for o in _objects(ALERT_SUMMARY_SCHEMA))


def test_type_hints_map_to_json_schema() -> None:
    assert json_schema_of(Optional[int]) == {"anyOf": [{"type": "integer"}, {"type": "null"}]}
    assert json_schema_of(List[str]) == {"type": "array", "items": {"type": "string"}}
    assert json_schema_of(Dict[str, Any]) == {"type": "object", "additionalProperties": True}
    route = json_schema_of(DecisionDigest)["properties"]["route"]
    assert route == {"type": "string", "enum": ["escalate", "plan_response", "close"]}
    with pytest.raises(TypeError):
        json_schema_of(bytes)


def test_openapi_advertises_the_summary_schema() -> None:
    for model in (AlertOut, AlertDetailOut):
        summary = model.model_json_schema()["properties"]["summary"]
        assert set(summary["properties"]) == set(AlertSummary.__annotations__)


def test_summary_is_not_validated_at_runtime() -> None:
    """Rows written by older releases (other shapes, unknown keys) serialise unchanged."""
    odd = {"triage": "not a digest", "decision": {"route": "unknown_route"}, "legacy_key": [1, 2]}
    alert = AlertOut(
        id="a1", tenant_id="t1", source_id="s1", source_alert_id="x1", fingerprint="f", title="t", severity="low",
        status="closed", occurred_at=T0, ingested_at=T0, updated_at=T0, summary=odd,
    )
    assert alert.model_dump()["summary"] == odd
