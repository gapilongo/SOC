from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from lg_sotf.models.alert import (
    MAX_ENTITY_ITEMS,
    MAX_TITLE_CHARS,
    MAX_UNMAPPED_BYTES,
    TRUNCATED_MARKER,
    CanonicalAlert,
    Entities,
    cap_mapping,
    json_size,
    map_severity,
    severity_from_name,
    severity_from_scale,
)


def _alert(**overrides: object) -> CanonicalAlert:
    values: dict = {
        "source_id": "s1",
        "source_type": "canonical",
        "source_alert_id": "a1",
        "title": "t",
        "severity": "low",
        "occurred_at": datetime(2024, 1, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return CanonicalAlert(**values)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("High", "high"),
        (" informational ", "info"),
        ("CRITICAL", "critical"),
        ("moderate", "medium"),
        ("warning", "medium"),
        ("very_high", "critical"),
        ("emerg", "critical"),
        ("notice", "low"),
        ("bogus", None),
        (5, None),
    ],
)
def test_severity_names(name: object, expected: str | None) -> None:
    assert severity_from_name(name) == expected


@pytest.mark.parametrize(
    ("value", "scale", "expected"),
    [
        (0, "0-10", "info"),
        (3, "0-10", "low"),
        (6, "0-10", "medium"),
        (8, "0-10", "high"),
        (10, "0-10", "critical"),
        (11, "0-10", None),
        (2, "0-15", "info"),
        (10, "0-15", "medium"),
        (12, "0-15", "high"),
        (15, "0-15", "critical"),
        (19, "0-100", "info"),
        (20, "0-100", "low"),
        (69, "0-100", "medium"),
        (70, "0-100", "high"),
        (90, "0-100", "critical"),
        (101, "0-100", None),
        (1, "1-4", "low"),
        (4, "1-4", "critical"),
        (0, "1-4", None),
        (1, "1-5", "info"),
        ("5", "1-5", "critical"),
        (3.9, "guardduty", "low"),
        (5, "guardduty", "medium"),
        (8.9, "guardduty", "high"),
        (9.0, "guardduty", "critical"),
        (float("nan"), "0-10", None),
        (True, "0-10", None),
        ("abc", "1-5", None),
    ],
)
def test_severity_scales(value: object, scale: str, expected: str | None) -> None:
    assert severity_from_scale(value, scale) == expected


def test_unknown_scale_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        severity_from_scale(1, "0-7")


def test_map_severity_requires_scale_for_numbers() -> None:
    assert map_severity(8) is None
    assert map_severity(8, "0-10") == "high"
    assert map_severity("high", "0-10") == "high"


def test_canonical_alert_caps_and_normalizes_text() -> None:
    alert = _alert(
        title="  multi\n line\x00 title " + "x" * 2000,
        description="d\x00" * 10,
        category="  cat  ",
        occurred_at=datetime(2024, 1, 1, 12, tzinfo=timezone(timedelta(hours=2))),
    )
    assert "\x00" not in alert.title and "\n" not in alert.title
    assert len(alert.title) == MAX_TITLE_CHARS and alert.title.endswith("[truncated]")
    assert alert.description == "d" * 10
    assert alert.category == "cat"
    assert alert.occurred_at == datetime(2024, 1, 1, 10, tzinfo=UTC)
    assert alert.severity_id == 2
    assert alert.class_uid == 2004


def test_canonical_alert_rejects_naive_time_and_bad_severity() -> None:
    with pytest.raises(ValidationError):
        _alert(occurred_at=datetime(2024, 1, 1))
    with pytest.raises(ValidationError):
        _alert(severity="urgent")
    with pytest.raises(ValidationError):
        _alert(title=" \x00 ")


def test_entities_dedup_and_cap() -> None:
    entities = Entities(hosts=[f"h{i}" for i in range(200)] + ["h1"], ips=["1.1.1.1", "1.1.1.1"])
    assert len(entities.hosts) == MAX_ENTITY_ITEMS
    assert entities.ips == ["1.1.1.1"]
    assert not entities.is_empty()
    assert Entities().is_empty()


def test_unmapped_is_size_capped() -> None:
    alert = _alert(unmapped={"big": "x" * 100_000, "items": list(range(10_000))})
    assert json_size(alert.unmapped) <= MAX_UNMAPPED_BYTES
    assert TRUNCATED_MARKER in alert.unmapped


def test_cap_mapping_keeps_small_documents_and_marks_large_ones() -> None:
    small = {"a": 1}
    assert cap_mapping(small, 1024) == small
    huge = {f"k{i}": "\"" * 5000 for i in range(200)}
    capped = cap_mapping(huge, 4096)
    assert json_size(capped) <= 4096
    assert capped[TRUNCATED_MARKER]["original_bytes"] == json_size(huge)


def test_normalized_document_excludes_raw() -> None:
    doc = _alert(raw={"secret": "x"}).normalized_document()
    assert "raw" not in doc
    assert doc["severity_id"] == 2
    assert doc["occurred_at"].startswith("2024-01-01T00:00:00")


def test_ingestion_metrics_use_their_own_registry() -> None:
    from lg_sotf.ingestion import metrics
    from lg_sotf.observability.metrics import REGISTRY as CONTRACT_REGISTRY

    metrics.record_events("splunk", "inserted", 2)
    metrics.record_poll("splunk", True, 0.5)
    assert metrics.REGISTRY is not CONTRACT_REGISTRY
    assert metrics.REGISTRY.get_sample_value(
        "lgsotf_ingest_events_total", {"source_type": "splunk", "outcome": "inserted"}
    ) >= 2


@pytest.mark.parametrize("placeholder", ["unknown", "Unknown", "none", "NONE", "n/a", ""])
def test_placeholder_severity_names_are_not_mapped(placeholder: str) -> None:
    assert severity_from_name(placeholder) is None
    assert map_severity(placeholder) is None


def test_huge_numeric_severity_is_out_of_scale_not_an_error() -> None:
    assert severity_from_scale(10**400, "0-10") is None
    assert severity_from_scale("1" * 500, "0-100") is None


def test_json_size_tolerates_lone_surrogates() -> None:
    assert json_size({"a": "\ud800"}) > 0
