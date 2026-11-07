"""Pure batch steps of IngestionService._ingest: in-batch de-duplication and the per-event result."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, List

from lg_sotf.db.repos import NewAlert
from lg_sotf.ingestion.batch import IngestItem, PreparedEvent, RejectedEvent, assemble_result, dedupe_batch
from lg_sotf.models.alert import IngestedAlert

T0 = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)


def prepared(index: int, key: str, *, alert_id: str = "", severity: str = "high") -> PreparedEvent:
    row = NewAlert(
        id=alert_id or f"id-{index}",
        source_id="src",
        source_alert_id=key,
        fingerprint=f"fp-{key}",
        title=f"event {index}",
        severity=severity,
        occurred_at=T0,
    )
    return PreparedEvent(index=index, row=row)


def test_dedupe_keeps_the_first_event_of_each_key_in_order() -> None:
    batch = [prepared(0, "k1"), prepared(2, "k2"), prepared(3, "k1"), prepared(5, "k3"), prepared(6, "k2")]
    unique, dupes = dedupe_batch(batch)
    assert [p.index for p in unique] == [0, 2, 5]
    assert dupes == {3: "k1", 6: "k2"}


def test_dedupe_of_an_empty_or_distinct_batch() -> None:
    assert dedupe_batch([]) == ([], {})
    batch = [prepared(0, "a"), prepared(1, "b")]
    unique, dupes = dedupe_batch(batch)
    assert unique == batch and dupes == {}


def test_assemble_result_reports_every_event_in_input_order() -> None:
    # 0 inserted, 1 rejected, 2 duplicate of a stored alert, 3 duplicate of 0 within the batch,
    # 4 duplicate of a stored alert the lookup did not return, 5 inserted.
    unique = [prepared(0, "k0"), prepared(2, "k2"), prepared(4, "k4"), prepared(5, "k5", severity="low")]
    reasons: Dict[int, str] = {1: "missing title"}
    in_batch: Dict[int, str] = {3: "k0"}
    inserted = {"id-0", "id-5"}
    existing = {"k0": "id-0", "k2": "stored-2"}
    result = assemble_result(6, reasons, in_batch, unique, inserted, existing)
    assert result.items == [
        IngestItem(0, "inserted", alert_id="id-0"),
        IngestItem(1, "rejected", reason="missing title"),
        IngestItem(2, "duplicate", alert_id="stored-2"),
        IngestItem(3, "duplicate", alert_id="id-0"),
        IngestItem(4, "duplicate", alert_id=None),
        IngestItem(5, "inserted", alert_id="id-5"),
    ]
    assert result.inserted == [IngestedAlert(alert_id="id-0", severity="high"), IngestedAlert("id-5", "low")]
    assert result.rejected == [RejectedEvent(1, "missing title")]
    assert result.duplicates == 3
    assert (result.pages, result.more_pending, result.error) == (0, False, None)


def test_assemble_result_of_an_all_rejected_batch() -> None:
    reasons = {0: "bad", 1: "worse"}
    result = assemble_result(2, reasons, {}, [], set(), {})
    assert [i.status for i in result.items] == ["rejected", "rejected"]
    assert result.inserted == [] and result.duplicates == 0
    assert [r.reason for r in result.rejected] == ["bad", "worse"]


def test_assemble_result_of_an_empty_batch() -> None:
    result = assemble_result(0, {}, {}, [], set(), {})
    empty: List[IngestItem] = []
    assert result.items == empty and result.inserted == [] and result.rejected == [] and result.duplicates == 0
