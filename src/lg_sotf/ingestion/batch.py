"""One ingestion batch: its result types and the pure steps that build the result.

:meth:`IngestionService._ingest <lg_sotf.ingestion.service.IngestionService>`
normalizes the events, drops in-batch duplicates (:func:`dedupe_batch`),
writes the rest in one tenant transaction, then reports one item per
received event (:func:`assemble_result`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Literal, Mapping, Optional, Sequence, Tuple

from lg_sotf.db.repos import NewAlert
from lg_sotf.models.alert import IngestedAlert

ItemStatus = Literal["inserted", "duplicate", "rejected"]


@dataclass(frozen=True)
class RejectedEvent:
    index: int
    reason: str


@dataclass(frozen=True)
class IngestItem:
    """Per-event outcome, in input order (``POST /ingest/*`` returns these)."""

    index: int
    status: ItemStatus
    alert_id: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class IngestResult:
    inserted: List[IngestedAlert] = field(default_factory=list)
    duplicates: int = 0
    rejected: List[RejectedEvent] = field(default_factory=list)
    items: List[IngestItem] = field(default_factory=list)
    # poll_source only: pages committed, whether the page cap stopped the poll, and the failure (secret-free).
    pages: int = 0
    more_pending: bool = False
    error: Optional[str] = None

    def extend(self, other: IngestResult) -> None:
        offset = len(self.items)
        self.inserted.extend(other.inserted)
        self.duplicates += other.duplicates
        self.rejected.extend(RejectedEvent(r.index + offset, r.reason) for r in other.rejected)
        self.items.extend(
            IngestItem(i.index + offset, i.status, i.alert_id, i.reason) for i in other.items
        )


@dataclass
class PreparedEvent:
    """A normalized event ready to insert, with its index in the batch."""

    index: int
    row: NewAlert


def dedupe_batch(prepared: Sequence[PreparedEvent]) -> Tuple[List[PreparedEvent], Dict[int, str]]:
    """Keep the first event of each ``source_alert_id``; a later one maps its index to that key."""
    unique: List[PreparedEvent] = []
    seen: Dict[str, int] = {}
    in_batch_dupes: Dict[int, str] = {}
    for p in prepared:
        if p.row.source_alert_id in seen:
            in_batch_dupes[p.index] = p.row.source_alert_id
            continue
        seen[p.row.source_alert_id] = p.index
        unique.append(p)
    return unique, in_batch_dupes


def assemble_result(
    received: int,
    reasons: Mapping[int, str],
    in_batch_dupes: Mapping[int, str],
    unique: Sequence[PreparedEvent],
    inserted_ids: AbstractSet[str],
    existing: Mapping[str, str],
) -> IngestResult:
    """One item per received event, in input order: rejected, duplicate (with the stored alert id when
    known) or inserted."""
    result = IngestResult()
    by_index = {p.index: p for p in unique}
    for index in range(received):
        if index in reasons:
            result.rejected.append(RejectedEvent(index, reasons[index]))
            result.items.append(IngestItem(index, "rejected", reason=reasons[index]))
        elif index in in_batch_dupes:
            result.duplicates += 1
            result.items.append(IngestItem(index, "duplicate", alert_id=existing.get(in_batch_dupes[index])))
        else:
            p = by_index[index]
            if p.row.id in inserted_ids:
                result.inserted.append(IngestedAlert(alert_id=p.row.id, severity=p.row.severity))
                result.items.append(IngestItem(index, "inserted", alert_id=p.row.id))
            else:
                result.duplicates += 1
                result.items.append(
                    IngestItem(index, "duplicate", alert_id=existing.get(p.row.source_alert_id))
                )
    return result
