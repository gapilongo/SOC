"""The fact ledger's store: what each investigation run observed (migration 0021).

Rows are append-only: there is no update or delete here, the runtime role has neither privilege, and a
trigger refuses both. :meth:`EvidenceFactsRepo.append` numbers a batch after the entries the run already
has, in one statement. The entries and their ids are built by :mod:`lg_sotf.domain.ledger`; the table's
constraints refuse a row that breaks the ledger's rules, and a second entry with an id the run already
has.

A shadow run stores nothing: its ledger stays with the run (:class:`lg_sotf.agents.investigation.ledger.FactLedger`).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence
from uuid import UUID

from lg_sotf.db.pagination import check_limit
from lg_sotf.db.repos._base import Connection, Record, Repository, affected, to_models
from lg_sotf.domain.ledger import MAX_RUN_ENTRIES, LedgerEntry
from lg_sotf.security.shadow import egress, sink

# Rows as ``LedgerEntry.model_dump(mode="json")`` plus their position ``ord`` in $4, numbered after the run's
# last entry.
_APPEND_SQL = """
    INSERT INTO evidence_facts
        (tenant_id, alert_id, run_id, seq, fact_id, evidence_id, tool, tool_version, input_hash, output_hash,
         outcome, complete, reason, as_of, fact, content_hash)
    SELECT $1, $2, $3, base.first_seq + e.ord, e.fact_id, e.evidence_id, e.tool, e.tool_version, e.input_hash,
           e.output_hash, e.outcome, e.complete, e.reason, e.as_of, e.fact, e.content_hash
    FROM jsonb_to_recordset($4::jsonb) AS e(
        fact_id text, evidence_id text, tool text, tool_version int, input_hash text, output_hash text,
        outcome text, complete boolean, reason text, as_of timestamptz, fact jsonb, content_hash text, ord int
    ),
    (SELECT COALESCE(max(seq) + 1, 0) AS first_seq FROM evidence_facts
     WHERE tenant_id = $1 AND alert_id = $2 AND run_id = $3) AS base
    ORDER BY e.ord
"""


class StoredFact(LedgerEntry, Record):
    """A stored ledger entry."""

    id: UUID
    tenant_id: str
    alert_id: str
    run_id: str
    seq: int
    created_at: datetime


class EvidenceFactsRepo(Repository):
    @egress("fact_ledger", sink(lambda args: len(args["entries"]), detail=lambda a: {"entries": len(a["entries"])}))
    async def append(
        self,
        tenant_id: str,
        alert_id: str,
        run_id: str,
        entries: Sequence[LedgerEntry],
        *,
        conn: Optional[Connection] = None,
    ) -> int:
        """Append ``entries`` (in order) after the run's existing entries. Returns rows inserted."""
        if not entries:
            return 0
        rows = [{**entry.model_dump(mode="json"), "ord": i} for i, entry in enumerate(entries)]
        async with self._tenant(tenant_id, conn) as c:
            return affected(await c.execute(_APPEND_SQL, tenant_id, alert_id, run_id, rows))

    async def list_for_run(
        self, tenant_id: str, alert_id: str, run_id: str, *, conn: Optional[Connection] = None
    ) -> List[StoredFact]:
        """One run's ledger in the order it was recorded (at most ``MAX_RUN_ENTRIES``: a ledger holds no more)."""
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                "SELECT * FROM evidence_facts WHERE tenant_id = $1 AND alert_id = $2 AND run_id = $3 "
                "ORDER BY seq LIMIT $4",
                tenant_id, alert_id, run_id, MAX_RUN_ENTRIES,
            )
        return to_models(StoredFact, rows)

    async def list_latest_run(
        self, tenant_id: str, alert_id: str, *, limit: int = MAX_RUN_ENTRIES, conn: Optional[Connection] = None
    ) -> List[StoredFact]:
        """The first ``limit`` entries of the alert's newest run that has a ledger, in the order they were recorded."""
        check_limit(limit, MAX_RUN_ENTRIES)
        async with self._tenant(tenant_id, conn) as c:
            rows = await c.fetch(
                """
                SELECT * FROM evidence_facts
                WHERE tenant_id = $1 AND alert_id = $2 AND run_id = (
                    SELECT run_id FROM evidence_facts WHERE tenant_id = $1 AND alert_id = $2
                    ORDER BY created_at DESC, run_id DESC LIMIT 1
                )
                ORDER BY seq
                LIMIT $3
                """,
                tenant_id,
                alert_id,
                limit,
            )
        return to_models(StoredFact, rows)
