"""The fact ledger: ``evidence_facts``, what each investigation run observed (AI-E3.2).

One row per typed evidence fact a tool call returned, and one row without a fact for a call that
returned none (``empty``, ``failed``, or an answer that holds no typed fact). Each row has the id a
verdict cites (``fact_id``, ``<evidence id>:<n>``, minted by ``lg_sotf.domain.ledger``, unique in the
run), its position in the run (``seq``), and the call it came from: the tool and its version, the trace
step's input and output hashes, the outcome, whether the answer was complete and when it was recorded.
``fact`` is the evidence fact (schema v1) under that id; ``content_hash`` is the SHA-256 of every other
field of the row's entry. ``run_id`` is the investigation run (``inv_`` and 32 hex digits), never the alert.

The table states the ledger's rules itself: a row without ``success`` never holds a fact, a failed
call is never complete, a row with a fact is complete exactly when the fact says so, the id and the
input hash inside the fact are the row's, and a run holds at most 200 rows.

Append-only. The runtime role may read and insert, never update or delete. A trigger also refuses
every update, and refuses a delete or a truncate unless it is retention or tenant erasure (the schema
owner with the row-security bypass on), which remove the rows with their alert (``ON DELETE CASCADE``).
Tenant-scoped with forced RLS like every tenant table. The table is new and empty: the migration only
changes the catalog, and the previous release never reads or writes it.

Revision ID: 0021
Revises: 0018
Create Date: 2026-11-14
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0021"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = r"""
CREATE TABLE evidence_facts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 200),
    seq INTEGER NOT NULL CHECK (seq BETWEEN 0 AND 199),
    fact_id TEXT NOT NULL CHECK (fact_id ~ '^[a-z][a-z0-9_.-]{0,63}:(0|[1-9][0-9]{0,5})$'),
    evidence_id TEXT NOT NULL CHECK (evidence_id ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    tool TEXT NOT NULL CHECK (length(tool) BETWEEN 1 AND 64),
    tool_version INTEGER NOT NULL CHECK (tool_version >= 1),
    input_hash TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    output_hash TEXT CHECK (output_hash ~ '^[0-9a-f]{64}$'),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'empty', 'failed')),
    complete BOOLEAN NOT NULL,
    reason TEXT CHECK (length(reason) <= 64),
    as_of TIMESTAMPTZ NOT NULL,
    fact JSONB CHECK (fact IS NULL OR octet_length(fact::text) <= 2097152),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT evidence_facts_id_names_evidence CHECK (split_part(fact_id, ':', 1) = evidence_id),
    CONSTRAINT evidence_facts_fact_needs_success CHECK (fact IS NULL OR outcome = 'success'),
    CONSTRAINT evidence_facts_failed_incomplete CHECK (outcome <> 'failed' OR NOT complete),
    -- One notion of complete: a row with a fact is complete exactly when the fact says so.
    CONSTRAINT evidence_facts_complete_is_the_facts CHECK (
        fact IS NULL OR complete = COALESCE(fact -> 'complete' = 'true'::jsonb, false)
    ),
    -- IS NOT DISTINCT FROM: a fact without an id or without its call's hash is refused, not passed as NULL.
    CONSTRAINT evidence_facts_fact_is_bound CHECK (
        fact IS NULL OR ((fact ->> 'id') IS NOT DISTINCT FROM fact_id
                         AND (fact #>> '{provenance,input_hash}') IS NOT DISTINCT FROM input_hash)
    ),
    CONSTRAINT evidence_facts_run_seq_key UNIQUE (tenant_id, alert_id, run_id, seq),
    CONSTRAINT evidence_facts_run_fact_key UNIQUE (tenant_id, alert_id, run_id, fact_id),
    CONSTRAINT evidence_facts_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);

-- Schema-qualified: tenant erasure deletes with search_path = pg_catalog.
CREATE FUNCTION evidence_facts_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' AND public.lgsotf_rls_bypass() THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'evidence_facts is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER evidence_facts_immutable BEFORE UPDATE OR DELETE ON evidence_facts
    FOR EACH ROW EXECUTE FUNCTION evidence_facts_block_mutation();
CREATE TRIGGER evidence_facts_no_truncate BEFORE TRUNCATE ON evidence_facts
    FOR EACH STATEMENT EXECUTE FUNCTION evidence_facts_block_mutation();
"""

RLS = (
    "ALTER TABLE evidence_facts ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE evidence_facts FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY tenant_isolation ON evidence_facts USING ({TENANT_POLICY_PREDICATE}) "
    f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
)


def upgrade() -> None:
    op.execute(SCHEMA)
    for statement in RLS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS evidence_facts")
    op.execute("DROP FUNCTION IF EXISTS evidence_facts_block_mutation()")
