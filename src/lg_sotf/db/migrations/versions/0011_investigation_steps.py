"""Investigation trace store: ``investigation_steps``, one row per LLM call and tool call of a run.

Each row records, for one alert and one run (``run_id``; the workflow's
LangGraph thread id), the step's position (``step_index``), the agent,
``kind`` (``llm`` or ``tool``), the prompt name and hash and the provider
and model (LLM steps) or the tool name (tool steps), SHA-256 hashes of the
step's input and output, a redacted, size-capped ``result_digest``, token
counts, latency, start time and the error type of a failed step. Tool
observations are found again by ``(tenant_id, kind, input_hash)``, which
record/replay builds on.

Rows go with their alert (``ON DELETE CASCADE``), so they follow the
tenant's ``alerts_days`` retention and tenant erasure. The table is new and
empty: the migration only changes the catalog. Tenant-scoped with forced
RLS like every tenant table; the runtime role may read and insert, never
update or delete (the trace is append-only).

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-07
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = r"""
CREATE TABLE investigation_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 200),
    step_index INTEGER NOT NULL CHECK (step_index >= 0),
    agent TEXT NOT NULL CHECK (length(agent) BETWEEN 1 AND 64),
    kind TEXT NOT NULL CHECK (kind IN ('llm', 'tool')),
    prompt_name TEXT CHECK (length(prompt_name) <= 64),
    prompt_hash TEXT CHECK (length(prompt_hash) <= 64),
    provider TEXT CHECK (length(provider) <= 128),
    model TEXT CHECK (length(model) <= 128),
    tool TEXT CHECK (length(tool) <= 64),
    input_hash TEXT NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
    output_hash TEXT CHECK (output_hash ~ '^[0-9a-f]{64}$'),
    result_digest JSONB CHECK (result_digest IS NULL OR pg_column_size(result_digest) <= 16384),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'refusal', 'invalid_output', 'error')),
    error_type TEXT CHECK (length(error_type) <= 128),
    input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_read_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    cache_write_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
    latency_ms INTEGER NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
    started_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT investigation_steps_llm_prompt CHECK (kind <> 'llm' OR (prompt_name IS NOT NULL AND prompt_hash IS NOT NULL)),
    CONSTRAINT investigation_steps_tool_name CHECK (kind <> 'tool' OR tool IS NOT NULL),
    CONSTRAINT investigation_steps_run_step_key UNIQUE (tenant_id, alert_id, run_id, step_index),
    CONSTRAINT investigation_steps_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
-- Record/replay: a tool observation by the hash of its input.
CREATE INDEX ix_investigation_steps_input ON investigation_steps (tenant_id, kind, input_hash);
"""

RLS = (
    "ALTER TABLE investigation_steps ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE investigation_steps FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY tenant_isolation ON investigation_steps USING ({TENANT_POLICY_PREDICATE}) "
    f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
)


def upgrade() -> None:
    op.execute(SCHEMA)
    for statement in RLS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS investigation_steps")
