"""Proof-of-value runs (PRD-11.1): ``pov_runs``.

One row per PoV run of a tenant: its name, the history window the backtest
replays (``[backtest_start, backtest_end)``), the shadow period that follows
(``[shadow_start, shadow_end)``), the backtest's status and its stored
result (the evaluation report without its per-alert items), and who created
or cancelled it. A run references no alert: it only reads them.

Forced RLS like every tenant table. The runtime role (the API) may read
runs, insert one (named columns only: never a backtest status or result) and
cancel one (``cancelled_at``, ``cancelled_by``). The backtest columns are
written by the scheduler, which connects as the schema owner.

Revision ID: 0019
Revises: 0017
Create Date: 2026-11-14
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0019"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = """
CREATE TABLE pov_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    backtest_start TIMESTAMPTZ NOT NULL,
    backtest_end TIMESTAMPTZ NOT NULL,
    shadow_start TIMESTAMPTZ NOT NULL,
    shadow_end TIMESTAMPTZ NOT NULL,
    backtest_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (backtest_status IN ('pending', 'running', 'completed', 'no_data', 'failed')),
    backtest_attempts INTEGER NOT NULL DEFAULT 0 CHECK (backtest_attempts >= 0),
    backtest_started_at TIMESTAMPTZ,
    backtest_finished_at TIMESTAMPTZ,
    backtest_error TEXT CHECK (length(backtest_error) <= 300),
    backtest_result JSONB,
    created_by TEXT CHECK (length(created_by) <= 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at TIMESTAMPTZ,
    cancelled_by TEXT CHECK (length(cancelled_by) <= 200),
    CONSTRAINT pov_runs_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT pov_runs_backtest_window CHECK (backtest_end > backtest_start),
    CONSTRAINT pov_runs_shadow_window CHECK (shadow_end > shadow_start),
    CONSTRAINT pov_runs_shadow_after_backtest CHECK (shadow_start >= backtest_end),
    CONSTRAINT pov_runs_result_when_completed CHECK (backtest_result IS NULL OR backtest_status = 'completed')
);
CREATE INDEX ix_pov_runs_created ON pov_runs (tenant_id, created_at DESC, id DESC);
-- The scheduler's queue: backtests still to run, oldest run first.
CREATE INDEX ix_pov_runs_backtest_queue ON pov_runs (created_at, id)
    WHERE backtest_status IN ('pending', 'running') AND cancelled_at IS NULL;
"""

RLS = (
    "ALTER TABLE pov_runs ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE pov_runs FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY tenant_isolation ON pov_runs USING ({TENANT_POLICY_PREDICATE}) "
    f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
)


def upgrade() -> None:
    op.execute(SCHEMA)
    for statement in RLS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS pov_runs")
