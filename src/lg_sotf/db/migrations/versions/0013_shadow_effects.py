"""Shadow mode sink: ``shadow_effects``, what a shadow run would have done, one row per diverted call.

A shadow run (``lg_sotf.core.shadow``) runs a candidate pipeline on a real
alert with every egress boundary diverted. Each diverted call is a row: the
run (``run_id``, always ``shadow/...``), its position (``seq``), the
boundary (``outbox``, ``escalation``, ``response_plan``...), the operation
(the function's qualified name), whether it was ``sunk`` (recorded instead
of done) or ``refused``, and a small ``detail`` (event types, action types
and targets; never message bodies or credentials).

Rows go with their alert (``ON DELETE CASCADE``), so they follow the
tenant's ``alerts_days`` retention and tenant erasure. Tenant-scoped with
forced RLS like every tenant table; the runtime role may read and insert,
never update or delete. No API endpoint reads the table.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-08
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = r"""
CREATE TABLE shadow_effects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    run_id TEXT NOT NULL CHECK (run_id LIKE 'shadow/%' AND length(run_id) <= 200),
    seq INTEGER NOT NULL CHECK (seq >= 0),
    boundary TEXT NOT NULL CHECK (length(boundary) BETWEEN 1 AND 64),
    operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 200),
    outcome TEXT NOT NULL CHECK (outcome IN ('sunk', 'refused')),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(detail) <= 8192),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT shadow_effects_run_seq_key UNIQUE (tenant_id, alert_id, run_id, seq),
    CONSTRAINT shadow_effects_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
"""

RLS = (
    "ALTER TABLE shadow_effects ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE shadow_effects FORCE ROW LEVEL SECURITY",
    f"CREATE POLICY tenant_isolation ON shadow_effects USING ({TENANT_POLICY_PREDICATE}) "
    f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
)


def upgrade() -> None:
    op.execute(SCHEMA)
    for statement in RLS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS shadow_effects")
