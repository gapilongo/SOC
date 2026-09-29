"""Indexes for the dashboard and the filtered alert list at production volume.

* ``ix_alerts_status_severity`` / ``ix_alerts_disposition``: the alert list
  orders by ``(ingested_at, id)``; filters without a composite index (status
  plus severity, disposition) otherwise walk ``ix_alerts_ingested`` through
  the tenant's whole history when few rows match.
* ``ix_alerts_tenant_closed``: MTTR over a window (``closed_at``) per tenant;
  ``ix_alerts_closed_at`` has no tenant and serves retention.
* ``ix_escalations_claimed``: MTTA over a window (``claimed_at``).
* ``ix_workflow_runs_active``: the dashboard counts only runs that have not
  finished, a small set, instead of every run the tenant ever had.

Created ``CONCURRENTLY`` (outside a transaction) so an upgrade does not block
ingestion on a large database.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEXES = (
    ("ix_alerts_status_severity", "alerts (tenant_id, status, severity, ingested_at DESC, id DESC)"),
    ("ix_alerts_disposition", "alerts (tenant_id, disposition, ingested_at DESC, id DESC)"),
    ("ix_alerts_tenant_closed", "alerts (tenant_id, closed_at) WHERE status = 'closed'"),
    ("ix_escalations_claimed", "escalations (tenant_id, claimed_at) WHERE claimed_at IS NOT NULL"),
    (
        "ix_workflow_runs_active",
        "workflow_runs (tenant_id, status) WHERE status NOT IN ('completed', 'dead_lettered')",
    ),
)


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for name, definition in INDEXES:
            # A failed concurrent build leaves an INVALID index behind; drop it so the retry rebuilds.
            op.execute(
                f"""
                DO $$ BEGIN
                    IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                               WHERE c.relname = '{name}' AND NOT i.indisvalid) THEN
                        EXECUTE 'DROP INDEX {name}';
                    END IF;
                END $$
                """  # noqa: S608 - fixed identifiers
            )
            op.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {definition}")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for name, _ in reversed(INDEXES):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
