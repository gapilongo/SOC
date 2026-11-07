"""``workflow_runs.graph_version``: the workflow graph a run's checkpointed thread started on.

The worker resumes a run on the graph it started on, so runs waiting for an
analyst drain on the previous graph after an upgrade (``core/graph.py``,
``GRAPH_BUILDERS``).

Expand only: a nullable column with no default is a catalog change (no table
scan or rewrite, the ``ACCESS EXCLUSIVE`` lock is held for moments), and the
previous release keeps working against it (its rows ignore the column and
leave it NULL). NULL means the run's thread, if any, was started by code
without graph versions, which always ran graph 1. No backfill, so no
statement here touches tenant rows: RLS, its policy and the runtime grants
(table level) are unchanged.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-07
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE workflow_runs ADD COLUMN IF NOT EXISTS graph_version INTEGER")


def downgrade() -> None:
    op.execute("ALTER TABLE workflow_runs DROP COLUMN IF EXISTS graph_version")
