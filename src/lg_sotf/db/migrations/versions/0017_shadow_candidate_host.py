"""The candidate's LLM host on each shadow verdict row (AI-E1.5c, #315 review F6).

``lg-sotf shadow-run`` records where the candidate's LLM calls went (the
host only, never a key) beside each comparison, so a report always says
which endpoint received the tenant's alert data. Rows stored before have
no host (``NULL``: not recorded).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-08
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE shadow_verdicts ADD COLUMN candidate_host TEXT CHECK (length(candidate_host) <= 253)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE shadow_verdicts DROP COLUMN IF EXISTS candidate_host")
