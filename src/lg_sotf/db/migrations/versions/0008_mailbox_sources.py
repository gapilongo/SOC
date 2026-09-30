"""Mailbox source types for user-reported phishing: ``m365_mailbox`` and ``imap``.

Widens the ``sources.type`` check constraint; no table changes. Downgrading
fails while sources of the new types exist (delete them first).

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_TYPES = ("splunk", "qradar", "sentinel", "wazuh", "crowdstrike", "guardduty", "webhook", "file")
NEW_TYPES = OLD_TYPES + ("m365_mailbox", "imap")


def _constraint_sql(types: Sequence[str]) -> str:
    # types only ever come from the constants above, never from input.
    listed = ", ".join(f"'{t}'" for t in types)
    return f"ALTER TABLE sources ADD CONSTRAINT sources_type_check CHECK (type IN ({listed}))"


def upgrade() -> None:
    op.execute("ALTER TABLE sources DROP CONSTRAINT IF EXISTS sources_type_check")
    op.execute(_constraint_sql(NEW_TYPES))


def downgrade() -> None:
    op.execute("ALTER TABLE sources DROP CONSTRAINT IF EXISTS sources_type_check")
    op.execute(_constraint_sql(OLD_TYPES))
