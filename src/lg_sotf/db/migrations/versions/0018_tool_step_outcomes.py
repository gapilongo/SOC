"""Tool outcomes in the investigation trace: ``investigation_steps.outcome`` gains ``empty`` and ``failed`` (AI-E2.1).

A tool call that goes through the tool registry (``lg_sotf.tools.registry``) is stored with the outcome its
result has: ``success`` (rows came back), ``empty`` (the query ran and matched nothing) or ``failed`` (it was
refused, timed out, went over a cap or did not get an answer). Before, every tool call that returned was
stored as ``success``, so a failed lookup could not be told from one that found something.

Only the CHECK constraint changes; no row is rewritten on upgrade. Rows stored before keep ``success``.
The downgrade maps the two new values back to what the older code would have written (``success`` for
``empty``, ``error`` for ``failed``) before it restores the narrower constraint.

Revision ID: 0018
Revises: 0020
Create Date: 2026-11-14
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_OUTCOMES = ("success", "refusal", "invalid_output", "error")
NEW_OUTCOMES = OLD_OUTCOMES + ("empty", "failed")
CONSTRAINT = "investigation_steps_outcome_check"


def _constraint_sql(outcomes: Sequence[str]) -> str:
    # outcomes only ever come from the constants above, never from input.
    listed = ", ".join(f"'{o}'" for o in outcomes)
    return f"ALTER TABLE investigation_steps ADD CONSTRAINT {CONSTRAINT} CHECK (outcome IN ({listed}))"


def upgrade() -> None:
    op.execute(f"ALTER TABLE investigation_steps DROP CONSTRAINT IF EXISTS {CONSTRAINT}")
    op.execute(_constraint_sql(NEW_OUTCOMES))


def downgrade() -> None:
    op.execute(f"ALTER TABLE investigation_steps DROP CONSTRAINT IF EXISTS {CONSTRAINT}")
    # Every tenant's rows (the table has forced RLS); local to the migration transaction.
    op.execute("SELECT set_config('app.bypass_rls', 'on', true)")
    op.execute("UPDATE investigation_steps SET outcome = 'success' WHERE outcome = 'empty'")
    op.execute("UPDATE investigation_steps SET outcome = 'error' WHERE outcome = 'failed'")
    op.execute(_constraint_sql(OLD_OUTCOMES))
