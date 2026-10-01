"""Direct Microsoft response: integration kind ``microsoft``, ledger ownership, pinning, checkpoints and verification.

* ``integrations.kind`` accepts ``microsoft``; a tenant has at most one
  Microsoft integration (enabled or not).
* ``response_actions`` gains:

  - ``execution_owner`` (``workflow`` | ``scheduler``): who executes an
    approved row. Rollbacks are always the scheduler's (existing rollback
    rows are moved to it);
  - ``integration_id``: the integration a connector used, pinned for
    re-runs, retries and rollbacks (``ON DELETE SET NULL``: a pinned row of a
    deleted integration fails visibly instead of using another one);
  - ``external_ref`` (at most 64 KiB): the connector's checkpointed progress;
  - ``attempts`` and ``lease_until``: execution attempts and the scheduler's
    lease on a background row;
  - ``verification`` (``pending`` | ``verified`` | ``failed`` |
    ``inconclusive``, only on ``succeeded`` rows), ``verification_detail``
    (at most 16 KiB), ``verify_after``, ``verify_deadline``, ``verified_at``
    and ``verify_attempts``.

* Indexes for the verification job, the background executor, stranded
  approvals and rollback lookups; a unique index allows at most one live
  rollback (proposed, awaiting approval, approved, executing or succeeded)
  per original action.

No new table: RLS and the runtime grants are unchanged. Downgrading fails
while a Microsoft integration exists (delete it first).

Locking: the migration transaction only changes the catalog (the new
columns have constant defaults and no inline CHECK, and every constraint on
``response_actions`` is added ``NOT VALID``), so its ``ACCESS EXCLUSIVE``
lock is held for moments, not for table scans. After it commits, outside
a transaction like 0003: existing rollback rows move to the scheduler, the
constraints are validated (``SHARE UPDATE EXCLUSIVE``: reads and writes go
on) and the ``response_actions`` indexes are built ``CONCURRENTLY`` (an
invalid index left by an interrupted build is dropped and rebuilt).

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_KINDS = ("slack", "teams", "email", "webhook", "jira", "servicenow")
NEW_KINDS = OLD_KINDS + ("microsoft",)


def _kind_constraint_sql(kinds: Sequence[str]) -> str:
    # kinds only ever come from the constants above, never from input.
    listed = ", ".join(f"'{k}'" for k in kinds)
    return f"ALTER TABLE integrations ADD CONSTRAINT integrations_kind_check CHECK (kind IN ({listed}))"


# Catalog changes only (run in the migration transaction): no statement here scans response_actions.
UPGRADE = r"""
CREATE UNIQUE INDEX ux_integrations_microsoft ON integrations (tenant_id) WHERE kind = 'microsoft';

ALTER TABLE response_actions
    ADD COLUMN execution_owner TEXT NOT NULL DEFAULT 'workflow',
    ADD COLUMN integration_id UUID,
    ADD COLUMN external_ref JSONB,
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN lease_until TIMESTAMPTZ,
    ADD COLUMN verification TEXT,
    ADD COLUMN verification_detail JSONB,
    ADD COLUMN verify_after TIMESTAMPTZ,
    ADD COLUMN verify_deadline TIMESTAMPTZ,
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN verify_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_execution_owner_check
        CHECK (execution_owner IN ('workflow', 'scheduler')) NOT VALID,
    ADD CONSTRAINT response_actions_external_ref_check
        CHECK (external_ref IS NULL OR (jsonb_typeof(external_ref) = 'object'
               AND pg_column_size(external_ref) <= 65536)) NOT VALID,
    ADD CONSTRAINT response_actions_attempts_check CHECK (attempts >= 0) NOT VALID,
    ADD CONSTRAINT response_actions_verification_check
        CHECK (verification IN ('pending', 'verified', 'failed', 'inconclusive')) NOT VALID,
    ADD CONSTRAINT response_actions_verification_detail_check
        CHECK (verification_detail IS NULL OR (jsonb_typeof(verification_detail) = 'object'
               AND pg_column_size(verification_detail) <= 16384)) NOT VALID,
    ADD CONSTRAINT response_actions_verify_attempts_check CHECK (verify_attempts >= 0) NOT VALID,
    ADD CONSTRAINT response_actions_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE SET NULL (integration_id) NOT VALID,
    ADD CONSTRAINT response_actions_verification_on_success
        CHECK (verification IS NULL OR status = 'succeeded') NOT VALID,
    ADD CONSTRAINT response_actions_verification_schedule CHECK (verification IS DISTINCT FROM 'pending'
        OR (verify_after IS NOT NULL AND verify_deadline IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT response_actions_rollback_not_self CHECK (rollback_of IS DISTINCT FROM id) NOT VALID,
    ADD CONSTRAINT response_actions_rollback_owner
        CHECK (rollback_of IS NULL OR execution_owner = 'scheduler') NOT VALID;
"""

# Existing rollback rows belong to the scheduler (before rollback_owner is validated). Outside the migration
# transaction the RLS bypass of env.py is gone, so it is set for this session (the migration's own connection,
# disposed afterwards) first.
MOVE_ROLLBACKS = (
    "SELECT set_config('app.bypass_rls', 'on', false)",
    "UPDATE response_actions SET execution_owner = 'scheduler' "
    "WHERE rollback_of IS NOT NULL AND execution_owner <> 'scheduler'",
)

# Validated after the catalog change committed (SHARE UPDATE EXCLUSIVE: reads and writes continue).
CONSTRAINTS = (
    "response_actions_execution_owner_check",
    "response_actions_external_ref_check",
    "response_actions_attempts_check",
    "response_actions_verification_check",
    "response_actions_verification_detail_check",
    "response_actions_verify_attempts_check",
    "response_actions_integration_fk",
    "response_actions_verification_on_success",
    "response_actions_verification_schedule",
    "response_actions_rollback_not_self",
    "response_actions_rollback_owner",
)

# (name, UNIQUE?, definition): built CONCURRENTLY after the catalog change committed.
INDEXES = (
    ("ix_response_actions_verify_due", False, "response_actions (verify_after) WHERE verification = 'pending'"),
    (
        "ix_response_actions_background", False,
        "response_actions (lease_until NULLS FIRST) "
        "WHERE execution_owner = 'scheduler' AND status IN ('approved', 'executing')",
    ),
    (
        "ix_response_actions_approved_workflow", False,
        "response_actions (tenant_id, approved_at) WHERE status = 'approved' AND execution_owner = 'workflow'",
    ),
    ("ix_response_actions_rollback_of", False, "response_actions (tenant_id, rollback_of) WHERE rollback_of IS NOT NULL"),
    (
        "ux_response_actions_live_rollback", True,
        "response_actions (tenant_id, rollback_of) WHERE rollback_of IS NOT NULL "
        "AND status IN ('proposed', 'awaiting_approval', 'approved', 'executing', 'succeeded')",
    ),
)

DOWNGRADE = r"""
ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_rollback_owner,
    DROP CONSTRAINT IF EXISTS response_actions_rollback_not_self,
    DROP CONSTRAINT IF EXISTS response_actions_verification_schedule,
    DROP CONSTRAINT IF EXISTS response_actions_verification_on_success,
    DROP CONSTRAINT IF EXISTS response_actions_integration_fk,
    DROP CONSTRAINT IF EXISTS response_actions_verify_attempts_check,
    DROP CONSTRAINT IF EXISTS response_actions_verification_detail_check,
    DROP CONSTRAINT IF EXISTS response_actions_verification_check,
    DROP CONSTRAINT IF EXISTS response_actions_attempts_check,
    DROP CONSTRAINT IF EXISTS response_actions_external_ref_check,
    DROP CONSTRAINT IF EXISTS response_actions_execution_owner_check;
ALTER TABLE response_actions
    DROP COLUMN IF EXISTS verify_attempts,
    DROP COLUMN IF EXISTS verified_at,
    DROP COLUMN IF EXISTS verify_deadline,
    DROP COLUMN IF EXISTS verify_after,
    DROP COLUMN IF EXISTS verification_detail,
    DROP COLUMN IF EXISTS verification,
    DROP COLUMN IF EXISTS lease_until,
    DROP COLUMN IF EXISTS attempts,
    DROP COLUMN IF EXISTS external_ref,
    DROP COLUMN IF EXISTS integration_id,
    DROP COLUMN IF EXISTS execution_owner;
DROP INDEX IF EXISTS ux_integrations_microsoft;
"""

REFUSE_DOWNGRADE = r"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM integrations WHERE kind = 'microsoft') THEN
        RAISE EXCEPTION 'cannot downgrade below 0009 while Microsoft integrations exist (delete them first)'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
END
$$;
"""


def _drop_if_invalid_sql(name: str) -> str:
    # name only ever comes from INDEXES above, never from input.
    template = (
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "WHERE c.relname = '{name}' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX {name}'; END IF; END $$"
    )
    return template.replace("{name}", name)


def upgrade() -> None:
    op.execute("ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_kind_check")
    op.execute(_kind_constraint_sql(NEW_KINDS))
    op.execute(UPGRADE)
    # Everything that scans response_actions runs after the catalog change committed (module docstring).
    with op.get_context().autocommit_block():
        for statement in MOVE_ROLLBACKS:
            op.execute(statement)
        for name in CONSTRAINTS:
            op.execute(f"ALTER TABLE response_actions VALIDATE CONSTRAINT {name}")
        for name, unique, definition in INDEXES:
            # A failed concurrent build leaves an INVALID index behind; drop it so the retry rebuilds.
            op.execute(_drop_if_invalid_sql(name))
            op.execute(f"CREATE {'UNIQUE ' if unique else ''}INDEX CONCURRENTLY IF NOT EXISTS {name} ON {definition}")


def downgrade() -> None:
    # Migrations run with the RLS bypass on (env.py), so this check sees every tenant's rows.
    op.execute(REFUSE_DOWNGRADE)
    with op.get_context().autocommit_block():
        for name, _, _ in reversed(INDEXES):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
    op.execute(DOWNGRADE)
    op.execute("ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_kind_check")
    op.execute(_kind_constraint_sql(OLD_KINDS))
