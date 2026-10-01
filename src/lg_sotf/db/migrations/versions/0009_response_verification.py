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
on) and the ``response_actions`` indexes are built ``CONCURRENTLY``.

Re-running: a failure after that commit (a constraint that does not
validate, two live rollbacks of one action, a killed job) leaves the new
columns in place with 0008 still stamped. Every step is therefore
idempotent: indexes and columns are created ``IF NOT EXISTS``, each
constraint is dropped ``IF EXISTS`` and added ``NOT VALID`` again, and an
invalid index left by an interrupted concurrent build is dropped (within
the migration ``lock_timeout``) and rebuilt. Fix the cause and upgrade
again. env.py's transaction-level migration lock ends with that first
commit, so a session-level hold of the same advisory lock, taken just
before it, keeps another ``lg-sotf migrate`` waiting until 0009 is stamped;
the transaction alembic opens after the autocommit part gets env.py's
setup again (``lock_timeout``, RLS bypass, migration lock).

The downgrade is one transaction under env.py's ``lock_timeout``: its
``ALTER TABLE`` needs ``ACCESS EXCLUSIVE`` anyway, so the indexes are
dropped in it too, and it either completes or changes nothing. It also
removes a half-applied upgrade (``alembic stamp 0009`` first).

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-30
"""

from __future__ import annotations

import contextlib
from typing import Sequence, Union

from alembic import op

from lg_sotf.db import locks
from lg_sotf.db.migrate import MIGRATION_LOCK_TIMEOUT, migration_transaction_setup

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
CREATE UNIQUE INDEX IF NOT EXISTS ux_integrations_microsoft ON integrations (tenant_id) WHERE kind = 'microsoft';

ALTER TABLE response_actions
    ADD COLUMN IF NOT EXISTS execution_owner TEXT NOT NULL DEFAULT 'workflow',
    ADD COLUMN IF NOT EXISTS integration_id UUID,
    ADD COLUMN IF NOT EXISTS external_ref JSONB,
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification TEXT,
    ADD COLUMN IF NOT EXISTS verification_detail JSONB,
    ADD COLUMN IF NOT EXISTS verify_after TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verify_deadline TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verify_attempts INTEGER NOT NULL DEFAULT 0;
"""

# (name, definition): added NOT VALID in the migration transaction, validated after it committed
# (SHARE UPDATE EXCLUSIVE: reads and writes continue).
CONSTRAINTS = (
    ("response_actions_execution_owner_check", "CHECK (execution_owner IN ('workflow', 'scheduler'))"),
    (
        "response_actions_external_ref_check",
        "CHECK (external_ref IS NULL OR (jsonb_typeof(external_ref) = 'object'\n"
        "        AND pg_column_size(external_ref) <= 65536))",
    ),
    ("response_actions_attempts_check", "CHECK (attempts >= 0)"),
    ("response_actions_verification_check", "CHECK (verification IN ('pending', 'verified', 'failed', 'inconclusive'))"),
    (
        "response_actions_verification_detail_check",
        "CHECK (verification_detail IS NULL OR (jsonb_typeof(verification_detail) = 'object'\n"
        "        AND pg_column_size(verification_detail) <= 16384))",
    ),
    ("response_actions_verify_attempts_check", "CHECK (verify_attempts >= 0)"),
    (
        "response_actions_integration_fk",
        "FOREIGN KEY (tenant_id, integration_id)\n"
        "        REFERENCES integrations (tenant_id, id) ON DELETE SET NULL (integration_id)",
    ),
    ("response_actions_verification_on_success", "CHECK (verification IS NULL OR status = 'succeeded')"),
    (
        "response_actions_verification_schedule",
        "CHECK (verification IS DISTINCT FROM 'pending'\n"
        "        OR (verify_after IS NOT NULL AND verify_deadline IS NOT NULL))",
    ),
    ("response_actions_rollback_not_self", "CHECK (rollback_of IS DISTINCT FROM id)"),
    ("response_actions_rollback_owner", "CHECK (rollback_of IS NULL OR execution_owner = 'scheduler')"),
)


def _drop_constraints_sql() -> str:
    # names only ever come from CONSTRAINTS above, never from input.
    drops = ",\n    ".join(f"DROP CONSTRAINT IF EXISTS {name}" for name, _ in reversed(CONSTRAINTS))
    return f"ALTER TABLE response_actions\n    {drops}"


def _add_constraints_sql() -> str:
    adds = ",\n    ".join(f"ADD CONSTRAINT {name}\n        {definition} NOT VALID" for name, definition in CONSTRAINTS)
    return f"ALTER TABLE response_actions\n    {adds}"


# Existing rollback rows belong to the scheduler (before rollback_owner is validated). Outside the migration
# transaction the RLS bypass of env.py is gone, so it is set for this session (the migration's own connection,
# disposed afterwards) first.
MOVE_ROLLBACKS = (
    "SELECT set_config('app.bypass_rls', 'on', false)",
    "UPDATE response_actions SET execution_owner = 'scheduler' "
    "WHERE rollback_of IS NOT NULL AND execution_owner <> 'scheduler'",
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

# Session level: held across the autocommit part, where env.py's transaction-level lock is gone.
SESSION_LOCK = f"SELECT pg_advisory_lock({locks.MIGRATIONS}, 0)"
SESSION_UNLOCK = f"SELECT pg_advisory_unlock({locks.MIGRATIONS}, 0)"

DROP_COLUMNS = r"""
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
    # name only ever comes from INDEXES above, never from input. A plain DROP INDEX takes ACCESS EXCLUSIVE:
    # lock_timeout keeps it from queueing the table's readers and writers behind a long transaction.
    template = (
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "WHERE c.relname = '{name}' AND NOT i.indisvalid) THEN "
        "PERFORM set_config('lock_timeout', '{timeout}', true); EXECUTE 'DROP INDEX {name}'; END IF; END $$"
    )
    return template.replace("{name}", name).replace("{timeout}", MIGRATION_LOCK_TIMEOUT)


def upgrade() -> None:
    op.execute("ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_kind_check")
    op.execute(_kind_constraint_sql(NEW_KINDS))
    op.execute(UPGRADE)
    op.execute(_drop_constraints_sql())
    op.execute(_add_constraints_sql())
    # The last statement before the autocommit block commits: this hold outlives that commit (module docstring).
    op.execute(SESSION_LOCK)
    try:
        # Everything that scans response_actions runs after the catalog change committed (module docstring).
        with op.get_context().autocommit_block():
            for statement in MOVE_ROLLBACKS:
                op.execute(statement)
            for name, _ in CONSTRAINTS:
                op.execute(f"ALTER TABLE response_actions VALIDATE CONSTRAINT {name}")
            for name, unique, definition in INDEXES:
                # A failed concurrent build leaves an INVALID index behind; drop it so the retry rebuilds.
                op.execute(_drop_if_invalid_sql(name))
                op.execute(f"CREATE {'UNIQUE ' if unique else ''}INDEX CONCURRENTLY IF NOT EXISTS {name} ON {definition}")
    except Exception:
        # Closing the connection releases the hold too; this covers a connection the caller keeps.
        with contextlib.suppress(Exception):
            op.execute(SESSION_UNLOCK)
        raise
    # Alembic stamps 0009 (and runs any later revision) in the transaction it opened after the block: give it
    # env.py's setup, including the transaction-level lock, before the session-level hold goes.
    for statement in migration_transaction_setup():
        op.execute(statement)
    op.execute(SESSION_UNLOCK)


def downgrade() -> None:
    # One transaction (module docstring). Migrations run with the RLS bypass on (env.py), so the check sees
    # every tenant's rows.
    op.execute(REFUSE_DOWNGRADE)
    op.execute(f"DROP INDEX IF EXISTS {', '.join(name for name, _, _ in reversed(INDEXES))}")
    op.execute(_drop_constraints_sql())
    op.execute(DROP_COLUMNS)
    op.execute("DROP INDEX IF EXISTS ux_integrations_microsoft")
    op.execute("ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_kind_check")
    op.execute(_kind_constraint_sql(OLD_KINDS))
