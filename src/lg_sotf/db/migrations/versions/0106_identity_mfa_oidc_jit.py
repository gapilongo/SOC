"""TOTP MFA for local accounts and OIDC just-in-time provisioning.

* ``user_mfa``: one row per user with MFA enrolled or enrolling. The TOTP
  secret is stored encrypted (``SecretBox``, bound to tenant and user);
  recovery codes only as keyed hashes; ``last_used_step`` makes every TOTP
  code single-use. Tenant-owned with the same RLS policy as every other
  table; rows go with their user.
* ``users.oidc_subject``: the IdP ``sub`` of an account created (or linked)
  by OIDC just-in-time provisioning; unique per tenant.

Revision ID: 0106
Revises: 0003
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0106"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = r"""
ALTER TABLE users ADD COLUMN oidc_subject TEXT
    CONSTRAINT users_oidc_subject_format CHECK (length(oidc_subject) BETWEEN 1 AND 255);
CREATE UNIQUE INDEX ux_users_oidc_subject ON users (tenant_id, oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE user_mfa (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    user_id UUID NOT NULL,
    secret_ciphertext TEXT,
    pending_secret_ciphertext TEXT,
    pending_created_at TIMESTAMPTZ,
    enabled_at TIMESTAMPTZ,
    last_used_step BIGINT CHECK (last_used_step >= 0),
    recovery_code_hashes TEXT[] NOT NULL DEFAULT '{}'::text[]
        CHECK (cardinality(recovery_code_hashes) <= 20),
    recovery_codes_generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT user_mfa_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_mfa_enabled_has_secret CHECK (enabled_at IS NULL OR secret_ciphertext IS NOT NULL),
    CONSTRAINT user_mfa_pending_consistent CHECK ((pending_secret_ciphertext IS NULL) = (pending_created_at IS NULL))
);

CREATE TRIGGER user_mfa_touch_updated_at BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION lgsotf_touch_updated_at();
"""


def upgrade() -> None:
    op.execute(SCHEMA)
    op.execute("ALTER TABLE user_mfa ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE user_mfa FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON user_mfa USING ({TENANT_POLICY_PREDICATE}) "
        f"WITH CHECK ({TENANT_POLICY_PREDICATE})"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_mfa")
    op.execute("DROP INDEX IF EXISTS ux_users_oidc_subject")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS oidc_subject")
