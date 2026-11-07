"""MSSP organisations, their members, and delegated-access grants into customer tenants.

* ``organisations``: a tenant that is an MSSP organisation. Its key is the
  organisation's own (home) tenant id: its staff accounts are users of that
  tenant and its audit chain is that tenant's chain.
* ``organisation_members``: the staff accounts of the home tenant that may act
  under the organisation's grants.
* ``tenant_grants``: one customer tenant opened to one organisation (or to one
  member of it, ``user_id``) with a role, a reason and an expiry. Rows belong
  to the customer tenant (``tenant_id``): only the customer can create or
  revoke them. The organisation reads its own grants through a second,
  read-only policy (``org_read``); nobody else sees them.

Erasing an organisation's home tenant removes its grants in every customer
tenant (``ON DELETE CASCADE``); the audit chains keep their history.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-07
"""

from __future__ import annotations

from typing import List, Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = ("organisations", "organisation_members", "tenant_grants")

SCHEMA = r"""
CREATE TABLE organisations (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants (id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organisation_members (
    tenant_id TEXT NOT NULL REFERENCES organisations (tenant_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    added_by TEXT CHECK (length(added_by) <= 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT organisation_members_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE tenant_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    organisation_id TEXT NOT NULL REFERENCES organisations (tenant_id) ON DELETE CASCADE,
    user_id UUID,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT CHECK (length(revoked_by) <= 200),
    CONSTRAINT tenant_grants_not_own_tenant CHECK (organisation_id <> tenant_id),
    CONSTRAINT tenant_grants_time_bounded
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days'),
    CONSTRAINT tenant_grants_member_fk FOREIGN KEY (organisation_id, user_id)
        REFERENCES organisation_members (tenant_id, user_id) ON DELETE CASCADE
);
CREATE INDEX ix_tenant_grants_tenant ON tenant_grants (tenant_id, created_at DESC);
CREATE INDEX ix_tenant_grants_organisation ON tenant_grants (organisation_id, tenant_id) WHERE revoked_at IS NULL;
"""

ORG_READ_PREDICATE = TENANT_POLICY_PREDICATE.replace("tenant_id =", "organisation_id =", 1)


def _rls_sql(table: str) -> List[str]:
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY tenant_isolation ON {table} USING ({TENANT_POLICY_PREDICATE}) "
        f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
    ]


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in TABLES:
        for stmt in _rls_sql(table):
            op.execute(stmt)
    # Permissive policies are OR-ed per command: the organisation can SELECT its grants, never write them.
    op.execute(f"CREATE POLICY org_read ON tenant_grants FOR SELECT USING ({ORG_READ_PREDICATE})")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS tenant_grants, organisation_members, organisations CASCADE")
