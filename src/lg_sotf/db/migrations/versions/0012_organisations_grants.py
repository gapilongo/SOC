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

A grant row is the customer's record of who could act in it, so nothing the
organisation does removes it: ``organisation_id`` and ``user_id`` carry no
foreign key (removing a member, deleting a staff account or erasing the
organisation leaves the row; membership is checked when the grant is used,
and an unknown organisation is accepted like a known one, so the customer
learns nothing about which organisations exist). A trigger lets an update do
one thing only: revoke a live grant. Runtime writes to ``organisations`` go
through ``lgsotf_save_organisation`` (platform admins). ``integrations`` and
``suppression_rules`` gain ``grant_id``: the grant a row was written under.

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
    organisation_id TEXT NOT NULL CHECK (organisation_id ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
    user_id UUID,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    allow_api_keys BOOLEAN NOT NULL DEFAULT false,
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT CHECK (length(revoked_by) <= 200),
    CONSTRAINT tenant_grants_not_own_tenant CHECK (organisation_id <> tenant_id),
    CONSTRAINT tenant_grants_time_bounded
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days')
);
CREATE INDEX ix_tenant_grants_tenant ON tenant_grants (tenant_id, created_at DESC);
CREATE INDEX ix_tenant_grants_organisation ON tenant_grants (organisation_id, tenant_id) WHERE revoked_at IS NULL;

CREATE FUNCTION tenant_grants_only_revoke() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND (to_jsonb(NEW) - 'revoked_at' - 'revoked_by') = (to_jsonb(OLD) - 'revoked_at' - 'revoked_by') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a tenant grant can only be revoked, once' USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER tenant_grants_only_revoke BEFORE UPDATE ON tenant_grants
    FOR EACH ROW EXECUTE FUNCTION tenant_grants_only_revoke();

ALTER TABLE integrations ADD COLUMN grant_id UUID;
ALTER TABLE suppression_rules ADD COLUMN grant_id UUID;

CREATE FUNCTION lgsotf_save_organisation(p_tenant_id TEXT, p_name TEXT) RETURNS SETOF public.organisations
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN QUERY
    WITH saved AS (
        INSERT INTO public.organisations (tenant_id, name) VALUES (p_tenant_id, p_name)
        ON CONFLICT (tenant_id) DO UPDATE SET name = EXCLUDED.name
        RETURNING *
    )
    SELECT * FROM saved;
END
$$;
REVOKE ALL ON FUNCTION lgsotf_save_organisation(TEXT, TEXT) FROM PUBLIC;
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
    op.execute("DROP FUNCTION IF EXISTS lgsotf_save_organisation(TEXT, TEXT)")
    op.execute("ALTER TABLE suppression_rules DROP COLUMN IF EXISTS grant_id")
    op.execute("ALTER TABLE integrations DROP COLUMN IF EXISTS grant_id")
    op.execute("DROP TABLE IF EXISTS tenant_grants, organisation_members, organisations CASCADE")
    op.execute("DROP FUNCTION IF EXISTS tenant_grants_only_revoke()")
