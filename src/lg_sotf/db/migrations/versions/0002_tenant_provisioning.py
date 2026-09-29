"""Tenant provisioning function for the runtime role.

The API/worker runtime role has no INSERT on ``tenants`` and cannot bypass
RLS. ``lgsotf_create_tenant`` lets it create exactly one new tenant row (id
and name; status and settings take their defaults) and nothing else; the
platform-admin check is the API's. An existing id returns no row.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CREATE_TENANT_FUNCTION = r"""
CREATE FUNCTION lgsotf_create_tenant(p_id TEXT, p_name TEXT) RETURNS SETOF public.tenants
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY
        WITH created AS (
            INSERT INTO public.tenants (id, name) VALUES (p_id, p_name)
            ON CONFLICT (id) DO NOTHING
            RETURNING *
        )
        SELECT * FROM created;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

REVOKE ALL ON FUNCTION lgsotf_create_tenant(TEXT, TEXT) FROM PUBLIC;
"""


def upgrade() -> None:
    op.execute(CREATE_TENANT_FUNCTION)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS lgsotf_create_tenant(TEXT, TEXT)")
