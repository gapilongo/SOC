"""Break-glass sign-in alerts (SEC6.5).

A break-glass sign-in mails every platform admin of the install, in the
transaction that audits it. Two things were missing:

* ``notification_outbox.integration_id`` may now be NULL, for the new
  operation ``email`` only: a row mailed to ``payload.recipients`` through
  the install's SMTP. It belongs to no integration, so no tenant admin can
  disable or delete its channel. Every other operation still needs its
  integration.
* ``lgsotf_auth_platform_admins()``: tenant, id and email of the active
  platform admins of every tenant, for the runtime role, which cannot read
  other tenants itself (as the other ``lgsotf_auth_*`` lookups).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-14
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UPGRADE = r"""
ALTER TABLE notification_outbox ALTER COLUMN integration_id DROP NOT NULL;
ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_operation_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_operation_check
    CHECK (operation IN ('notify', 'ticket_create', 'ticket_update', 'test', 'email'));
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_integration_check
    CHECK ((integration_id IS NULL) = (operation = 'email'));

CREATE FUNCTION lgsotf_auth_platform_admins() RETURNS TABLE (tenant_id TEXT, id UUID, email TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY SELECT u.tenant_id, u.id, u.email FROM public.users u
                 WHERE u.is_platform_admin AND u.is_active ORDER BY u.tenant_id, u.email;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;
REVOKE ALL ON FUNCTION lgsotf_auth_platform_admins() FROM PUBLIC;
"""

DOWNGRADE = r"""
DROP FUNCTION IF EXISTS lgsotf_auth_platform_admins();
DELETE FROM notification_outbox WHERE integration_id IS NULL;
ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_integration_check;
ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_operation_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_operation_check
    CHECK (operation IN ('notify', 'ticket_create', 'ticket_update', 'test'));
ALTER TABLE notification_outbox ALTER COLUMN integration_id SET NOT NULL;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
