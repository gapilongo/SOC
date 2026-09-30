"""Integrations hub: notification channels, ticketing, the delivery outbox and linked tickets.

* ``integrations``: one row per configured channel or ticketing system of a
  tenant (``slack``, ``teams``, ``email``, ``webhook``, ``jira``,
  ``servicenow``). ``config`` is non-secret JSON; credentials live in
  ``secret_ciphertext`` (Fernet, bound to the tenant and integration id).
* ``notification_outbox``: one row per (event, integration), written in the
  same transaction as the state change that raised the event and delivered by
  the scheduler (``FOR UPDATE SKIP LOCKED`` claims, exponential backoff,
  ``dead`` after the last attempt). ``dedupe_key`` makes enqueueing
  idempotent for workflow nodes that run again on resume.
* ``external_tickets``: tickets opened in Jira/ServiceNow for an alert or an
  escalation (at most one per escalation and integration), with the external
  status the scheduler last saw.

Revision ID: 0102
Revises: 0003
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import List, Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0102"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = ("integrations", "notification_outbox", "external_tickets")
UPDATED_AT_TABLES = TABLES

SCHEMA = r"""
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    kind TEXT NOT NULL CHECK (kind IN ('slack', 'teams', 'email', 'webhook', 'jira', 'servicenow')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object'),
    secret_ciphertext TEXT,
    events TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(events) <= 32),
    min_severity TEXT NOT NULL DEFAULT 'low' CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT integrations_tenant_name_key UNIQUE (tenant_id, name),
    CONSTRAINT integrations_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT integrations_created_by_fk FOREIGN KEY (tenant_id, created_by)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (created_by)
);

CREATE TABLE notification_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    integration_id UUID NOT NULL,
    event_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type ~ '^[a-z][a-z_.]{0,63}$'),
    operation TEXT NOT NULL CHECK (operation IN ('notify', 'ticket_create', 'ticket_update', 'test')),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 300),
    alert_id TEXT,
    escalation_id TEXT,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT CHECK (length(last_error) <= 1000),
    result JSONB,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_outbox_dedupe_key UNIQUE (tenant_id, integration_id, dedupe_key),
    CONSTRAINT notification_outbox_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ix_notification_outbox_due ON notification_outbox (next_attempt_at)
    WHERE status IN ('pending', 'failed');
CREATE INDEX ix_notification_outbox_integration ON notification_outbox (tenant_id, integration_id, created_at DESC);
CREATE INDEX ix_notification_outbox_finished ON notification_outbox (updated_at)
    WHERE status IN ('sent', 'dead');

CREATE TABLE external_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    integration_id UUID NOT NULL,
    alert_id TEXT NOT NULL,
    escalation_id TEXT,
    action_id UUID,
    system TEXT NOT NULL CHECK (system IN ('jira', 'servicenow')),
    external_key TEXT NOT NULL CHECK (length(external_key) BETWEEN 1 AND 200),
    external_id TEXT CHECK (length(external_id) <= 200),
    external_url TEXT CHECK (length(external_url) <= 2048),
    external_status TEXT CHECK (length(external_status) <= 200),
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_by TEXT CHECK (length(resolved_by) <= 200),
    last_synced_at TIMESTAMPTZ,
    sync_error TEXT CHECK (length(sync_error) <= 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT external_tickets_escalation_key UNIQUE (tenant_id, integration_id, escalation_id),
    CONSTRAINT external_tickets_external_key UNIQUE (tenant_id, integration_id, external_key),
    CONSTRAINT external_tickets_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT external_tickets_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT external_tickets_escalation_fk FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES escalations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ix_external_tickets_alert ON external_tickets (tenant_id, alert_id);
-- A ticket opened for an alert alone (the create_ticket response action) is reused for the alert.
CREATE UNIQUE INDEX ux_external_tickets_alert_only ON external_tickets (tenant_id, integration_id, alert_id)
    WHERE escalation_id IS NULL;
CREATE INDEX ix_external_tickets_escalation ON external_tickets (tenant_id, escalation_id);
CREATE INDEX ix_external_tickets_sync ON external_tickets (last_synced_at NULLS FIRST) WHERE NOT resolved;
"""


def _rls_sql(table: str) -> List[str]:
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY tenant_isolation ON {table} USING ({TENANT_POLICY_PREDICATE}) "
        f"WITH CHECK ({TENANT_POLICY_PREDICATE})",
    ]


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in UPDATED_AT_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_touch_updated_at BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION lgsotf_touch_updated_at()"
        )
    for table in TABLES:
        for stmt in _rls_sql(table):
            op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS external_tickets, notification_outbox, integrations CASCADE")
