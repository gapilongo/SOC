"""Initial multi-tenant schema.

Revision ID: 0001
Revises:
Create Date: 2026-09-28
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import List, Sequence, Union

from alembic import op

from lg_sotf.db.partitions import (
    TENANT_POLICY_PREDICATE,
    add_months,
    create_default_partition_sql,
    create_partition_sql,
    month_start,
)

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_OWNED_TABLES = (
    "users",
    "refresh_tokens",
    "api_keys",
    "sources",
    "alerts",
    "alert_events",
    "workflow_runs",
    "escalations",
    "analyst_feedback",
    "response_actions",
    "suppression_rules",
    "indicator_sightings",
    "llm_usage_daily",
    "audit_log",
)

UPDATED_AT_TABLES = (
    "tenants",
    "users",
    "sources",
    "alerts",
    "workflow_runs",
    "escalations",
    "response_actions",
    "suppression_rules",
    "llm_usage_daily",
)

PARTITIONED = ("alert_events", "audit_log")
INITIAL_PARTITION_MONTHS = 3

SCHEMA = r"""
CREATE FUNCTION lgsotf_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE tenants (
    id TEXT PRIMARY KEY CONSTRAINT tenants_id_format CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    settings JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS bypass gate. ``app.bypass_rls`` alone is settable by any session, so it
-- is honoured only for members of the role that owns the schema (migrate,
-- scheduler). The API/worker runtime role (grant_runtime_privileges) is not a
-- member and stays confined to its tenant even if it sets the GUC.
CREATE FUNCTION lgsotf_rls_bypass() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(current_setting('app.bypass_rls', true) = 'on', false)
       AND pg_catalog.pg_has_role(
               current_user,
               (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = 'public.tenants'::regclass),
               'MEMBER')
$$;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    email TEXT NOT NULL CONSTRAINT users_email_format
        CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320 AND position('@' IN email) > 1),
    password_hash TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_platform_admin BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    failed_logins INTEGER NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_tenant_email_key UNIQUE (tenant_id, email),
    CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id)
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL CONSTRAINT refresh_tokens_hash_format CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT refresh_tokens_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT refresh_tokens_replaced_by_fk FOREIGN KEY (tenant_id, replaced_by)
        REFERENCES refresh_tokens (tenant_id, id) ON DELETE SET NULL (replaced_by)
);
CREATE INDEX ix_refresh_tokens_user ON refresh_tokens (tenant_id, user_id);
CREATE INDEX ix_refresh_tokens_expires ON refresh_tokens (expires_at);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    prefix TEXT NOT NULL CHECK (length(prefix) BETWEEN 1 AND 16),
    key_hash TEXT NOT NULL CONSTRAINT api_keys_hash_format CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    scopes TEXT[] NOT NULL CONSTRAINT api_keys_scopes_valid
        CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['ingest', 'read', 'write']::text[]),
    created_by UUID,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash),
    CONSTRAINT api_keys_created_by_fk FOREIGN KEY (tenant_id, created_by)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (created_by)
);
CREATE INDEX ix_api_keys_tenant ON api_keys (tenant_id, created_at DESC);

-- Source ids are unique per tenant only, so one tenant's choice of id can
-- neither block nor reveal another tenant's source.
CREATE TABLE sources (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    id TEXT NOT NULL DEFAULT gen_random_uuid()::text
        CONSTRAINT sources_id_format CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    type TEXT NOT NULL CHECK (type IN ('splunk', 'qradar', 'sentinel', 'wazuh', 'crowdstrike', 'guardduty', 'webhook', 'file')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object'),
    secret_ciphertext TEXT,
    poll_interval_s INTEGER NOT NULL DEFAULT 60 CHECK (poll_interval_s BETWEEN 5 AND 86400),
    cursor JSONB,
    cursor_watermark TIMESTAMPTZ,
    last_polled_at TIMESTAMPTZ,
    next_poll_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_error TEXT,
    health TEXT NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown', 'healthy', 'degraded', 'failing')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT sources_tenant_name_key UNIQUE (tenant_id, name)
);
CREATE INDEX ix_sources_due ON sources (next_poll_at NULLS FIRST) WHERE enabled;

CREATE TABLE alerts (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    id TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    source_id TEXT NOT NULL,
    source_alert_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    category TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (
        status IN ('new', 'queued', 'processing', 'waiting_human', 'waiting_approval', 'closed', 'failed')
    ),
    disposition TEXT CHECK (disposition IN ('malicious', 'benign', 'inconclusive')),
    confidence DOUBLE PRECISION CHECK (confidence >= 0 AND confidence <= 100),
    threat_score DOUBLE PRECISION CHECK (threat_score >= 0 AND threat_score <= 100),
    priority SMALLINT CHECK (priority BETWEEN 1 AND 10),
    assigned_to UUID,
    occurred_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    normalized JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary) = 'object'),
    case_key TEXT,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT alerts_source_alert_key UNIQUE (tenant_id, source_id, source_alert_id),
    CONSTRAINT alerts_closed_has_closed_at CHECK (status <> 'closed' OR closed_at IS NOT NULL),
    CONSTRAINT alerts_assigned_to_fk FOREIGN KEY (tenant_id, assigned_to)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (assigned_to)
);
CREATE INDEX ix_alerts_ingested ON alerts (tenant_id, ingested_at DESC, id DESC);
CREATE INDEX ix_alerts_status ON alerts (tenant_id, status, ingested_at DESC, id DESC);
CREATE INDEX ix_alerts_severity ON alerts (tenant_id, severity, ingested_at DESC, id DESC);
CREATE INDEX ix_alerts_fingerprint ON alerts (tenant_id, fingerprint, ingested_at DESC);
CREATE INDEX ix_alerts_closed_at ON alerts (closed_at) WHERE status = 'closed';

CREATE TABLE alert_events (
    id BIGSERIAL,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    node TEXT,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL DEFAULT 'system' CHECK (actor_type IN ('system', 'user', 'agent')),
    actor_id TEXT,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, ts),
    CONSTRAINT alert_events_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
) PARTITION BY RANGE (ts);
CREATE INDEX ix_alert_events_alert ON alert_events (tenant_id, alert_id, ts, id);

CREATE TABLE workflow_runs (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'running', 'waiting_human', 'waiting_approval', 'completed', 'failed', 'dead_lettered')
    ),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    worker_id TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, alert_id),
    CONSTRAINT workflow_runs_thread_id_key UNIQUE (thread_id),
    CONSTRAINT workflow_runs_thread_id_format CHECK (thread_id = tenant_id || ':' || alert_id),
    CONSTRAINT workflow_runs_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ix_workflow_runs_status ON workflow_runs (tenant_id, status);
CREATE INDEX ix_workflow_runs_lease ON workflow_runs (lease_expires_at) WHERE status = 'running';
CREATE INDEX ix_workflow_runs_finished ON workflow_runs (completed_at)
    WHERE status IN ('completed', 'dead_lettered');

CREATE TABLE escalations (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'L1' CHECK (level IN ('L1', 'L2', 'L3')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'claimed', 'decided', 'expired', 'cancelled')),
    reason TEXT NOT NULL,
    priority SMALLINT NOT NULL DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    related_alert_ids TEXT[] NOT NULL DEFAULT '{}',
    assigned_to UUID,
    sla_deadline TIMESTAMPTZ,
    decision TEXT CHECK (decision IN ('true_positive', 'false_positive', 'benign_positive', 'needs_more_info')),
    decision_notes TEXT,
    approved_actions TEXT[] NOT NULL DEFAULT '{}',
    decided_by UUID,
    decided_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT escalations_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT escalations_decided_complete
        CHECK (status <> 'decided' OR (decision IS NOT NULL AND decided_at IS NOT NULL)),
    CONSTRAINT escalations_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT escalations_assigned_to_fk FOREIGN KEY (tenant_id, assigned_to)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (assigned_to),
    CONSTRAINT escalations_decided_by_fk FOREIGN KEY (tenant_id, decided_by)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (decided_by)
);
CREATE UNIQUE INDEX ux_escalations_active_per_alert ON escalations (tenant_id, alert_id)
    WHERE status IN ('open', 'claimed');
CREATE INDEX ix_escalations_alert ON escalations (tenant_id, alert_id);
CREATE INDEX ix_escalations_created ON escalations (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_escalations_status ON escalations (tenant_id, status, created_at DESC, id DESC);
CREATE INDEX ix_escalations_sla ON escalations (sla_deadline) WHERE status IN ('open', 'claimed');

CREATE TABLE analyst_feedback (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    escalation_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    user_id UUID,
    decision TEXT NOT NULL CHECK (decision IN ('true_positive', 'false_positive', 'benign_positive', 'needs_more_info')),
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    notes TEXT,
    triage_correct BOOLEAN,
    correlation_helpful BOOLEAN,
    analysis_accurate BOOLEAN,
    review_duration_s INTEGER CHECK (review_duration_s >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT analyst_feedback_escalation_key UNIQUE (tenant_id, escalation_id),
    CONSTRAINT analyst_feedback_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT analyst_feedback_escalation_fk FOREIGN KEY (tenant_id, escalation_id)
        REFERENCES escalations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT analyst_feedback_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT analyst_feedback_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (user_id)
);
CREATE INDEX ix_analyst_feedback_alert ON analyst_feedback (tenant_id, alert_id);
CREATE INDEX ix_analyst_feedback_created ON analyst_feedback (tenant_id, created_at);

CREATE TABLE response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    alert_id TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 2048),
    params JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(params) = 'object'),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (
        status IN ('proposed', 'awaiting_approval', 'approved', 'rejected', 'executing',
                   'succeeded', 'failed', 'dry_run', 'blocked')
    ),
    blocked_reason TEXT,
    requested_by TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    connector TEXT,
    result JSONB,
    rollback_of UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT response_actions_idempotency_key UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT response_actions_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT response_actions_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT response_actions_rollback_of_fk FOREIGN KEY (tenant_id, rollback_of)
        REFERENCES response_actions (tenant_id, id) ON DELETE SET NULL (rollback_of)
);
CREATE INDEX ix_response_actions_created ON response_actions (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_response_actions_status ON response_actions (tenant_id, status, created_at DESC, id DESC);
CREATE INDEX ix_response_actions_alert ON response_actions (tenant_id, alert_id);
CREATE INDEX ix_response_actions_executed ON response_actions (tenant_id, executed_at)
    WHERE executed_at IS NOT NULL;

CREATE TABLE suppression_rules (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    match JSONB NOT NULL CONSTRAINT suppression_rules_match_nonempty
        CHECK (jsonb_typeof(match) = 'object' AND match <> '{}'::jsonb),
    disposition TEXT NOT NULL DEFAULT 'benign' CHECK (disposition IN ('benign')),
    created_by UUID,
    source_feedback_id TEXT,
    expires_at TIMESTAMPTZ,
    hit_count BIGINT NOT NULL DEFAULT 0 CHECK (hit_count >= 0),
    last_hit_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT suppression_rules_created_by_fk FOREIGN KEY (tenant_id, created_by)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (created_by),
    CONSTRAINT suppression_rules_feedback_fk FOREIGN KEY (tenant_id, source_feedback_id)
        REFERENCES analyst_feedback (tenant_id, id) ON DELETE SET NULL (source_feedback_id)
);
CREATE INDEX ix_suppression_rules_tenant ON suppression_rules (tenant_id, created_at DESC);
CREATE INDEX ix_suppression_rules_active ON suppression_rules (tenant_id) WHERE enabled;

CREATE TABLE indicator_sightings (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    indicator_type TEXT NOT NULL CHECK (indicator_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    value_hash TEXT NOT NULL CHECK (length(value_hash) BETWEEN 16 AND 128),
    value_display TEXT CHECK (length(value_display) <= 256),
    alert_id TEXT NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, alert_id, indicator_type, value_hash),
    CONSTRAINT indicator_sightings_alert_fk FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ix_indicator_sightings_lookup
    ON indicator_sightings (tenant_id, indicator_type, value_hash, seen_at DESC);
CREATE INDEX ix_indicator_sightings_seen_at ON indicator_sightings (seen_at);

CREATE TABLE llm_usage_daily (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    day DATE NOT NULL,
    model TEXT NOT NULL,
    agent TEXT NOT NULL,
    calls BIGINT NOT NULL DEFAULT 0 CHECK (calls >= 0),
    input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_read_tokens BIGINT NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    cache_write_tokens BIGINT NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
    cost_usd NUMERIC(12, 6) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    refusals BIGINT NOT NULL DEFAULT 0 CHECK (refusals >= 0),
    errors BIGINT NOT NULL DEFAULT 0 CHECK (errors >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, day, model, agent)
);
CREATE INDEX ix_llm_usage_daily_day ON llm_usage_daily (day);

CREATE TABLE audit_log (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    id BIGSERIAL,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('system', 'user', 'agent', 'api_key')),
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash TEXT,
    hash TEXT NOT NULL,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX ix_audit_log_chain ON audit_log (tenant_id, id);
CREATE INDEX ix_audit_log_ts ON audit_log (tenant_id, ts DESC, id DESC);
CREATE INDEX ix_audit_log_resource ON audit_log (tenant_id, resource_type, resource_id);

-- Canonical entry text is jsonb's deterministic text form; verifiers outside
-- the database must reproduce it byte for byte (keys ordered by length, then bytes).
CREATE FUNCTION audit_entry_hash(
    p_tenant_id TEXT, p_id BIGINT, p_ts TIMESTAMPTZ, p_actor_type TEXT, p_actor_id TEXT,
    p_action TEXT, p_resource_type TEXT, p_resource_id TEXT, p_details JSONB, p_prev_hash TEXT
) RETURNS TEXT
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT encode(sha256(convert_to(jsonb_build_object(
        'tenant_id', p_tenant_id,
        'id', p_id,
        'ts', to_char(p_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'actor_type', p_actor_type,
        'actor_id', p_actor_id,
        'action', p_action,
        'resource_type', p_resource_type,
        'resource_id', p_resource_id,
        'details', p_details,
        'prev_hash', p_prev_hash
    )::text, 'UTF8')), 'hex')
$$;

CREATE FUNCTION audit_log_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF lgsotf_rls_bypass() THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        ELSIF TG_OP = 'UPDATE' THEN
            RETURN NEW;
        END IF;
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();

-- Credential lookups made before the tenant is known (login, refresh, API
-- key authentication). They run as the schema owner with the bypass on for
-- the one query, so the runtime role can resolve exactly one credential
-- without holding any cross-tenant read access itself.
CREATE FUNCTION lgsotf_auth_refresh_token(p_token_hash TEXT) RETURNS SETOF public.refresh_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY SELECT * FROM public.refresh_tokens WHERE token_hash = p_token_hash;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

CREATE FUNCTION lgsotf_auth_api_key(p_key_id UUID) RETURNS SETOF public.api_keys
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY SELECT * FROM public.api_keys WHERE id = p_key_id;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

CREATE FUNCTION lgsotf_auth_users_by_email(p_email TEXT) RETURNS SETOF public.users
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY SELECT * FROM public.users WHERE email = p_email ORDER BY tenant_id;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

REVOKE ALL ON FUNCTION lgsotf_auth_refresh_token(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lgsotf_auth_api_key(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION lgsotf_auth_users_by_email(TEXT) FROM PUBLIC;
"""


def _rls_sql(table: str, column: str = "tenant_id") -> List[str]:
    predicate = TENANT_POLICY_PREDICATE.replace("tenant_id =", f"{column} =", 1)
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY tenant_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})",
    ]


def upgrade() -> None:
    op.execute(SCHEMA)

    for table in UPDATED_AT_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_touch_updated_at BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION lgsotf_touch_updated_at()"
        )

    for stmt in _rls_sql("tenants", column="id"):
        op.execute(stmt)
    for table in TENANT_OWNED_TABLES:
        for stmt in _rls_sql(table):
            op.execute(stmt)

    first = month_start(datetime.now(UTC).date())
    for table in PARTITIONED:
        for stmt in create_default_partition_sql(table):
            op.execute(stmt)
        for i in range(INITIAL_PARTITION_MONTHS):
            for stmt in create_partition_sql(table, add_months(first, i)):
                op.execute(stmt)

    op.execute("SELECT set_config('app.bypass_rls', 'on', true)")
    op.execute("INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT (id) DO NOTHING")


def downgrade() -> None:
    op.execute(
        "DROP TABLE IF EXISTS audit_log, llm_usage_daily, indicator_sightings, suppression_rules, "
        "response_actions, analyst_feedback, escalations, workflow_runs, alert_events, alerts, "
        "sources, api_keys, refresh_tokens, users, tenants CASCADE"
    )
    op.execute("DROP FUNCTION IF EXISTS lgsotf_auth_refresh_token(TEXT)")
    op.execute("DROP FUNCTION IF EXISTS lgsotf_auth_api_key(UUID)")
    op.execute("DROP FUNCTION IF EXISTS lgsotf_auth_users_by_email(TEXT)")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_mutation()")
    op.execute(
        "DROP FUNCTION IF EXISTS audit_entry_hash(TEXT, BIGINT, TIMESTAMPTZ, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)"
    )
    op.execute("DROP FUNCTION IF EXISTS lgsotf_touch_updated_at()")
    # LangGraph's checkpoint tables are not Alembic's, but `lg-sotf migrate` puts them under a
    # tenant policy that uses lgsotf_rls_bypass(); lift it so the function can go.
    op.execute(
        """
        DO $$
        DECLARE t TEXT;
        BEGIN
            FOREACH t IN ARRAY ARRAY['checkpoints', 'checkpoint_blobs', 'checkpoint_writes'] LOOP
                IF to_regclass('public.' || t) IS NOT NULL THEN
                    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
                    EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
                    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
                END IF;
            END LOOP;
        END $$
        """
    )
    op.execute("DROP FUNCTION IF EXISTS lgsotf_rls_bypass()")
