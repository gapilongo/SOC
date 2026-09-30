"""MSSP operations: tenant quotas, onboarding state, usage metering and platform read functions.

* ``tenants``: ``max_alerts_per_day``, ``max_sources``, ``max_users``
  (``NULL`` = unlimited; set by platform admins only) and ``onboarding``
  (first-run checklist state: ``dismissed_at``, ``autonomy_reviewed_at``).
* ``usage_daily``: per tenant and UTC day, alerts ingested and processed and
  ingest requests refused over quota. Invoicing reads this table, not
  ``alerts``: alerts are purged by (per-tenant) retention and deduplicated
  re-deliveries never become rows, so counting rows would under-bill a month
  whose alerts were already purged.
* ``lgsotf_platform_*``: SECURITY DEFINER aggregates across tenants for the
  platform-admin endpoints. Like ``lgsotf_create_tenant`` they let the
  runtime role (which cannot bypass RLS) read exactly these aggregates and
  nothing else; the platform-admin check and the audit entry are the API's.

Revision ID: 0105
Revises: 0003
Create Date: 2026-09-30
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from lg_sotf.db.partitions import TENANT_POLICY_PREDICATE

revision: str = "0105"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SAMPLE_SOURCE_ID = "demo:samples"

SCHEMA = r"""
ALTER TABLE tenants
    ADD COLUMN max_alerts_per_day INTEGER CONSTRAINT tenants_max_alerts_per_day_check CHECK (max_alerts_per_day >= 0),
    ADD COLUMN max_sources INTEGER CONSTRAINT tenants_max_sources_check CHECK (max_sources >= 0),
    ADD COLUMN max_users INTEGER CONSTRAINT tenants_max_users_check CHECK (max_users >= 0),
    ADD COLUMN onboarding JSONB NOT NULL DEFAULT '{}'::jsonb
        CONSTRAINT tenants_onboarding_object CHECK (jsonb_typeof(onboarding) = 'object');

CREATE TABLE usage_daily (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    day DATE NOT NULL,
    alerts_ingested BIGINT NOT NULL DEFAULT 0 CHECK (alerts_ingested >= 0),
    alerts_processed BIGINT NOT NULL DEFAULT 0 CHECK (alerts_processed >= 0),
    alerts_rejected_quota BIGINT NOT NULL DEFAULT 0 CHECK (alerts_rejected_quota >= 0),
    quota_exceeded_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, day)
);
CREATE INDEX ix_usage_daily_day ON usage_daily (day);
CREATE TRIGGER usage_daily_touch_updated_at BEFORE UPDATE ON usage_daily
    FOR EACH ROW EXECUTE FUNCTION lgsotf_touch_updated_at();

CREATE FUNCTION lgsotf_platform_tenants() RETURNS SETOF public.tenants
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY SELECT * FROM public.tenants ORDER BY id;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

-- One row per tenant; every figure is an index range scan within that tenant.
CREATE FUNCTION lgsotf_platform_tenant_stats(p_now TIMESTAMPTZ)
RETURNS TABLE (
    tenant_id TEXT,
    alerts_24h BIGINT,
    alerts_today BIGINT,
    last_ingest_at TIMESTAMPTZ,
    open_escalations BIGINT,
    overdue_escalations BIGINT,
    sla_breaches_24h BIGINT,
    llm_cost_mtd NUMERIC,
    llm_tokens_mtd BIGINT,
    users BIGINT,
    sources BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
    v_day DATE := (p_now AT TIME ZONE 'UTC')::date;
    v_month DATE := date_trunc('month', (p_now AT TIME ZONE 'UTC'))::date;
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY
        SELECT t.id,
            (SELECT count(*) FROM public.alerts a
             WHERE a.tenant_id = t.id AND a.ingested_at >= p_now - interval '24 hours'),
            COALESCE((SELECT u.alerts_ingested FROM public.usage_daily u
                      WHERE u.tenant_id = t.id AND u.day = v_day), 0)::bigint,
            (SELECT max(a.ingested_at) FROM public.alerts a
             WHERE a.tenant_id = t.id AND a.source_id <> '{sample}'),
            (SELECT count(*) FROM public.escalations e
             WHERE e.tenant_id = t.id AND e.status IN ('open', 'claimed')),
            (SELECT count(*) FROM public.escalations e
             WHERE e.tenant_id = t.id AND e.status IN ('open', 'claimed') AND e.sla_deadline < p_now),
            (SELECT count(*) FROM public.audit_log l
             WHERE l.tenant_id = t.id AND l.ts >= p_now - interval '24 hours'
               AND l.action IN ('escalation.sla_escalated', 'escalation.sla_expired')),
            COALESCE((SELECT sum(c.cost_usd) FROM public.llm_usage_daily c
                      WHERE c.tenant_id = t.id AND c.day BETWEEN v_month AND v_day), 0)::numeric,
            COALESCE((SELECT sum(c.input_tokens + c.output_tokens) FROM public.llm_usage_daily c
                      WHERE c.tenant_id = t.id AND c.day BETWEEN v_month AND v_day), 0)::bigint,
            (SELECT count(*) FROM public.users x WHERE x.tenant_id = t.id AND x.is_active),
            (SELECT count(*) FROM public.sources s WHERE s.tenant_id = t.id)
        FROM public.tenants t
        ORDER BY t.id;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

-- Active escalations of every tenant, soonest SLA first (no deadline last), keyset-paginated.
CREATE FUNCTION lgsotf_platform_escalations(p_limit INTEGER, p_after_due TIMESTAMPTZ, p_after_id TEXT, p_tenant TEXT)
RETURNS TABLE (
    id TEXT,
    tenant_id TEXT,
    tenant_name TEXT,
    tenant_status TEXT,
    alert_id TEXT,
    alert_title TEXT,
    alert_severity TEXT,
    level TEXT,
    status TEXT,
    priority SMALLINT,
    reason TEXT,
    assigned_to UUID,
    sla_deadline TIMESTAMPTZ,
    sort_due TIMESTAMPTZ,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY
        SELECT e.id, e.tenant_id, t.name, t.status, e.alert_id, a.title, a.severity, e.level, e.status,
               e.priority, e.reason, e.assigned_to, e.sla_deadline,
               COALESCE(e.sla_deadline, '9999-12-31T00:00:00Z'::timestamptz), e.created_at
        FROM public.escalations e
        JOIN public.tenants t ON t.id = e.tenant_id
        LEFT JOIN public.alerts a ON a.tenant_id = e.tenant_id AND a.id = e.alert_id
        WHERE e.status IN ('open', 'claimed')
          AND (p_tenant IS NULL OR e.tenant_id = p_tenant)
          AND (p_after_id IS NULL
               OR (COALESCE(e.sla_deadline, '9999-12-31T00:00:00Z'::timestamptz), e.id) > (p_after_due, p_after_id))
        ORDER BY COALESCE(e.sla_deadline, '9999-12-31T00:00:00Z'::timestamptz), e.id
        LIMIT LEAST(GREATEST(p_limit, 1), 501);
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

-- Invoicing figures per tenant for the UTC days p_start..p_end (inclusive).
-- active_users: distinct accounts of the tenant (or SSO subjects) that appear as
-- actors in its audit log in the period (sign-ins, decisions, changes).
CREATE FUNCTION lgsotf_platform_usage(p_start DATE, p_end DATE)
RETURNS TABLE (
    tenant_id TEXT,
    tenant_name TEXT,
    tenant_status TEXT,
    alerts_ingested BIGINT,
    alerts_processed BIGINT,
    alerts_rejected_quota BIGINT,
    llm_calls BIGINT,
    llm_input_tokens BIGINT,
    llm_output_tokens BIGINT,
    llm_cost_usd NUMERIC,
    active_users BIGINT,
    users BIGINT,
    sources BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    previous TEXT := current_setting('app.bypass_rls', true);
    v_from TIMESTAMPTZ := p_start::timestamp AT TIME ZONE 'UTC';
    v_to TIMESTAMPTZ := (p_end + 1)::timestamp AT TIME ZONE 'UTC';
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    RETURN QUERY
        SELECT t.id, t.name, t.status,
            COALESCE(u.ingested, 0)::bigint, COALESCE(u.processed, 0)::bigint, COALESCE(u.rejected, 0)::bigint,
            COALESCE(c.calls, 0)::bigint, COALESCE(c.input_tokens, 0)::bigint, COALESCE(c.output_tokens, 0)::bigint,
            COALESCE(c.cost_usd, 0)::numeric,
            (SELECT count(DISTINCT l.actor_id) FROM public.audit_log l
             WHERE l.tenant_id = t.id AND l.ts >= v_from AND l.ts < v_to AND l.actor_type = 'user'
               AND (l.actor_id LIKE 'oidc:%'
                    OR EXISTS (SELECT 1 FROM public.users x WHERE x.tenant_id = t.id AND x.id::text = l.actor_id))),
            (SELECT count(*) FROM public.users x WHERE x.tenant_id = t.id AND x.is_active),
            (SELECT count(*) FROM public.sources s WHERE s.tenant_id = t.id)
        FROM public.tenants t
        LEFT JOIN (
            SELECT d.tenant_id, sum(d.alerts_ingested) AS ingested, sum(d.alerts_processed) AS processed,
                   sum(d.alerts_rejected_quota) AS rejected
            FROM public.usage_daily d WHERE d.day BETWEEN p_start AND p_end GROUP BY d.tenant_id
        ) u ON u.tenant_id = t.id
        LEFT JOIN (
            SELECT m.tenant_id, sum(m.calls) AS calls, sum(m.input_tokens) AS input_tokens,
                   sum(m.output_tokens) AS output_tokens, sum(m.cost_usd) AS cost_usd
            FROM public.llm_usage_daily m WHERE m.day BETWEEN p_start AND p_end GROUP BY m.tenant_id
        ) c ON c.tenant_id = t.id
        ORDER BY t.id;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END
$$;

REVOKE ALL ON FUNCTION lgsotf_platform_tenants() FROM PUBLIC;
REVOKE ALL ON FUNCTION lgsotf_platform_tenant_stats(TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION lgsotf_platform_escalations(INTEGER, TIMESTAMPTZ, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lgsotf_platform_usage(DATE, DATE) FROM PUBLIC;
""".replace("{sample}", SAMPLE_SOURCE_ID)


def upgrade() -> None:
    op.execute(SCHEMA)
    op.execute("ALTER TABLE usage_daily ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE usage_daily FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON usage_daily "
        f"USING ({TENANT_POLICY_PREDICATE}) WITH CHECK ({TENANT_POLICY_PREDICATE})"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS lgsotf_platform_usage(DATE, DATE)")
    op.execute("DROP FUNCTION IF EXISTS lgsotf_platform_escalations(INTEGER, TIMESTAMPTZ, TEXT, TEXT)")
    op.execute("DROP FUNCTION IF EXISTS lgsotf_platform_tenant_stats(TIMESTAMPTZ)")
    op.execute("DROP FUNCTION IF EXISTS lgsotf_platform_tenants()")
    op.execute("DROP TABLE IF EXISTS usage_daily")
    op.execute(
        "ALTER TABLE tenants DROP COLUMN IF EXISTS onboarding, DROP COLUMN IF EXISTS max_users, "
        "DROP COLUMN IF EXISTS max_sources, DROP COLUMN IF EXISTS max_alerts_per_day"
    )
