import type { TenantSummaryOut } from '../api/types';

/** A `/platform/tenants` row with quiet defaults. */
export function tenant(id: string, name: string, overrides: Partial<TenantSummaryOut> = {}): TenantSummaryOut {
  return {
    id,
    name,
    status: 'active',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    quotas: { max_alerts_per_day: null, max_sources: null, max_users: null },
    quota_usage: {
      max_alerts_per_day: { used: 0, limit: null },
      max_sources: { used: 0, limit: null },
      max_users: { used: 1, limit: null },
    },
    stats: {
      alerts_24h: 0,
      alerts_today: 0,
      last_ingest_at: null,
      open_escalations: 0,
      overdue_escalations: 0,
      sla_breaches_24h: 0,
      llm_cost_mtd_usd: '0',
      llm_tokens_mtd: 0,
      users: 1,
      sources: 0,
    },
    ...overrides,
  };
}
