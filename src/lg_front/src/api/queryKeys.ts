/**
 * React Query keys, declared once.
 *
 * Each group has an `all` key, and every other key of the group starts with
 * it, so invalidating `qk.<group>.all` reaches every list, detail and
 * sub-resource of that group (queryKeys.test.ts checks the invariant). The
 * values are the literal keys the pages used before this module existed;
 * live events and invalidation policies (`api/invalidate.ts`) rely on them.
 */

import type {
  ActionFilters,
  AlertCountsWindow,
  AlertFilters,
  AuditFilters,
  EscalationFilters,
  EscalationGroupFilters,
} from './endpoints';

export const qk = {
  alerts: {
    all: ['alerts'] as const,
    list: (filters: AlertFilters) => ['alerts', filters] as const,
    /** Status counts of the view tabs (GET /alerts/counts); stale whenever an alert changes. */
    counts: (window: AlertCountsWindow) => ['alerts', 'counts', window] as const,
  },
  /** One alert and what hangs off it (the drawer). */
  alert: {
    all: ['alert'] as const,
    detail: (id: string | null) => ['alert', id] as const,
    events: (id: string) => ['alert', id, 'events'] as const,
  },
  escalations: {
    all: ['escalations'] as const,
    list: (filters: EscalationFilters) => ['escalations', filters] as const,
    /** The first `limit` rows only (overview panels), not a paged list. */
    top: (filters: EscalationFilters, limit: number) => ['escalations', 'top', filters, limit] as const,
    groups: (filters: EscalationGroupFilters) => ['escalations', 'groups', filters] as const,
  },
  /** One escalation (the decision page) and what hangs off it. */
  escalation: {
    all: ['escalation'] as const,
    detail: (id: string) => ['escalation', id] as const,
    responsePreview: (id: string) => ['escalation', id, 'response-preview'] as const,
  },
  actions: {
    all: ['actions'] as const,
    list: (filters: ActionFilters) => ['actions', filters] as const,
  },
  tickets: {
    all: ['tickets'] as const,
    forAlert: (alertId: string) => ['tickets', 'alert', alertId] as const,
    forEscalations: (escalationIds: readonly string[]) => ['tickets', 'escalations', escalationIds] as const,
  },
  /** The caller as the API sees it (GET /auth/me), per acting tenant. */
  me: {
    all: ['me'] as const,
    forTenant: (tenantId: string) => ['me', tenantId] as const,
  },
  dashboard: {
    all: ['dashboard'] as const,
    summary: (windowHours: number) => ['dashboard', windowHours] as const,
  },
  sources: {
    all: ['sources'] as const,
  },
  suppressions: {
    all: ['suppressions'] as const,
    /** Every rule, disabled ones included (the page filters them). */
    includingDisabled: ['suppressions', 'all'] as const,
  },
  users: {
    all: ['users'] as const,
    list: (includeInactive: boolean) => ['users', includeInactive] as const,
  },
  apiKeys: {
    all: ['api-keys'] as const,
    list: (includeRevoked: boolean) => ['api-keys', includeRevoked] as const,
  },
  /** MFA status of the signed-in account. */
  mfaStatus: {
    all: ['mfa-status'] as const,
  },
  onboarding: {
    all: ['onboarding-status'] as const,
  },
  /** First-run setup wizard state (GET /onboarding/setup). */
  setup: {
    all: ['onboarding-setup'] as const,
  },
  tenantSettings: {
    all: ['tenant-settings'] as const,
  },
  responseRoutes: {
    all: ['response-routes'] as const,
    /** Re-read whenever the settings they derive from change. */
    forSettings: (settingsUpdatedAt: string) => ['response-routes', settingsUpdatedAt] as const,
  },
  /** The integrations list; delivery logs hang off it, so invalidating `all` reaches them too. */
  integrations: {
    all: ['integrations'] as const,
    deliveries: (integrationId: string) => ['integrations', integrationId, 'deliveries'] as const,
  },
  microsoftCatalog: {
    all: ['microsoft-catalog'] as const,
  },
  audit: {
    all: ['audit'] as const,
    list: (filters: AuditFilters) => ['audit', filters] as const,
  },
  usage: {
    all: ['usage'] as const,
    range: (from: string, to: string) => ['usage', from, to] as const,
  },
  reportValue: {
    all: ['report-value'] as const,
    range: (from: string, to: string) => ['report-value', from, to] as const,
  },
  reportAccuracy: {
    all: ['report-accuracy'] as const,
    range: (from: string, to: string) => ['report-accuracy', from, to] as const,
  },
  reportDetections: {
    all: ['report-detections'] as const,
    range: (from: string, to: string) => ['report-detections', from, to] as const,
  },
  reportBlindAudit: {
    all: ['report-blind-audit'] as const,
    range: (from: string, to: string) => ['report-blind-audit', from, to] as const,
  },
  /** The blind audit queue, one sample, and the sampling runs. */
  blindAudit: {
    all: ['blind-audit'] as const,
    queue: (status: 'pending' | 'labelled') => ['blind-audit', 'items', status] as const,
    item: (id: string) => ['blind-audit', 'item', id] as const,
    runs: ['blind-audit', 'runs'] as const,
  },
  /** Proof-of-value runs: the list and one run with its backtest result. */
  pov: {
    all: ['pov'] as const,
    runs: ['pov', 'runs'] as const,
    run: (id: string) => ['pov', 'run', id] as const,
  },
  reportMonthly: {
    all: ['report-monthly'] as const,
    month: (month: string) => ['report-monthly', month] as const,
  },
  platformTenants: {
    all: ['platform-tenants'] as const,
  },
  platformEscalations: {
    all: ['platform-escalations'] as const,
    list: (tenantId: string) => ['platform-escalations', tenantId] as const,
  },
  platformUsage: {
    all: ['platform-usage'] as const,
    month: (month: string) => ['platform-usage', month] as const,
  },
} as const;
