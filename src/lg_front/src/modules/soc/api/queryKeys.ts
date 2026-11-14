/**
 * The SOC module's React Query keys, declared once.
 *
 * Every key starts with the module id (`NS`), so the SOC's invalidation
 * policies and live events can only reach the SOC's cache (ADR 0015). Each
 * group has an `all` key, and every other key of the group starts with it,
 * so invalidating `qk.<group>.all` reaches every list, detail and
 * sub-resource of that group (queryKeys.test.ts checks both invariants).
 * Live events (the manifest's `liveEvents`) and invalidation policies
 * (`invalidate.ts`) rely on them.
 */

import type {
  ActionFilters,
  AlertCountsWindow,
  AlertFilters,
  AuditFilters,
  EscalationFilters,
  EscalationGroupFilters,
} from './endpoints';

/** The module id: the first element of every key. */
export const NS = 'soc';

export const qk = {
  alerts: {
    all: [NS, 'alerts'] as const,
    list: (filters: AlertFilters) => [NS, 'alerts', filters] as const,
    /** Status counts of the view tabs (GET /alerts/counts); stale whenever an alert changes. */
    counts: (window: AlertCountsWindow) => [NS, 'alerts', 'counts', window] as const,
  },
  /** One alert and what hangs off it (the drawer). */
  alert: {
    all: [NS, 'alert'] as const,
    detail: (id: string | null) => [NS, 'alert', id] as const,
    events: (id: string) => [NS, 'alert', id, 'events'] as const,
  },
  escalations: {
    all: [NS, 'escalations'] as const,
    list: (filters: EscalationFilters) => [NS, 'escalations', filters] as const,
    /** The first `limit` rows only (overview panels), not a paged list. */
    top: (filters: EscalationFilters, limit: number) => [NS, 'escalations', 'top', filters, limit] as const,
    groups: (filters: EscalationGroupFilters) => [NS, 'escalations', 'groups', filters] as const,
  },
  /** One escalation (the decision page) and what hangs off it. */
  escalation: {
    all: [NS, 'escalation'] as const,
    detail: (id: string) => [NS, 'escalation', id] as const,
    responsePreview: (id: string) => [NS, 'escalation', id, 'response-preview'] as const,
  },
  actions: {
    all: [NS, 'actions'] as const,
    list: (filters: ActionFilters) => [NS, 'actions', filters] as const,
  },
  tickets: {
    all: [NS, 'tickets'] as const,
    forAlert: (alertId: string) => [NS, 'tickets', 'alert', alertId] as const,
    forEscalations: (escalationIds: readonly string[]) => [NS, 'tickets', 'escalations', escalationIds] as const,
  },
  dashboard: {
    all: [NS, 'dashboard'] as const,
    summary: (windowHours: number) => [NS, 'dashboard', windowHours] as const,
  },
  sources: {
    all: [NS, 'sources'] as const,
  },
  suppressions: {
    all: [NS, 'suppressions'] as const,
    /** Every rule, disabled ones included (the page filters them). */
    includingDisabled: [NS, 'suppressions', 'all'] as const,
  },
  users: {
    all: [NS, 'users'] as const,
    list: (includeInactive: boolean) => [NS, 'users', includeInactive] as const,
  },
  apiKeys: {
    all: [NS, 'api-keys'] as const,
    list: (includeRevoked: boolean) => [NS, 'api-keys', includeRevoked] as const,
  },
  /** MFA status of the signed-in account. */
  mfaStatus: {
    all: [NS, 'mfa-status'] as const,
  },
  onboarding: {
    all: [NS, 'onboarding-status'] as const,
  },
  /** First-run setup wizard state (GET /onboarding/setup). */
  setup: {
    all: [NS, 'onboarding-setup'] as const,
  },
  tenantSettings: {
    all: [NS, 'tenant-settings'] as const,
  },
  responseRoutes: {
    all: [NS, 'response-routes'] as const,
    /** Re-read whenever the settings they derive from change. */
    forSettings: (settingsUpdatedAt: string) => [NS, 'response-routes', settingsUpdatedAt] as const,
  },
  /** The integrations list; delivery logs hang off it, so invalidating `all` reaches them too. */
  integrations: {
    all: [NS, 'integrations'] as const,
    deliveries: (integrationId: string) => [NS, 'integrations', integrationId, 'deliveries'] as const,
  },
  microsoftCatalog: {
    all: [NS, 'microsoft-catalog'] as const,
  },
  audit: {
    all: [NS, 'audit'] as const,
    list: (filters: AuditFilters) => [NS, 'audit', filters] as const,
  },
  usage: {
    all: [NS, 'usage'] as const,
    range: (from: string, to: string) => [NS, 'usage', from, to] as const,
  },
  reportValue: {
    all: [NS, 'report-value'] as const,
    range: (from: string, to: string) => [NS, 'report-value', from, to] as const,
  },
  reportAccuracy: {
    all: [NS, 'report-accuracy'] as const,
    range: (from: string, to: string) => [NS, 'report-accuracy', from, to] as const,
  },
  reportDetections: {
    all: [NS, 'report-detections'] as const,
    range: (from: string, to: string) => [NS, 'report-detections', from, to] as const,
  },
  reportBlindAudit: {
    all: [NS, 'report-blind-audit'] as const,
    range: (from: string, to: string) => [NS, 'report-blind-audit', from, to] as const,
  },
  /** The blind audit queue, one sample, and the sampling runs. */
  blindAudit: {
    all: [NS, 'blind-audit'] as const,
    queue: (status: 'pending' | 'labelled') => [NS, 'blind-audit', 'items', status] as const,
    item: (id: string) => [NS, 'blind-audit', 'item', id] as const,
    runs: [NS, 'blind-audit', 'runs'] as const,
  },
  reportMonthly: {
    all: [NS, 'report-monthly'] as const,
    month: (month: string) => [NS, 'report-monthly', month] as const,
  },
  platformTenants: {
    all: [NS, 'platform-tenants'] as const,
  },
  platformEscalations: {
    all: [NS, 'platform-escalations'] as const,
    list: (tenantId: string) => [NS, 'platform-escalations', tenantId] as const,
  },
  platformUsage: {
    all: [NS, 'platform-usage'] as const,
    month: (month: string) => [NS, 'platform-usage', month] as const,
  },
} as const;
