/**
 * React Query keys, declared once.
 *
 * Each group has an `all` key, and every other key of the group starts with
 * it, so invalidating `qk.<group>.all` reaches every list, detail and
 * sub-resource of that group (queryKeys.test.ts checks the invariant). The
 * values are the literal keys the pages used before this module existed;
 * live events and invalidation policies (`api/invalidate.ts`) rely on them.
 */

import type { ActionFilters, AlertFilters, EscalationFilters } from './endpoints';

export const qk = {
  alerts: {
    all: ['alerts'] as const,
    list: (filters: AlertFilters) => ['alerts', filters] as const,
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
  dashboard: {
    all: ['dashboard'] as const,
    summary: (windowHours: number) => ['dashboard', windowHours] as const,
  },
} as const;
