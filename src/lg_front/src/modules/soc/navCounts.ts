/** The SOC's sidebar counts: escalations breaching SLA and approvals waiting on the signed-in person. */

import { useDashboardSummary } from '../../api/hooks';
import { usePollInterval } from '../../lib/visibility';

/** Dashboard summary fields that feed a nav count (absent on older APIs). */
export type NavCountField = 'unassigned_breaching' | 'pending_approvals';

/** The dashboard window the counts come from (the overview page's default, so the query is shared). */
const COUNT_WINDOW_HOURS = 24;

/**
 * Nav counts from the dashboard summary, read defensively: a field shows only
 * when the API sends it as a positive whole number, so older APIs (without
 * the field) show no count rather than a made-up one.
 */
export function navCounts(summary: unknown): Partial<Record<NavCountField, number>> {
  const out: Partial<Record<NavCountField, number>> = {};
  if (!summary || typeof summary !== 'object') return out;
  for (const field of ['unassigned_breaching', 'pending_approvals'] as const) {
    const value = (summary as Record<string, unknown>)[field];
    if (typeof value === 'number' && Number.isInteger(value) && value > 0) out[field] = value;
  }
  return out;
}

/** One nav count. Every item reads the same cached dashboard summary, so the sidebar makes one request. */
export function useNavCount(field: NavCountField): number | undefined {
  const q = useDashboardSummary(COUNT_WINDOW_HOURS, { refetchInterval: usePollInterval(60_000) });
  return navCounts(q.data)[field];
}
