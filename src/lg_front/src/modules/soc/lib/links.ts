/**
 * In-app links shared by pages, so a route change happens in one place.
 *
 * The escalation queue reads its filters from the URL with the API's own
 * parameter names (`assigned_to=me|none|<id>`, `overdue=true`,
 * `order=sla_deadline`, `source_id`, `rule`, `decided_by`, repeated `status`
 * and `level`).
 */

import type { EscalationFilters } from '../api/endpoints';
import type { EscalationOut } from '../api/types';

function withQuery(path: string, params: URLSearchParams): string {
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

/** The escalation queue with these filters. */
export function escalationQueueHref(filters: EscalationFilters = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters) as Array<[string, unknown]>) {
    if (value === undefined || value === null || value === '' || value === false) continue;
    if (Array.isArray(value)) for (const v of value) params.append(key, String(v));
    else params.append(key, String(value));
  }
  return withQuery('/escalations', params);
}

/** Where one escalation opens: its decision page. */
export function escalationHref(e: Pick<EscalationOut, 'id'>): string {
  return `/escalations/${encodeURIComponent(e.id)}`;
}

/** The proof-of-value page: the runs and their status. */
export const POV_HREF = '/pov';

/** The proof-of-value wizard, where the first-run setup ends. */
export const POV_WIZARD_HREF = '/pov/new';

/** The guided Wazuh setup (checks first, then the source is saved). */
export const WAZUH_SETUP_HREF = '/sources/wazuh';

/** The Reports page over a window of whole UTC days (`YYYY-MM-DD`, both included). */
export function reportsHref(range: { from: string; to: string }): string {
  return withQuery('/reports', new URLSearchParams(range));
}

/** Alerts with these filters (`severity`, `status`, `from` ...). */
export function alertsHref(filters: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value) params.append(key, value);
  return withQuery('/alerts', params);
}

/** The Approvals page: actions waiting for an approval first (`/actions` redirects there). */
export const APPROVALS_HREF = '/approvals';
