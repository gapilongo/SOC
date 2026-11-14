/**
 * What needs an act now in the SOC, for the shell's notifications: only
 * what the API reports today.
 *
 * - Deadlines: escalations past their deadline, and the next deadline when
 *   it is at most 15 minutes away (the dashboard summary the rail's counts
 *   already read, so no extra request).
 * - Approvals waiting on the signed-in person (the same summary).
 * - A source that stopped delivering: `health` of `GET /sources` (admins).
 *
 * Nothing else has a source yet (an AI close reopened by the safety net, a
 * blind-audit sample ready), so nothing else is listed.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import type { Notice } from '../../core/module';
import { useNow } from '../../lib/useNow';
import { usePollInterval } from '../../lib/visibility';
import { endpoints } from './api/endpoints';
import { useDashboardSummary } from './api/hooks';
import { qk } from './api/queryKeys';
import type { SourceOut } from './api/types';
import { APPROVALS_HREF, escalationQueueHref } from './lib/links';

/** A deadline this close is "about to pass". */
const SOON_MS = 15 * 60_000;

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** A count field of the summary, read defensively: a positive whole number or nothing (older APIs omit fields). */
function count(summary: Record<string, unknown>, field: string): number {
  const value = summary[field];
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : 0;
}

/** The notices for a dashboard summary and (for admins) the tenant's sources, at time `now`. */
export function socNotices(summary: unknown, sources: readonly SourceOut[] | undefined, now: number): Notice[] {
  const out: Notice[] = [];
  const s = summary && typeof summary === 'object' ? (summary as Record<string, unknown>) : {};

  const overdue = count(s, 'overdue_escalations');
  if (overdue) {
    out.push({
      id: 'overdue',
      kind: 'deadline',
      text: `${overdue} ${plural(overdue, 'escalation is past its deadline', 'escalations are past their deadline')}`,
      detail: 'the oldest first',
      to: escalationQueueHref({ overdue: true, order: 'sla_deadline' }),
    });
  }
  const left = typeof s.next_sla_deadline === 'string' ? new Date(s.next_sla_deadline).getTime() - now : Number.NaN;
  if (left >= 0 && left <= SOON_MS) {
    const unassigned = count(s, 'unassigned_breaching');
    out.push({
      id: 'next-deadline',
      kind: 'deadline',
      text: `A deadline passes in ${Math.max(1, Math.ceil(left / 60_000))} min`,
      detail: unassigned ? `${unassigned} ${plural(unassigned, 'escalation near its deadline has', 'escalations near their deadline have')} no owner` : 'the soonest deadline first',
      to: escalationQueueHref({ order: 'sla_deadline' }),
    });
  }
  const approvals = count(s, 'pending_approvals');
  if (approvals) {
    out.push({
      id: 'approvals',
      kind: 'approval',
      text: `${approvals} ${plural(approvals, 'action waits', 'actions wait')} for your approval`,
      to: APPROVALS_HREF,
    });
  }
  for (const source of sources ?? []) {
    if (!source.enabled || (source.health !== 'failing' && source.health !== 'degraded')) continue;
    out.push({
      id: `source:${source.id}`,
      kind: 'source',
      text: `Source ${source.health}: ${source.name}`,
      detail: 'alerts may be missing',
      to: '/sources',
    });
  }
  return out;
}

/** The SOC's notices for the signed-in person, refreshed with the rail's counts. */
export function useSocNotices(): readonly Notice[] {
  const api = useApi();
  const { principal } = useAuth();
  const summary = useDashboardSummary(24, { refetchInterval: usePollInterval(60_000) });
  const sources = useQuery({
    queryKey: qk.sources.all,
    queryFn: ({ signal }) => endpoints.sources(api, signal),
    // The API lets admins read sources.
    enabled: can.admin(principal),
    refetchInterval: usePollInterval(120_000),
  });
  const now = useNow(30_000);
  return useMemo(() => socNotices(summary.data, sources.data, now), [summary.data, sources.data, now]);
}
