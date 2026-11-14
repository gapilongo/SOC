/**
 * Where the Overview sends work. One place, so the day the work queue of
 * console v2 (`/queue`) is on the route table these three links move there
 * together; until then they open the same lists on the Escalations page.
 */

import { escalationQueueHref } from '../../lib/links';

export type QueueView = 'all' | 'mine' | 'unassigned';

/** The items that need a person, soonest deadline first: all of them, the caller's, or the ones nobody holds. */
export function workQueueHref(view: QueueView): string {
  if (view === 'mine') return escalationQueueHref({ assigned_to: 'me', order: 'sla_deadline' });
  if (view === 'unassigned') return escalationQueueHref({ assigned_to: 'none', order: 'sla_deadline' });
  return escalationQueueHref({ order: 'sla_deadline' });
}

/** Where sampled AI closes are labelled. */
export const BLIND_AUDIT_HREF = '/blind-audit';

/** The Reports page (its Blind audit tab holds the full estimate and the sampling runs). */
export const REPORTS_HREF = '/reports';
