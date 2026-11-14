/**
 * Where the Overview sends work: the work queue of console v2, opened on one
 * of its views. The view's URL parameters are the queue's own (`viewSearch`),
 * so a change to how the queue spells a view is followed here.
 */

import { viewSearch, type ViewId } from '../queue/model';

/**
 * The queue's path, as the module manifest registers it. The queue exports no
 * route or link constant, so the path is named once here rather than typed
 * into each link.
 */
const QUEUE_PATH = '/queue';

/** The queue views the Overview links to: everything that needs a person, the caller's, the ones nobody holds. */
export type QueueView = Extract<ViewId, 'all' | 'mine' | 'unassigned'>;

/** The work queue on `view` (soonest deadline first, as the queue sorts by default). */
export function workQueueHref(view: QueueView): string {
  const query = viewSearch(view).toString();
  return query ? `${QUEUE_PATH}?${query}` : QUEUE_PATH;
}

/** Where sampled AI closes are labelled. */
export const BLIND_AUDIT_HREF = '/blind-audit';

/** The Reports page (its Blind audit tab holds the full estimate and the sampling runs). */
export const REPORTS_HREF = '/reports';
