/**
 * The alert list's view tabs ("Needs analyst", "Awaiting approval" ...) and
 * its URL model.
 *
 * The URL is the state: `view` picks the tab, the other parameters are the
 * API's own filters (`severity`, `disposition`, `source_id`, `q`, `from`,
 * `to`; `status` and `closed_from`/`closed_to` in the All view). A view other
 * than All sets the status filter itself. Without `view`, a URL carrying any
 * filter (the overview's links, older bookmarks) opens All, so it lists what
 * it always did; a bare `/alerts` (or `/alerts?alert=<id>`) opens Needs analyst.
 */

import type { AlertCountsWindow, AlertFilters } from '../../../../api/endpoints';

export const ALERT_VIEWS = ['needs_analyst', 'awaiting_approval', 'processing', 'failed', 'closed', 'all'] as const;
export type AlertView = (typeof ALERT_VIEWS)[number];

export const DEFAULT_VIEW: AlertView = 'needs_analyst';

/** The statuses each view lists (null: any). */
export const VIEW_STATUSES: Record<AlertView, readonly string[] | null> = {
  needs_analyst: ['waiting_human'],
  awaiting_approval: ['waiting_approval'],
  processing: ['new', 'queued', 'processing'],
  failed: ['failed'],
  closed: ['closed'],
  all: null,
};

/** URL parameters that filter the list (everything but `view` and the selected `alert`). */
export const FILTER_PARAMS = ['status', 'severity', 'disposition', 'source_id', 'q', 'from', 'to', 'closed_from', 'closed_to'] as const;

function isView(value: string | null): value is AlertView {
  return (ALERT_VIEWS as readonly (string | null)[]).includes(value);
}

export function viewFromParams(params: URLSearchParams): AlertView {
  const view = params.get('view');
  if (isView(view)) return view;
  return FILTER_PARAMS.some((k) => params.getAll(k).some(Boolean)) ? 'all' : DEFAULT_VIEW;
}

/** Local midnight today, as ISO (the "Closed today" window starts there). */
export function startOfToday(now: Date = new Date()): string {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

/**
 * The closing-time window of the Closed view and of the tab counts: the URL's
 * `closed_from`/`closed_to`, else today. One value per day, so the counts stay
 * one cached request.
 */
export function closedWindow(params: URLSearchParams, now: Date = new Date()): AlertCountsWindow {
  const window: AlertCountsWindow = { closed_from: params.get('closed_from') || startOfToday(now) };
  const to = params.get('closed_to');
  if (to) window.closed_to = to;
  return window;
}

/** True when the Closed view shows its default window (today). */
export function isTodayWindow(params: URLSearchParams): boolean {
  return !params.get('closed_from') && !params.get('closed_to');
}

/** The filters the API receives for `view`: the URL's filters with the view's statuses (and window for Closed). */
export function viewFilters(view: AlertView, base: AlertFilters, window: AlertCountsWindow): AlertFilters {
  if (view === 'all') return base;
  const { status: _status, closed_from: _from, closed_to: _to, ...rest } = base;
  const filters: AlertFilters = { ...rest, status: [...(VIEW_STATUSES[view] ?? [])] };
  if (view === 'closed') Object.assign(filters, window);
  return filters;
}

/** The tab's count from `GET /alerts/counts` `by_status`; null for All (no count) or when unknown. */
export function viewCount(view: AlertView, byStatus: Record<string, number> | undefined): number | null {
  const statuses = VIEW_STATUSES[view];
  if (!statuses || !byStatus) return null;
  return statuses.reduce((sum, s) => sum + (byStatus[s] ?? 0), 0);
}

export function viewLabel(view: AlertView, todayWindow = true): string {
  switch (view) {
    case 'needs_analyst':
      return 'Needs analyst';
    case 'awaiting_approval':
      return 'Awaiting approval';
    case 'processing':
      return 'Processing';
    case 'failed':
      return 'Failed';
    case 'closed':
      return todayWindow ? 'Closed today' : 'Closed';
    default:
      return 'All';
  }
}

/**
 * The URL of `view` from the current one: the filters carry over, except the
 * status filter and closing window, which belong to the view.
 */
export function viewHref(view: AlertView, params: URLSearchParams): string {
  const next = new URLSearchParams(params);
  next.delete('status');
  if (view !== 'closed') {
    next.delete('closed_from');
    next.delete('closed_to');
  }
  next.set('view', view);
  return `/alerts?${next.toString()}`;
}
