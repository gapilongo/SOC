/**
 * The escalation queue's URL: its filters use the API's parameter names
 * (`status`, `level`, `assigned_to`, `overdue`, `order`, `decided_by`,
 * `source_id`, `rule`), so a link from elsewhere (lib/links.ts) is the API
 * query itself. `group=rule` turns on the grouped view (a page setting, not
 * an API filter).
 */

import type { EscalationFilters } from '../../../../api/endpoints';
import { ESCALATION_ORDERS, type EscalationOrder } from '../../../../api/types';

/** Without a `status` parameter the queue lists escalations still waiting for a decision. */
export const DEFAULT_STATUS = ['open', 'claimed', 'expired'];
export const DEFAULT_ORDER: EscalationOrder = 'sla_deadline';

/** The parameters the queue reads; anything else in the URL is left alone. */
export const FILTER_KEYS = ['status', 'level', 'assigned_to', 'overdue', 'order', 'decided_by', 'source_id', 'rule'] as const;

function one(params: URLSearchParams, key: string): string | undefined {
  const v = params.get(key)?.trim();
  return v ? v : undefined;
}

/** The API filters for these URL parameters (SLA order and the waiting statuses by default). */
export function filtersFromParams(params: URLSearchParams): EscalationFilters {
  const status = params.has('status') ? params.getAll('status').filter(Boolean) : DEFAULT_STATUS;
  const level = params.getAll('level').filter(Boolean);
  const order = one(params, 'order');
  return {
    status: status.length ? status : undefined,
    level: level.length ? level : undefined,
    assigned_to: one(params, 'assigned_to'),
    decided_by: one(params, 'decided_by'),
    overdue: params.get('overdue') === 'true' ? true : undefined,
    source_id: one(params, 'source_id'),
    rule: one(params, 'rule'),
    order: (ESCALATION_ORDERS as readonly string[]).includes(order ?? '') ? (order as EscalationOrder) : DEFAULT_ORDER,
  };
}

/** Whether the grouped view is on (`group=rule`). */
export function groupedFromParams(params: URLSearchParams): boolean {
  return params.get('group') === 'rule';
}

/**
 * `params` with `changes` applied: a string or string[] sets the parameter, an
 * empty value or undefined removes it. Other parameters are kept.
 */
export function withParams(params: URLSearchParams, changes: Record<string, string | string[] | boolean | undefined>): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const [key, value] of Object.entries(changes)) {
    next.delete(key);
    if (Array.isArray(value)) for (const v of value) next.append(key, v);
    else if (value === true) next.append(key, 'true');
    else if (typeof value === 'string' && value) next.append(key, value);
  }
  return next;
}

/** A preset of the queue: the filters it sets (every other filter is cleared). */
export interface QueueView {
  id: string;
  label: string;
  params: Record<string, string | string[]>;
}

export const VIEWS: QueueView[] = [
  { id: 'active', label: 'All waiting', params: {} },
  { id: 'unassigned', label: 'Unassigned', params: { assigned_to: 'none' } },
  { id: 'mine', label: 'Mine', params: { assigned_to: 'me' } },
  { id: 'breaching', label: 'Breaching', params: { overdue: 'true' } },
  { id: 'expired', label: 'Expired', params: { status: 'expired' } },
  { id: 'decided', label: 'Decided by me', params: { status: 'decided', decided_by: 'me' } },
];

/** The URL of a view, keeping the order and the grouped setting. */
export function viewParams(params: URLSearchParams, view: QueueView): URLSearchParams {
  const cleared: Record<string, undefined> = {};
  for (const key of FILTER_KEYS) if (key !== 'order') cleared[key] = undefined;
  return withParams(params, { ...cleared, ...view.params });
}

function sameValues(params: URLSearchParams, key: string, expected: string | string[] | undefined): boolean {
  const actual = params.getAll(key).filter(Boolean).sort();
  const want = (expected === undefined ? [] : Array.isArray(expected) ? expected : [expected]).slice().sort();
  return actual.length === want.length && actual.every((v, i) => v === want[i]);
}

/** The view these parameters show exactly (ignoring the order), else null (custom filters). */
export function currentView(params: URLSearchParams): QueueView | null {
  return (
    VIEWS.find((view) => FILTER_KEYS.every((key) => key === 'order' || sameValues(params, key, view.params[key]))) ?? null
  );
}
