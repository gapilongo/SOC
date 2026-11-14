/**
 * The work queue's rules, kept apart from its components: which rows a view
 * shows, what each tab counts, how a deadline reads, why a row needs a person
 * and what the analysis made of it so far.
 *
 * The queue is today's escalation list (the same request and query key as
 * the Escalations page): what waits for a person, soonest deadline first.
 * What the API does not send yet is derived here in one place, or left out:
 *
 * * the outcome mark comes from the routing code (`outcome` on the row will
 *   replace `rowOutcome`);
 * * look-alike grouping is read from the row and is absent today, so the
 *   Look-alikes view and bulk decide stay hidden until the API sends it.
 */

import type { EscalationFilters } from '../../api/endpoints';
import { escalationSeverity, finite, readAiReason, readRouting, text, type QueueFigures } from '../../api/fields';
import type { EscalationOut } from '../../api/types';
import { formatDuration } from '../../lib/format';
import { routingWhy } from '../escalations/labels';
import { filtersFromParams } from '../escalations/queueParams';

// Rows ---------------------------------------------------------------------------

/** What waits for a person, soonest deadline first: the Escalations page's default list (same query key). */
export const BASE_FILTERS: EscalationFilters = filtersFromParams(new URLSearchParams());

/** The same list narrowed by the API to one owner (`me`) or to nobody (`none`). */
export function assignedFilters(assignedTo: 'me' | 'none'): EscalationFilters {
  return filtersFromParams(new URLSearchParams({ assigned_to: assignedTo }));
}

/** A deadline this close (seconds) is marked in the row and counted in the page's first sentence. */
export const SOON_S = 600;
/** The "Deadline under 15 min" view (seconds). */
export const VIEW_SOON_S = 900;

export type DueState = 'none' | 'ok' | 'soon' | 'overdue';

export interface Due {
  state: DueState;
  /** Seconds to the deadline (negative once passed), null without one. */
  seconds: number | null;
  /** "04:12", "1h 05m", "2d 3h", with " over" once the deadline passed; "-" without a deadline. */
  text: string;
  /** The same in words, for a tooltip and screen readers. */
  label: string;
}

function clock(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const two = (n: number) => String(n).padStart(2, '0');
  if (s < 3_600) return `${two(Math.floor(s / 60))}:${two(s % 60)}`;
  const h = Math.floor(s / 3_600);
  if (h < 24) return `${h}h ${two(Math.floor((s % 3_600) / 60))}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** How long until (or since) a deadline, as the queue shows it. */
export function dueIn(deadline: string | null | undefined, now: number): Due {
  const t = deadline ? new Date(deadline).getTime() : Number.NaN;
  if (Number.isNaN(t)) return { state: 'none', seconds: null, text: '-', label: 'No deadline' };
  const seconds = Math.round((t - now) / 1000);
  if (seconds < 0) return { state: 'overdue', seconds, text: `${clock(-seconds)} over`, label: `Overdue by ${formatDuration(-seconds)}` };
  if (seconds < SOON_S) return { state: 'soon', seconds, text: clock(seconds), label: `Due in ${formatDuration(seconds)}, soon` };
  return { state: 'ok', seconds, text: clock(seconds), label: `Due in ${formatDuration(seconds)}` };
}

/** What the analysis made of an item so far: the two kinds that reach a person. */
export type Outcome = 'threat' | 'review';

export const OUTCOMES: readonly Outcome[] = ['threat', 'review'];

export const OUTCOME_TEXT: Record<Outcome, { short: string; long: string }> = {
  threat: { short: 'Likely malicious', long: 'Needs your decision: likely malicious' },
  review: { short: 'Not proven either way', long: 'Needs review: not proven either way' },
};

/** Routing codes under which the analysis judged the alert a threat; every other code left it unproven. */
const THREAT_CODES = new Set(['response_review', 'high_risk', 'complex_attack']);

/** The outcome mark of a row, or null on escalations opened before routing was recorded. */
export function rowOutcome(e: Pick<EscalationOut, 'routing'>): Outcome | null {
  const routing = readRouting(e.routing);
  if (!routing) return null;
  return THREAT_CODES.has(routing.code) ? 'threat' : 'review';
}

function sentence(value: string | null): string | null {
  const s = value?.trim();
  if (!s) return null;
  const capital = s.charAt(0).toUpperCase() + s.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

/** Why the item needs a person (the routing code in plain words, else the recorded reason). */
export function rowReason(e: Pick<EscalationOut, 'routing' | 'reason'>): string | null {
  return routingWhy(e.routing) ?? sentence(text(e.reason));
}

/** The row's secondary text: why it needs a person, then what the analysis concluded. */
export function rowWhy(e: Pick<EscalationOut, 'routing' | 'reason' | 'ai_reason' | 'ai_reason_source'>): string {
  return [rowReason(e), sentence(readAiReason(e)?.text ?? null)].filter(Boolean).join(' ');
}

const SEVERITY_BARS: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Bars lit for a severity (4 for critical down to 0 for info and unknown values). */
export function severityBars(value: string | null | undefined): number {
  return SEVERITY_BARS[value ?? ''] ?? 0;
}

/**
 * The look-alike group a row belongs to (same rule, same source, same
 * finding), or null. Today's API groups by rule only (`GET
 * /escalations/groups`) and puts no group on the row, so this is always null
 * and everything built on it stays hidden; the field names follow the design
 * (docs/design/console-v2/README.md, section 5) and move with the API.
 */
export function lookAlike(e: EscalationOut): { id: string; size: number } | null {
  const raw = e as unknown as { group_id?: unknown; group_size?: unknown };
  const id = text(raw.group_id);
  const size = finite(raw.group_size);
  return id && size !== null && size > 1 ? { id, size } : null;
}

/** The one look-alike group every selected row belongs to, or null (bulk decide is offered only then). */
export function sharedLookAlike(rows: readonly EscalationOut[]): { id: string; size: number } | null {
  const first = rows.length ? lookAlike(rows[0]) : null;
  if (!first) return null;
  return rows.every((e) => lookAlike(e)?.id === first.id) ? first : null;
}

// Views --------------------------------------------------------------------------

export const VIEW_IDS = ['all', 'mine', 'unassigned', 'soon', 'threat', 'alike'] as const;
export type ViewId = (typeof VIEW_IDS)[number];

export const VIEW_LABELS: Record<ViewId, string> = {
  all: 'Needs a person',
  mine: 'Mine',
  unassigned: 'Unassigned',
  soon: 'Deadline under 15 min',
  threat: 'Likely malicious',
  alike: 'Look-alikes',
};

/** Views the API narrows itself (complete however long the queue is); the others filter the loaded rows. */
export const VIEW_ASSIGNED: Partial<Record<ViewId, 'me' | 'none'>> = { mine: 'me', unassigned: 'none' };

export interface ViewContext {
  userId: string | null;
  now: number;
}

const VIEW_TESTS: Record<ViewId, (e: EscalationOut, ctx: ViewContext) => boolean> = {
  all: () => true,
  mine: (e, ctx) => Boolean(ctx.userId) && e.assigned_to === ctx.userId,
  unassigned: (e) => !e.assigned_to,
  soon: (e, ctx) => {
    const { seconds } = dueIn(e.sla_deadline, ctx.now);
    return seconds !== null && seconds < VIEW_SOON_S;
  },
  threat: (e) => rowOutcome(e) === 'threat',
  alike: (e) => lookAlike(e) !== null,
};

export function inView(view: ViewId, e: EscalationOut, ctx: ViewContext): boolean {
  return VIEW_TESTS[view](e, ctx);
}

/** The chips over the table: both filter the rows already loaded. */
export interface RowFilters {
  severity: readonly string[];
  outcome: readonly string[];
}

export function matchesFilters(e: EscalationOut, filters: RowFilters): boolean {
  if (filters.severity.length && !filters.severity.includes(escalationSeverity(e) ?? '')) return false;
  if (filters.outcome.length && !filters.outcome.includes(rowOutcome(e) ?? '')) return false;
  return true;
}

/** A tab's count: `more` when rows not loaded yet may add to it ("50+"). */
export interface ViewCount {
  n: number;
  more: boolean;
}

export function countText(c: ViewCount): string {
  return c.more ? `${c.n}+` : String(c.n);
}

/**
 * What each view holds, counted over the loaded queue. With the whole queue
 * loaded every count is exact. With more rows on the server, Mine and
 * Unassigned use the dashboard's figures when it sent them, and the others
 * say "at least" (the soonest deadlines load first, so "Deadline under 15
 * min" is exact unless every loaded row is that close).
 */
export function viewCounts(rows: readonly EscalationOut[], complete: boolean, figures: QueueFigures | null, ctx: ViewContext): Record<ViewId, ViewCount> {
  const count = (view: ViewId) => rows.filter((e) => inView(view, e, ctx)).length;
  const last = rows[rows.length - 1];
  const exact = (n: number): ViewCount => ({ n, more: false });
  const atLeast = (view: ViewId): ViewCount => ({ n: count(view), more: !complete });
  // The dashboard's figure, unless it lags behind what is already loaded (it is cached for a few seconds).
  const fromDashboard = (view: ViewId, figure: number | undefined): ViewCount => (!complete && figure !== undefined && figure >= count(view) ? exact(figure) : atLeast(view));
  return {
    all: atLeast('all'),
    mine: fromDashboard('mine', figures?.myClaimed),
    unassigned: fromDashboard('unassigned', figures?.unassigned),
    soon: { n: count('soon'), more: !complete && Boolean(last) && inView('soon', last, ctx) },
    threat: atLeast('threat'),
    alike: atLeast('alike'),
  };
}

/** "28 items need a person. 2 are past their deadline and 3 pass it in the next 10 minutes." */
export function leadSentence(rows: readonly EscalationOut[], total: ViewCount, now: number): string {
  if (total.n === 0) return 'Nothing needs a person right now.';
  const states = rows.map((e) => dueIn(e.sla_deadline, now).state);
  const overdue = states.filter((s) => s === 'overdue').length;
  const soon = states.filter((s) => s === 'soon').length;
  const items = `${total.more ? `More than ${total.n}` : total.n} ${total.n === 1 && !total.more ? 'item needs' : 'items need'} a person.`;
  const is = (n: number) => (n === 1 ? 'is' : 'are');
  const passes = (n: number) => (n === 1 ? 'passes' : 'pass');
  if (overdue && soon) return `${items} ${overdue} ${is(overdue)} past the deadline and ${soon} ${passes(soon)} it in the next 10 minutes.`;
  if (overdue) return `${items} ${overdue} ${is(overdue)} past the deadline.`;
  if (soon) return `${items} ${soon} ${passes(soon)} the deadline in the next 10 minutes.`;
  return `${items} No deadline in the next 10 minutes.`;
}

// Density and saved views (kept per user in the browser) ---------------------------

export const DENSITIES = ['dense', 'compact', 'relaxed'] as const;
export type QueueDensity = (typeof DENSITIES)[number];

export const DENSITY_LABELS: Record<QueueDensity, string> = { dense: 'Dense', compact: 'Compact', relaxed: 'Two lines' };

/** Row height per density (px); a stacked record on a narrow screen has its own. */
export const ROW_HEIGHT: Record<QueueDensity, number> = { dense: 24, compact: 28, relaxed: 44 };
export const STACKED_ROW_HEIGHT = 92;

export function parseQueueDensity(value: string | null | undefined): QueueDensity {
  return (DENSITIES as readonly string[]).includes(value ?? '') ? (value as QueueDensity) : 'compact';
}

/** A view a user saved: a built-in view plus the chips and the density in force when it was saved. */
export interface SavedView {
  id: string;
  name: string;
  base: ViewId;
  severity: string[];
  outcome: string[];
  density: QueueDensity;
}

export const SAVED_VIEWS_MAX = 8;
export const SAVED_VIEW_NAME_MAX = 40;

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v.length <= 40).slice(0, 10) : [];
}

/** The saved views in a stored value; anything malformed is dropped (storage is not trusted). */
export function parseSavedViews(raw: string | null | undefined): SavedView[] {
  if (!raw) return [];
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  const out: SavedView[] = [];
  for (const item of data) {
    if (!item || typeof item !== 'object') continue;
    const v = item as Record<string, unknown>;
    const id = text(v.id);
    const name = text(v.name)?.trim().slice(0, SAVED_VIEW_NAME_MAX);
    if (!id || !/^s-[a-z0-9]{1,24}$/.test(id) || !name || !(VIEW_IDS as readonly unknown[]).includes(v.base)) continue;
    if (out.some((o) => o.id === id)) continue;
    out.push({ id, name, base: v.base as ViewId, severity: strings(v.severity), outcome: strings(v.outcome), density: parseQueueDensity(text(v.density)) });
    if (out.length >= SAVED_VIEWS_MAX) break;
  }
  return out;
}

/** What the URL asks for: a built-in view with chips, or a saved view (whose chips win). */
export interface ActiveView {
  /** The selected tab: a built-in view id or a saved view id. */
  tab: string;
  base: ViewId;
  filters: RowFilters;
  saved: SavedView | null;
}

export function activeView(params: URLSearchParams, saved: readonly SavedView[]): ActiveView {
  const view = params.get('view') ?? '';
  const hit = saved.find((s) => s.id === view);
  if (hit) return { tab: hit.id, base: hit.base, filters: { severity: hit.severity, outcome: hit.outcome }, saved: hit };
  const base = (VIEW_IDS as readonly string[]).includes(view) ? (view as ViewId) : 'all';
  return { tab: base, base, filters: { severity: params.getAll('severity').filter(Boolean), outcome: params.getAll('outcome').filter(Boolean) }, saved: null };
}

/** The URL parameters of a view (the default view with no chip has none). */
export function viewSearch(view: string, filters: RowFilters = { severity: [], outcome: [] }): URLSearchParams {
  const params = new URLSearchParams();
  if (view !== 'all') params.set('view', view);
  for (const s of filters.severity) params.append('severity', s);
  for (const o of filters.outcome) params.append('outcome', o);
  return params;
}
