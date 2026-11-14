import { describe, expect, it } from 'vitest';

import type { QueueFigures } from '../../api/fields';
import type { EscalationOut } from '../../api/types';
import { routingLabel, routingWhy } from '../escalations/labels';
import {
  BASE_FILTERS,
  activeView,
  assignedFilters,
  countText,
  dueIn,
  inView,
  leadSentence,
  lookAlike,
  matchesFilters,
  parseQueueDensity,
  parseSavedViews,
  rowOutcome,
  rowReason,
  rowWhy,
  severityBars,
  sharedLookAlike,
  viewCounts,
  viewSearch,
} from './model';

const NOW = Date.parse('2026-11-14T10:04:00Z');
const at = (seconds: number) => new Date(NOW + seconds * 1000).toISOString();

function escalation(id: string, overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `alert-${id}`,
    level: 'L1',
    status: 'open',
    reason: 'assessment in the grey zone',
    priority: 50,
    summary: { title: `Item ${id}` },
    assigned_to: null,
    sla_deadline: at(3_600),
    version: 1,
    created_at: at(-600),
    updated_at: at(-600),
    ...overrides,
  };
}

const figures = (overrides: Partial<QueueFigures> = {}): QueueFigures => ({
  overdue: 0,
  unassigned: 0,
  unassignedBreaching: 0,
  nextSlaDeadline: null,
  openBySeverity: {},
  pendingTotal: 0,
  pendingByRisk: {},
  pendingMine: 0,
  myClaimed: 0,
  ...overrides,
});

describe('the queue list', () => {
  it('is the Escalations page list: waiting statuses, soonest deadline first', () => {
    expect(BASE_FILTERS).toMatchObject({ status: ['open', 'claimed', 'expired'], order: 'sla_deadline' });
    expect(assignedFilters('me')).toMatchObject({ assigned_to: 'me', order: 'sla_deadline' });
    expect(assignedFilters('none')).toMatchObject({ assigned_to: 'none' });
  });
});

describe('deadlines', () => {
  it('reads as a clock under an hour, then hours and days', () => {
    expect(dueIn(at(252), NOW)).toMatchObject({ state: 'soon', text: '04:12', label: 'Due in 4m 12s, soon' });
    expect(dueIn(at(700), NOW)).toMatchObject({ state: 'ok', text: '11:40', label: 'Due in 11m 40s' });
    expect(dueIn(at(3_900), NOW)).toMatchObject({ state: 'ok', text: '1h 05m' });
    expect(dueIn(at(2 * 86_400 + 3 * 3_600), NOW)).toMatchObject({ text: '2d 3h' });
  });

  it('marks an item past its deadline as overdue, in words', () => {
    expect(dueIn(at(-252), NOW)).toEqual({ state: 'overdue', seconds: -252, text: '04:12 over', label: 'Overdue by 4m 12s' });
    expect(dueIn(at(-7_500), NOW).text).toBe('2h 05m over');
  });

  it('has no clock without a deadline', () => {
    expect(dueIn(null, NOW)).toEqual({ state: 'none', seconds: null, text: '-', label: 'No deadline' });
    expect(dueIn('not a date', NOW).state).toBe('none');
  });
});

describe('why a row needs a person', () => {
  it('maps every routing code to plain words in one table', () => {
    for (const code of ['grey_zone', 'false_positive_review', 'inconclusive', 'model_refused', 'llm_normalized', 'analyst_request', 'response_review', 'group_review', 'blind_audit', 'high_risk']) {
      expect(routingWhy({ code }), code).toMatch(/^[A-Z].*\.$/);
    }
    expect(routingWhy({ code: 'grey_zone' })).toBe('Not proven either way: the assessed threat is in the grey zone.');
    expect(routingWhy({ code: 'new_code' })).toBe('Needs a person: new code.');
    expect(routingWhy(null)).toBeNull();
    expect(routingLabel('high_risk')).toBe('High risk');
  });

  it('puts the reason first, then what the analysis concluded', () => {
    const e = escalation('a', { routing: { code: 'false_positive_review' }, ai_reason: 'A scheduled backup started the tool', ai_reason_source: 'model' });
    expect(rowWhy(e)).toBe('Probably harmless, but the AI may not close it without a person. A scheduled backup started the tool.');
    // Before routing was recorded: the escalation's own reason, as a sentence.
    expect(rowReason(escalation('b'))).toBe('Assessment in the grey zone.');
    expect(rowWhy(escalation('b'))).toBe('Assessment in the grey zone.');
  });

  it('derives the outcome mark from the routing code', () => {
    expect(rowOutcome(escalation('a', { routing: { code: 'response_review' } }))).toBe('threat');
    expect(rowOutcome(escalation('a', { routing: { code: 'grey_zone', confidence: 42 } }))).toBe('review');
    expect(rowOutcome(escalation('a', { routing: { code: 'blind_audit' } }))).toBe('review');
    expect(rowOutcome(escalation('a'))).toBeNull();
  });

  it('lights one bar per severity step', () => {
    expect(['critical', 'high', 'medium', 'low', 'info', 'odd', null].map(severityBars)).toEqual([4, 3, 2, 1, 0, 0, 0]);
  });
});

describe('look-alikes', () => {
  const grouped = (id: string, group: string, size = 3) => ({ ...escalation(id), group_id: group, group_size: size }) as EscalationOut;

  it("are absent from today's rows, so nothing is grouped", () => {
    expect(lookAlike(escalation('a', { rule: 'Same rule', source_id: 's-1' }))).toBeNull();
    expect(sharedLookAlike([escalation('a'), escalation('b')])).toBeNull();
    expect(inView('alike', escalation('a'), { userId: 'u-1', now: NOW })).toBe(false);
  });

  it('are read from the row once the API sends a group, and bulk decide needs one shared group', () => {
    expect(lookAlike(grouped('a', 'g-1', 9))).toEqual({ id: 'g-1', size: 9 });
    expect(lookAlike(grouped('a', 'g-1', 1))).toBeNull();
    expect(sharedLookAlike([grouped('a', 'g-1'), grouped('b', 'g-1')])).toEqual({ id: 'g-1', size: 3 });
    expect(sharedLookAlike([grouped('a', 'g-1'), grouped('b', 'g-2')])).toBeNull();
    expect(sharedLookAlike([grouped('a', 'g-1'), escalation('c')])).toBeNull();
    expect(sharedLookAlike([])).toBeNull();
  });
});

describe('views and their counts', () => {
  const ctx = { userId: 'u-1', now: NOW };
  const rows = [
    escalation('a', { sla_deadline: at(-60), assigned_to: 'u-1', alert_severity: 'critical', routing: { code: 'response_review' } }),
    escalation('b', { sla_deadline: at(300), alert_severity: 'high', routing: { code: 'grey_zone' } }),
    escalation('c', { sla_deadline: at(800), assigned_to: 'u-2', alert_severity: 'high' }),
    escalation('d', { sla_deadline: at(4_000), alert_severity: 'low', routing: { code: 'high_risk' } }),
  ];

  it('filters rows by view', () => {
    const ids = (view: Parameters<typeof inView>[0]) => rows.filter((e) => inView(view, e, ctx)).map((e) => e.id);
    expect(ids('all')).toEqual(['a', 'b', 'c', 'd']);
    expect(ids('mine')).toEqual(['a']);
    expect(ids('unassigned')).toEqual(['b', 'd']);
    expect(ids('soon')).toEqual(['a', 'b', 'c']);
    expect(ids('threat')).toEqual(['a', 'd']);
    expect(rows.filter((e) => inView('mine', e, { userId: null, now: NOW }))).toEqual([]);
  });

  it('filters rows by the severity and outcome chips', () => {
    const ids = (severity: string[], outcome: string[]) => rows.filter((e) => matchesFilters(e, { severity, outcome })).map((e) => e.id);
    expect(ids([], [])).toEqual(['a', 'b', 'c', 'd']);
    expect(ids(['high'], [])).toEqual(['b', 'c']);
    expect(ids(['high', 'critical'], ['threat'])).toEqual(['a']);
    expect(ids([], ['review'])).toEqual(['b']);
  });

  it('counts exactly when the whole queue is loaded', () => {
    const counts = viewCounts(rows, true, figures({ myClaimed: 9 }), ctx);
    expect(Object.fromEntries(Object.entries(counts).map(([k, c]) => [k, countText(c)]))).toEqual({ all: '4', mine: '1', unassigned: '2', soon: '3', threat: '2', alike: '0' });
  });

  it('says "at least" while more rows are on the server, and uses the dashboard for Mine and Unassigned', () => {
    const counts = viewCounts(rows, false, figures({ myClaimed: 7, unassigned: 61 }), ctx);
    expect(countText(counts.all)).toBe('4+');
    expect(countText(counts.mine)).toBe('7');
    expect(countText(counts.unassigned)).toBe('61');
    // The soonest deadlines load first: the last loaded row is far off, so the count is complete.
    expect(countText(counts.soon)).toBe('3');
    expect(countText(counts.threat)).toBe('2+');
    expect(countText(viewCounts(rows.slice(0, 3), false, null, ctx).soon)).toBe('3+');
    expect(countText(viewCounts(rows, false, null, ctx).mine)).toBe('1+');
    // A dashboard figure behind the rows already loaded is not shown.
    expect(countText(viewCounts(rows, false, figures({ myClaimed: 0, unassigned: 1 }), ctx).unassigned)).toBe('2+');
  });

  it('opens the page with how many items need a person and how many deadlines are near', () => {
    const total = (n: number, more = false) => ({ n, more });
    expect(leadSentence(rows, total(4), NOW)).toBe('4 items need a person. 1 is past the deadline and 1 passes it in the next 10 minutes.');
    expect(leadSentence(rows.slice(1), total(3), NOW)).toBe('3 items need a person. 1 passes the deadline in the next 10 minutes.');
    expect(leadSentence(rows.slice(0, 1), total(1), NOW)).toBe('1 item needs a person. 1 is past the deadline.');
    expect(leadSentence(rows.slice(3), total(50, true), NOW)).toBe('More than 50 items need a person. No deadline in the next 10 minutes.');
    expect(leadSentence([], total(0), NOW)).toBe('Nothing needs a person right now.');
  });
});

describe('density and saved views', () => {
  it('falls back to compact', () => {
    expect(['dense', 'compact', 'relaxed', 'huge', null].map(parseQueueDensity)).toEqual(['dense', 'compact', 'relaxed', 'compact', 'compact']);
  });

  it('keeps well-formed saved views and drops the rest', () => {
    const good = { id: 's-abc1', name: ' Critical, mine ', base: 'mine', severity: ['critical'], outcome: [], density: 'dense' };
    const raw = JSON.stringify([good, { id: 'x', name: 'bad id', base: 'all' }, { id: 's-2', name: '', base: 'all' }, { id: 's-3', name: 'bad base', base: 'everything' }, good, 'text', null]);
    expect(parseSavedViews(raw)).toEqual([{ id: 's-abc1', name: 'Critical, mine', base: 'mine', severity: ['critical'], outcome: [], density: 'dense' }]);
    expect(parseSavedViews('{not json')).toEqual([]);
    expect(parseSavedViews('{"a":1}')).toEqual([]);
    expect(parseSavedViews(null)).toEqual([]);
    const many = Array.from({ length: 20 }, (_, i) => ({ id: `s-${i}`, name: `View ${i}`, base: 'all' }));
    expect(parseSavedViews(JSON.stringify(many))).toHaveLength(8);
  });

  it('reads the view and chips from the URL, and a saved view by its id', () => {
    const saved = parseSavedViews(JSON.stringify([{ id: 's-1', name: 'Hot', base: 'unassigned', severity: ['critical', 'high'], outcome: ['threat'], density: 'relaxed' }]));
    expect(activeView(new URLSearchParams(''), saved)).toEqual({ tab: 'all', base: 'all', filters: { severity: [], outcome: [] }, saved: null });
    expect(activeView(new URLSearchParams('view=soon&severity=high&outcome=review'), saved)).toMatchObject({ tab: 'soon', base: 'soon', filters: { severity: ['high'], outcome: ['review'] } });
    expect(activeView(new URLSearchParams('view=nope'), saved).tab).toBe('all');
    expect(activeView(new URLSearchParams('view=s-1&severity=low'), saved)).toMatchObject({ tab: 's-1', base: 'unassigned', filters: { severity: ['critical', 'high'], outcome: ['threat'] }, saved: saved[0] });
    expect(viewSearch('all').toString()).toBe('');
    expect(viewSearch('mine', { severity: ['high'], outcome: ['threat'] }).toString()).toBe('view=mine&severity=high&outcome=threat');
  });
});
