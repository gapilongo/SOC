import { describe, expect, it } from 'vitest';

import { fakeApi } from '../../test/helpers';
import type { SourceOut } from './api/types';
import { soc } from './index';
import { navCounts } from './navCounts';
import { socNotices } from './notices';
import { alertSearch, socCommands } from './search';

const DASHBOARD = { window_hours: 24, alerts_total: 0, open_escalations: 0, queue_depth: 0 };

describe('SOC nav counts', () => {
  it('reads nav counts defensively from the dashboard summary', () => {
    expect(navCounts(undefined)).toEqual({});
    expect(navCounts('nope')).toEqual({});
    expect(navCounts(DASHBOARD)).toEqual({});
    expect(navCounts({ ...DASHBOARD, unassigned_breaching: 3, pending_approvals: 1 })).toEqual({ unassigned_breaching: 3, pending_approvals: 1 });
    expect(navCounts({ unassigned_breaching: 0, pending_approvals: -1 })).toEqual({});
    expect(navCounts({ unassigned_breaching: '3', pending_approvals: 1.5 })).toEqual({});
    expect(navCounts({ unassigned_breaching: null })).toEqual({});
  });

  it('puts a count on Escalations and Approvals, each with its meaning', () => {
    const counted = soc.routes.filter((r) => r.nav?.count);
    expect(counted.map((r) => r.path)).toEqual(['/escalations', '/approvals']);
    expect(counted[0].nav?.count?.meaning(1)).toBe('unassigned escalation breaching SLA');
    expect(counted[0].nav?.count?.meaning(3)).toBe('unassigned escalations breaching SLA');
    expect(counted[1].nav?.count?.meaning(1)).toBe('action you can approve');
    expect(counted[1].nav?.count?.meaning(2)).toBe('actions you can approve');
  });
});

describe('SOC manifest', () => {
  it('maps live events to the queries they make stale', () => {
    const heads = (type: string) => (soc.liveEvents ?? {})[type].map((key) => key.at(-1));
    expect(heads('alert.updated')).toEqual(['alerts', 'alert', 'dashboard']);
    expect(heads('alert.created')).toEqual(heads('alert.updated'));
    expect(heads('escalation.created')).toContain('escalations');
    expect(heads('escalation.updated')).toEqual(heads('escalation.created'));
    expect(heads('action.updated')).toContain('actions');
  });

  it('takes every route gate from its declared permissions', () => {
    const gates = new Set<unknown>(Object.values(soc.permissions ?? {}));
    for (const route of soc.routes) expect(gates.has(route.allowed), route.path).toBe(true);
  });
});

describe('SOC in the search field', () => {
  it('finds alerts by title through GET /alerts, a few at a time', async () => {
    const { api, calls } = fakeApi(() => ({
      items: [
        { id: 'a 1', title: 'LSASS memory read on WS-FIN-0142', severity: 'critical', status: 'awaiting_approval' },
        { id: 'a-2', title: 'Encoded PowerShell on WS-FIN-0142', severity: 'high', status: 'closed' },
      ],
      next_cursor: 'more',
    }));
    const hits = await alertSearch.find(api, 'ws-fin', new AbortController().signal);
    expect(calls).toEqual([{ method: 'GET', path: '/alerts', body: undefined, query: { q: 'ws-fin', limit: 8 } }]);
    expect(hits).toEqual([
      { id: 'a 1', kind: 'Alert', title: 'LSASS memory read on WS-FIN-0142', detail: 'Critical · Awaiting approval', to: '/alerts/a%201' },
      { id: 'a-2', kind: 'Alert', title: 'Encoded PowerShell on WS-FIN-0142', detail: 'High · Closed', to: '/alerts/a-2' },
    ]);
    expect(alertSearch.label).toBe('Alerts');
    expect(soc.search).toBe(alertSearch);
  });

  it('leads to the alert list for everything that matches, in every status', () => {
    expect(alertSearch.more?.('ws fin')).toEqual({ label: 'All alerts with "ws fin" in the title', to: '/alerts?q=ws+fin&view=all' });
  });

  it('offers commands that are links to pages of the module, each behind a declared permission', () => {
    const paths = new Set(soc.routes.map((r) => r.path));
    const gates = new Set<unknown>(Object.values(soc.permissions ?? {}));
    expect(soc.commands).toBe(socCommands);
    for (const command of socCommands) {
      expect(paths.has(command.to), command.label).toBe(true);
      expect(gates.has(command.allowed), command.label).toBe(true);
      // A link and nothing else: there is no callback that could change data.
      expect(Object.keys(command).sort()).toEqual(['allowed', 'label', 'to']);
    }
  });
});

describe('SOC notices', () => {
  const NOW = Date.parse('2026-11-14T10:04:00Z');
  const source = (overrides: Partial<SourceOut>): SourceOut => ({
    id: 's-1',
    tenant_id: 'acme',
    type: 'wazuh',
    name: 'Wazuh manager',
    enabled: true,
    poll_interval_s: 60,
    health: 'healthy',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  });

  it('reports nothing when nothing needs an act, or when the API does not say', () => {
    expect(socNotices(undefined, undefined, NOW)).toEqual([]);
    expect(socNotices('nope', [], NOW)).toEqual([]);
    expect(socNotices({ overdue_escalations: 0, pending_approvals: 0, next_sla_deadline: null }, [source({})], NOW)).toEqual([]);
    // Read defensively, like the nav counts: a field that is not a positive whole number is no count.
    expect(socNotices({ overdue_escalations: '2', pending_approvals: 1.5, next_sla_deadline: 'not a date' }, undefined, NOW)).toEqual([]);
  });

  it('reports escalations past their deadline and approvals waiting, one or many', () => {
    expect(socNotices({ overdue_escalations: 1, pending_approvals: 1 }, undefined, NOW)).toEqual([
      { id: 'overdue', kind: 'deadline', text: '1 escalation is past its deadline', detail: 'the oldest first', to: '/escalations?overdue=true&order=sla_deadline' },
      { id: 'approvals', kind: 'approval', text: '1 action waits for your approval', to: '/approvals' },
    ]);
    expect(socNotices({ overdue_escalations: 3, pending_approvals: 13 }, undefined, NOW).map((n) => n.text)).toEqual([
      '3 escalations are past their deadline',
      '13 actions wait for your approval',
    ]);
  });

  it('reports the next deadline only when it is about to pass', () => {
    const at = (ms: number) => ({ next_sla_deadline: new Date(NOW + ms).toISOString() });
    expect(socNotices(at(4 * 60_000), undefined, NOW)).toEqual([
      { id: 'next-deadline', kind: 'deadline', text: 'A deadline passes in 4 min', detail: 'the soonest deadline first', to: '/escalations?order=sla_deadline' },
    ]);
    expect(socNotices(at(20_000), undefined, NOW)[0].text).toBe('A deadline passes in 1 min');
    expect(socNotices(at(15 * 60_000), undefined, NOW)).toHaveLength(1);
    // Further away, or already past (that one is counted as overdue).
    expect(socNotices(at(15 * 60_000 + 1), undefined, NOW)).toEqual([]);
    expect(socNotices(at(-1_000), undefined, NOW)).toEqual([]);
    // Who it concerns, when the API says how many near their deadline have no owner.
    expect(socNotices({ ...at(60_000), unassigned_breaching: 1 }, undefined, NOW)[0].detail).toBe('1 escalation near its deadline has no owner');
    expect(socNotices({ ...at(60_000), unassigned_breaching: 2 }, undefined, NOW)[0].detail).toBe('2 escalations near their deadline have no owner');
  });

  it('reports an enabled source the API calls failing or degraded', () => {
    const sources = [
      source({ id: 's-1', health: 'failing' }),
      source({ id: 's-2', name: 'Sentinel', health: 'degraded' }),
      source({ id: 's-3', name: 'Splunk', health: 'healthy' }),
      source({ id: 's-4', name: 'Old QRadar', health: 'failing', enabled: false }),
      source({ id: 's-5', name: 'New source', health: 'unknown' }),
    ];
    expect(socNotices({}, sources, NOW)).toEqual([
      { id: 'source:s-1', kind: 'source', text: 'Source failing: Wazuh manager', detail: 'alerts may be missing', to: '/sources' },
      { id: 'source:s-2', kind: 'source', text: 'Source degraded: Sentinel', detail: 'alerts may be missing', to: '/sources' },
    ]);
  });
});

