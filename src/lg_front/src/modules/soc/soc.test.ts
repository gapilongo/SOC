import { describe, expect, it } from 'vitest';

import { soc } from './index';
import { navCounts } from './navCounts';

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
