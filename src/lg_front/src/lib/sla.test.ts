import { describe, expect, it } from 'vitest';

import { escalationHref, escalationQueueHref, alertsHref } from './links';
import { slaLabel, slaStatus } from './sla';

const NOW = Date.parse('2026-11-06T12:00:00Z');
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString();

describe('slaStatus', () => {
  it('has no state without a valid deadline', () => {
    expect(slaStatus(null, NOW)).toEqual({ state: 'none', seconds: null, text: 'No SLA' });
    expect(slaStatus('not a date', NOW).state).toBe('none');
  });

  it('breaches once the deadline has passed', () => {
    const s = slaStatus(at(-134), NOW);
    expect(s).toEqual({ state: 'breaching', seconds: -134 * 60, text: '2h 14m over' });
    expect(slaLabel(s)).toBe('2h 14m over · breaching');
  });

  it('is at risk in the last quarter of its window', () => {
    // A 4-hour window with 50 minutes left: under a quarter.
    const s = slaStatus(at(50), NOW, at(-190));
    expect(s.state).toBe('at_risk');
    expect(slaLabel(s)).toBe('50m 00s left · at risk');
    // The same deadline with 3 of 4 hours left is fine.
    expect(slaStatus(at(180), NOW, at(-60)).state).toBe('ok');
  });

  it('falls back to one hour when the window is unknown', () => {
    expect(slaStatus(at(59), NOW).state).toBe('at_risk');
    expect(slaStatus(at(61), NOW, 'garbage').state).toBe('ok');
    expect(slaLabel(slaStatus(at(61), NOW))).toBe('1h 01m left');
  });
});

describe('links', () => {
  it('builds escalation queue links with the API parameter names', () => {
    expect(escalationQueueHref()).toBe('/escalations');
    expect(escalationQueueHref({ assigned_to: 'none', overdue: true, order: 'sla_deadline' })).toBe(
      '/escalations?assigned_to=none&overdue=true&order=sla_deadline',
    );
    expect(escalationQueueHref({ status: ['open', 'claimed'], overdue: false, rule: 'A & B' })).toBe(
      '/escalations?status=open&status=claimed&rule=A+%26+B',
    );
  });

  it('opens an escalation on its decision page and filters alerts', () => {
    expect(escalationHref({ id: 'e/1' })).toBe('/escalations/e%2F1');
    expect(alertsHref({ severity: 'high', from: '2026-11-05T12:00:00Z', q: undefined })).toBe(
      '/alerts?severity=high&from=2026-11-05T12%3A00%3A00Z',
    );
    expect(alertsHref({})).toBe('/alerts');
  });
});
