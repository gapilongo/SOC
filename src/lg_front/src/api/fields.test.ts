import { describe, expect, it } from 'vitest';

import {
  bulkFailures,
  decidedByLabel,
  escalationOwner,
  escalationSeverity,
  escalationTitle,
  finite,
  formatEntities,
  hiddenEntityCount,
  readAiReason,
  readCounts,
  readEntitiesPreview,
  readFindings,
  readGuardrail,
  readQueueFigures,
  readRouting,
  text,
  toBulkItems,
  totalOf,
} from './fields';
import type { ActionOut, AlertDetailOut, DashboardOut, EscalationOut } from './types';

const preview = {
  items: [
    { kind: 'user', value: 'j.moreau@acme.example' },
    { kind: 'ip', value: '185.220.101.4' },
  ],
  counts: { user: 1, ip: 3 },
};

describe('scalars', () => {
  it('reads non-blank strings and finite numbers only', () => {
    expect(text('a')).toBe('a');
    expect(text('  ')).toBeNull();
    expect(text(3)).toBeNull();
    expect(finite(2.5)).toBe(2.5);
    expect(finite(Number.NaN)).toBeNull();
    expect(finite('2')).toBeNull();
  });

  it('keeps finite non-negative counts', () => {
    expect(readCounts({ a: 1, b: -1, c: 'x', d: 0 })).toEqual({ a: 1, d: 0 });
    expect(readCounts(null)).toEqual({});
    expect(readCounts([1, 2])).toEqual({});
    expect(totalOf({ a: 1, b: 2 })).toBe(3);
  });
});

describe('entities preview', () => {
  it('keeps well-formed items and counts of known kinds', () => {
    expect(
      readEntitiesPreview({
        items: [...preview.items, { kind: 'planet', value: 'x' }, { kind: 'host', value: '' }, 'junk'],
        counts: { ...preview.counts, planet: 2, host: 'many' },
      }),
    ).toEqual(preview);
  });

  it('is null when absent, empty or malformed', () => {
    expect(readEntitiesPreview(null)).toBeNull();
    expect(readEntitiesPreview(undefined)).toBeNull();
    expect(readEntitiesPreview({ items: [], counts: {} })).toBeNull();
    expect(readEntitiesPreview({ items: 'x', counts: 4 })).toBeNull();
  });

  it('counts the values it does not show and formats a line', () => {
    expect(hiddenEntityCount(readEntitiesPreview(preview))).toBe(2);
    expect(hiddenEntityCount(null)).toBe(0);
    expect(formatEntities(preview)).toBe('j.moreau@acme.example · 185.220.101.4 · +2 more');
    expect(formatEntities(preview, 1)).toBe('j.moreau@acme.example · +3 more');
    expect(formatEntities({ items: [{ kind: 'host', value: 'WS-0142' }], counts: { host: 1 } })).toBe('WS-0142');
    expect(formatEntities(null)).toBe('');
    expect(formatEntities({ items: [], counts: { host: 2 } })).toBe('');
  });
});

describe('escalation fields', () => {
  const base = { summary: {}, rule: null } as Pick<EscalationOut, 'summary' | 'rule'>;

  it('reads routing defensively (null before it was recorded)', () => {
    expect(readRouting(null)).toBeNull();
    expect(readRouting({ confidence: 40 })).toBeNull();
    expect(readRouting({ code: 'grey_zone', confidence: 42, band: { min: 30, max: 70 } })).toEqual({
      code: 'grey_zone',
      confidence: 42,
      band: { min: 30, max: 70 },
    });
    expect(readRouting({ code: 'model_refused', confidence: 'high', band: { min: 30 } })).toEqual({
      code: 'model_refused',
      confidence: null,
      band: null,
    });
  });

  it('reads the AI reason with a known source or none', () => {
    expect(readAiReason({ ai_reason: 'TOR sign-in after a Lyon login.', ai_reason_source: 'model' })).toEqual({
      text: 'TOR sign-in after a Lyon login.',
      source: 'model',
    });
    expect(readAiReason({ ai_reason: 'Rule matched.', ai_reason_source: null })).toEqual({ text: 'Rule matched.', source: null });
    expect(readAiReason({ ai_reason: 'x', ai_reason_source: 'oracle' as never })?.source).toBeNull();
    expect(readAiReason({ ai_reason: null })).toBeNull();
  });

  it('titles from the summary, else the rule, else a placeholder', () => {
    expect(escalationTitle({ ...base, summary: { title: 'Impossible travel' }, rule: 'R1' })).toBe('Impossible travel');
    expect(escalationTitle({ ...base, rule: 'Password spray' })).toBe('Password spray');
    expect(escalationTitle(base)).toBe('Untitled alert');
  });

  it('prefers the alert severity over the summary', () => {
    expect(escalationSeverity({ alert_severity: 'high', summary: { severity: 'low' } })).toBe('high');
    expect(escalationSeverity({ alert_severity: null, summary: { severity: 'low' } })).toBe('low');
    expect(escalationSeverity({})).toBeNull();
  });

  it('labels owners and deciders', () => {
    expect(escalationOwner({ assigned_to: null }, 'u-1')).toEqual({ kind: 'none', label: 'Unassigned' });
    expect(escalationOwner({ assigned_to: 'u-1' }, 'u-1')).toEqual({ kind: 'you', label: 'You' });
    expect(escalationOwner({ assigned_to: 'u-2', assigned_to_email: 'n.haddad@acme.example' }, 'u-1')).toEqual({
      kind: 'other',
      label: 'n.haddad@acme.example',
    });
    expect(escalationOwner({ assigned_to: '0123456789abcdef' }, null).label).toBe('01234567...');
    expect(decidedByLabel({ decided_by: null }, 'u-1')).toBeNull();
    expect(decidedByLabel({ decided_by: 'u-1' }, 'u-1')).toBe('You');
    expect(decidedByLabel({ decided_by: 'u-2', decided_by_email: 'lead@acme.example' }, 'u-1')).toBe('lead@acme.example');
  });
});

describe('alert and action fields', () => {
  it('drops malformed findings', () => {
    const good = { origin: 'threat_intel', kind: 'ip', target: '185.220.101.4', source: 'abuseipdb', status: 'ok', verdict: 'malicious' };
    expect(readFindings({ findings: [good, { origin: 'other', kind: 'x', source: 'y' }, null] } as unknown as AlertDetailOut)).toEqual([good]);
    expect(readFindings({})).toEqual([]);
  });

  it('reads a guardrail verdict', () => {
    expect(readGuardrail({ guardrail: null })).toBeNull();
    expect(readGuardrail({ guardrail: { verdict: 'maybe' } } as unknown as ActionOut)).toBeNull();
    expect(readGuardrail({ guardrail: { verdict: 'blocked', evaluated: 'recorded', code: 'cap_reached', reason: 'Hourly cap' } })).toEqual({
      verdict: 'blocked',
      evaluated: 'recorded',
      code: 'cap_reached',
      reason: 'Hourly cap',
      approval_reason: null,
    });
    expect(readGuardrail({ guardrail: { verdict: 'passed', evaluated: 'now', approval_reason: 'llm_only_evidence' } })?.approval_reason).toBe(
      'llm_only_evidence',
    );
  });
});

describe('bulk helpers', () => {
  it('builds items once each, in order, and refuses more than the API takes', () => {
    expect(toBulkItems([{ id: 'e-1', version: 2 }, { id: 'e-2', version: 1 }, { id: 'e-1', version: 2 }])).toEqual([
      { escalation_id: 'e-1', version: 2 },
      { escalation_id: 'e-2', version: 1 },
    ]);
    const many = Array.from({ length: 51 }, (_, i) => ({ id: `e-${i}`, version: 1 }));
    expect(() => toBulkItems(many)).toThrow(RangeError);
  });

  it('lists the failed items with their errors', () => {
    expect(
      bulkFailures({
        succeeded: 1,
        failed: 2,
        results: [
          { escalation_id: 'e-1', ok: true },
          { escalation_id: 'e-2', ok: false, error: { status: 409, code: 'conflict', message: 'Changed meanwhile.' } },
          { escalation_id: 'e-3', ok: false, error: null },
        ],
      }),
    ).toEqual([
      { escalationId: 'e-2', status: 409, code: 'conflict', message: 'Changed meanwhile.' },
      { escalationId: 'e-3', status: 0, code: 'unknown', message: 'This escalation could not be updated.' },
    ]);
  });
});

describe('queue figures', () => {
  const older = { open_escalations: 3 } as DashboardOut;

  it('is null on an API that predates them', () => {
    expect(readQueueFigures(undefined)).toBeNull();
    expect(readQueueFigures(older)).toBeNull();
  });

  it('reads the figures with defaults for the missing ones', () => {
    expect(readQueueFigures({ ...older, unassigned_escalations: 4 })).toEqual({
      overdue: 0,
      unassigned: 4,
      unassignedBreaching: 0,
      nextSlaDeadline: null,
      openBySeverity: {},
      pendingTotal: 0,
      pendingByRisk: {},
      pendingMine: 0,
      myClaimed: 0,
    });
    expect(
      readQueueFigures({
        ...older,
        unassigned_escalations: 4,
        overdue_escalations: 2,
        unassigned_breaching: 1,
        next_sla_deadline: '2026-11-06T13:00:00Z',
        open_escalations_by_severity: { high: 2 },
        pending_approvals_total: 2,
        pending_approvals_by_risk: { medium: 1, high: 1 },
        pending_approvals: 1,
        my_claimed: 3,
      }),
    ).toMatchObject({ overdue: 2, unassignedBreaching: 1, nextSlaDeadline: '2026-11-06T13:00:00Z', pendingMine: 1, myClaimed: 3 });
  });
});
