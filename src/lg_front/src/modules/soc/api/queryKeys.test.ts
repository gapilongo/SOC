import { describe, expect, it } from 'vitest';

import { NS, qk } from './queryKeys';

type Group = { all: readonly unknown[] } & Record<string, unknown>;

/** Every key factory of every group, called with placeholder arguments. */
function derivedKeys(): Array<[string, readonly unknown[], readonly unknown[]]> {
  const out: Array<[string, readonly unknown[], readonly unknown[]]> = [];
  for (const [name, group] of Object.entries(qk as unknown as Record<string, Group>)) {
    for (const [member, value] of Object.entries(group)) {
      if (member === 'all') continue;
      const key = typeof value === 'function' ? (value as (...args: unknown[]) => readonly unknown[])('arg-1', 'arg-2') : (value as readonly unknown[]);
      out.push([`${name}.${member}`, group.all, key]);
    }
  }
  return out;
}

describe('query keys', () => {
  it('has one all-key per group, distinct from every other group', () => {
    const heads = Object.values(qk as unknown as Record<string, Group>).map((g) => JSON.stringify(g.all));
    expect(new Set(heads).size).toBe(heads.length);
    for (const g of Object.values(qk as unknown as Record<string, Group>)) expect(g.all.length).toBeGreaterThan(0);
  });

  it.each(derivedKeys())('%s starts with its group key', (_name, all, key) => {
    expect(key.slice(0, all.length)).toEqual([...all]);
    expect(key.length).toBeGreaterThan(all.length);
  });

  it.each(derivedKeys())('%s starts with the module id', (_name, all, key) => {
    expect(all[0]).toBe(NS);
    expect(key[0]).toBe(NS);
  });

  it('keeps the literal keys the pages used before, under the module id', () => {
    const filters = { status: ['queued'] };
    expect(qk.alerts.list(filters)).toEqual(['soc', 'alerts', filters]);
    expect(qk.alert.detail('a-1')).toEqual(['soc', 'alert', 'a-1']);
    expect(qk.alert.events('a-1')).toEqual(['soc', 'alert', 'a-1', 'events']);
    expect(qk.escalations.list(filters)).toEqual(['soc', 'escalations', filters]);
    expect(qk.actions.list({ alert_id: 'a-1' })).toEqual(['soc', 'actions', { alert_id: 'a-1' }]);
    expect(qk.tickets.forAlert('a-1')).toEqual(['soc', 'tickets', 'alert', 'a-1']);
    expect(qk.tickets.forEscalations(['e-1', 'e-2'])).toEqual(['soc', 'tickets', 'escalations', ['e-1', 'e-2']]);
    expect(qk.dashboard.summary(24)).toEqual(['soc', 'dashboard', 24]);
    expect(qk.sources.all).toEqual(['soc', 'sources']);
    expect(qk.suppressions.includingDisabled).toEqual(['soc', 'suppressions', 'all']);
    expect(qk.users.list(true)).toEqual(['soc', 'users', true]);
    expect(qk.apiKeys.list(false)).toEqual(['soc', 'api-keys', false]);
    expect(qk.mfaStatus.all).toEqual(['soc', 'mfa-status']);
    expect(qk.onboarding.all).toEqual(['soc', 'onboarding-status']);
    expect(qk.tenantSettings.all).toEqual(['soc', 'tenant-settings']);
    expect(qk.responseRoutes.forSettings('2026-10-01T00:00:00Z')).toEqual(['soc', 'response-routes', '2026-10-01T00:00:00Z']);
    expect(qk.integrations.all).toEqual(['soc', 'integrations']);
    expect(qk.integrations.deliveries('i-1')).toEqual(['soc', 'integrations', 'i-1', 'deliveries']);
    expect(qk.microsoftCatalog.all).toEqual(['soc', 'microsoft-catalog']);
    expect(qk.audit.list({ action: 'login' })).toEqual(['soc', 'audit', { action: 'login' }]);
    expect(qk.usage.range('2026-10-01', '2026-10-31')).toEqual(['soc', 'usage', '2026-10-01', '2026-10-31']);
    expect(qk.reportValue.range('a', 'b')).toEqual(['soc', 'report-value', 'a', 'b']);
    expect(qk.reportAccuracy.range('a', 'b')).toEqual(['soc', 'report-accuracy', 'a', 'b']);
    expect(qk.reportDetections.range('a', 'b')).toEqual(['soc', 'report-detections', 'a', 'b']);
    expect(qk.reportMonthly.month('2026-10')).toEqual(['soc', 'report-monthly', '2026-10']);
    expect(qk.platformTenants.all).toEqual(['soc', 'platform-tenants']);
    expect(qk.platformEscalations.list('')).toEqual(['soc', 'platform-escalations', '']);
    expect(qk.platformUsage.month('2026-10')).toEqual(['soc', 'platform-usage', '2026-10']);
  });

  it('keeps the console redesign keys under the groups their events invalidate', () => {
    expect(qk.alerts.counts({})).toEqual(['soc', 'alerts', 'counts', {}]);
    expect(qk.escalations.top({ assigned_to: 'me' }, 3)).toEqual(['soc', 'escalations', 'top', { assigned_to: 'me' }, 3]);
    expect(qk.escalations.groups({ min_size: 2 })).toEqual(['soc', 'escalations', 'groups', { min_size: 2 }]);
    expect(qk.escalation.detail('e-1')).toEqual(['soc', 'escalation', 'e-1']);
    expect(qk.escalation.responsePreview('e-1')).toEqual(['soc', 'escalation', 'e-1', 'response-preview']);
  });
});
