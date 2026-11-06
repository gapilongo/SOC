import { describe, expect, it } from 'vitest';

import { qk } from './queryKeys';

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

  it('keeps the literal keys the pages used before', () => {
    const filters = { status: ['queued'] };
    expect(qk.alerts.list(filters)).toEqual(['alerts', filters]);
    expect(qk.alert.detail('a-1')).toEqual(['alert', 'a-1']);
    expect(qk.alert.events('a-1')).toEqual(['alert', 'a-1', 'events']);
    expect(qk.escalations.list(filters)).toEqual(['escalations', filters]);
    expect(qk.actions.list({ alert_id: 'a-1' })).toEqual(['actions', { alert_id: 'a-1' }]);
    expect(qk.tickets.forAlert('a-1')).toEqual(['tickets', 'alert', 'a-1']);
    expect(qk.tickets.forEscalations(['e-1', 'e-2'])).toEqual(['tickets', 'escalations', ['e-1', 'e-2']]);
    expect(qk.dashboard.summary(24)).toEqual(['dashboard', 24]);
    expect(qk.sources.all).toEqual(['sources']);
    expect(qk.suppressions.includingDisabled).toEqual(['suppressions', 'all']);
    expect(qk.users.list(true)).toEqual(['users', true]);
    expect(qk.apiKeys.list(false)).toEqual(['api-keys', false]);
    expect(qk.mfaStatus.all).toEqual(['mfa-status']);
    expect(qk.onboarding.all).toEqual(['onboarding-status']);
    expect(qk.tenantSettings.all).toEqual(['tenant-settings']);
    expect(qk.responseRoutes.forSettings('2026-10-01T00:00:00Z')).toEqual(['response-routes', '2026-10-01T00:00:00Z']);
    expect(qk.integrations.all).toEqual(['integrations']);
    expect(qk.integrations.deliveries('i-1')).toEqual(['integrations', 'i-1', 'deliveries']);
    expect(qk.microsoftCatalog.all).toEqual(['microsoft-catalog']);
    expect(qk.audit.list({ action: 'login' })).toEqual(['audit', { action: 'login' }]);
    expect(qk.usage.range('2026-10-01', '2026-10-31')).toEqual(['usage', '2026-10-01', '2026-10-31']);
    expect(qk.reportValue.range('a', 'b')).toEqual(['report-value', 'a', 'b']);
    expect(qk.reportAccuracy.range('a', 'b')).toEqual(['report-accuracy', 'a', 'b']);
    expect(qk.reportDetections.range('a', 'b')).toEqual(['report-detections', 'a', 'b']);
    expect(qk.reportMonthly.month('2026-10')).toEqual(['report-monthly', '2026-10']);
    expect(qk.platformTenants.all).toEqual(['platform-tenants']);
    expect(qk.platformEscalations.list('')).toEqual(['platform-escalations', '']);
    expect(qk.platformUsage.month('2026-10')).toEqual(['platform-usage', '2026-10']);
  });
});
