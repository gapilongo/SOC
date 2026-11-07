import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { Page, PlatformEscalationOut, TenantSummaryOut } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { tenant } from '../../test/tenants';
import { templateFields } from './CreateTenantTab';
import PlatformPage from './PlatformPage';
import { quotasFromForm, quotaText } from './TenantsTab';

function busyTenant(): TenantSummaryOut {
  return tenant('globex', 'Globex Corp', {
    quotas: { max_alerts_per_day: 1000, max_sources: 5, max_users: null },
    quota_usage: {
      max_alerts_per_day: { used: 1000, limit: 1000 },
      max_sources: { used: 2, limit: 5 },
      max_users: { used: 7, limit: null },
    },
    stats: {
      alerts_24h: 1234,
      alerts_today: 1000,
      last_ingest_at: new Date().toISOString(),
      open_escalations: 4,
      overdue_escalations: 1,
      sla_breaches_24h: 2,
      llm_cost_mtd_usd: '12.5',
      llm_tokens_mtd: 99,
      users: 7,
      sources: 2,
    },
  });
}

describe('MSSP console helpers', () => {
  it('turns quota form values into the API body', () => {
    expect(quotasFromForm({ max_alerts_per_day: '500', max_sources: '', max_users: ' 3 ' })).toEqual({
      max_alerts_per_day: 500,
      max_sources: null,
      max_users: 3,
    });
    expect(quotasFromForm({ max_alerts_per_day: '-1', max_sources: '', max_users: '' })).toBeInstanceOf(Error);
    expect(quotasFromForm({ max_alerts_per_day: '1.5', max_sources: '', max_users: '' })).toBeInstanceOf(Error);
    expect(quotaText(3, null)).toBe('3');
    expect(quotaText(3, 10)).toBe('3 / 10');
  });

  it('maps the initial-settings choice to profile or copy_settings_from', () => {
    expect(templateFields('')).toEqual({});
    expect(templateFields('profile:balanced')).toEqual({ profile: 'balanced' });
    expect(templateFields('copy:globex')).toEqual({ copy_settings_from: 'globex' });
  });
});

describe('MSSP console', () => {
  it('lists tenants with their figures and suspends one after confirmation', async () => {
    const rows = [tenant('acme', 'Acme (MSSP)'), busyTenant()];
    const { api, calls } = fakeApi((method, _path, body) => {
      if (method === 'PATCH') return { ...rows[1], status: (body as { status: string }).status };
      return rows;
    });
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<PlatformPage />, session, { route: '/platform' });

    const row = (await screen.findByText('Globex Corp')).closest('tr') as HTMLElement;
    const cells = within(row);
    expect(cells.getByText('1,000 / 1,000')).toBeInTheDocument();
    expect(cells.getByText('(1 overdue)')).toBeInTheDocument();
    expect(cells.getByText('$12.50')).toBeInTheDocument();
    // The home tenant cannot be suspended from here.
    const home = (screen.getByText('Acme (MSSP)').closest('tr') as HTMLElement);
    expect(within(home).queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();

    fireEvent.click(cells.getByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('dialog', { name: /Suspend Globex Corp/ });
    expect(dialog).toHaveTextContent(/refused at once/);
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Suspend tenant' }));
    await waitFor(() => expect(calls.find((c) => c.method === 'PATCH')).toMatchObject({ path: '/platform/tenants/globex', body: { status: 'suspended' } }));
  });

  it('edits quotas with empty meaning unlimited', async () => {
    const rows = [busyTenant()];
    const { api, calls } = fakeApi((method) => (method === 'PATCH' ? rows[0] : rows));
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<PlatformPage />, session, { route: '/platform' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit quotas of Globex Corp' }));
    const dialog = await screen.findByRole('dialog', { name: /Quotas for Globex Corp/ });
    fireEvent.change(within(dialog).getByLabelText('Sources'), { target: { value: '' } });
    fireEvent.change(within(dialog).getByLabelText('Active users'), { target: { value: '10' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save quotas' }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ quotas: { max_alerts_per_day: 1000, max_sources: null, max_users: 10 } }),
    );
  });

  it('opens a cross-tenant escalation in its tenant', async () => {
    const escalation: PlatformEscalationOut = {
      id: 'esc-1',
      tenant_id: 'globex',
      tenant_name: 'Globex Corp',
      tenant_status: 'active',
      alert_id: 'a-1',
      alert_title: 'Encoded PowerShell',
      alert_severity: 'critical',
      level: 'L2',
      status: 'open',
      priority: 9,
      reason: 'high_risk',
      assigned_to: null,
      sla_deadline: new Date(Date.now() - 60_000).toISOString(),
      overdue: true,
      created_at: '2026-09-30T00:00:00Z',
    };
    const page: Page<PlatformEscalationOut> = { items: [escalation], next_cursor: null };
    const { api } = fakeApi((_m, path) => (path === '/platform/escalations' ? page : [busyTenant()]));
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<PlatformPage />, session, { route: '/platform?tab=escalations' });
    expect(await screen.findByText(/overdue by/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Encoded PowerShell' }));
    expect(session.auth.getState().actingTenant).toBe('globex');
  });
});
