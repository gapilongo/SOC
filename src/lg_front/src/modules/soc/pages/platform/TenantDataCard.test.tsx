import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { TenantErasureStatusOut } from '../../../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { TenantDataCard } from './TenantDataCard';

function status(overrides: Partial<TenantErasureStatusOut> = {}): TenantErasureStatusOut {
  return { tenant_id: 'globex', name: 'Globex', status: 'active', erasable: false, blockers: ['tenant is not suspended'], erased_at: null, ...overrides };
}

const erased = { tenant_id: 'globex', erased_at: '2026-09-30T10:00:00Z', deleted: { alerts: 3, users: 2 }, redis_keys: 4, queue_entries: 1, audit_entries_retained: 17 };

async function lookUp(id: string) {
  await userEvent.type(screen.getByLabelText('Tenant id'), id);
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }));
}

describe('TenantDataCard', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps erasure disabled for an active tenant and explains why', async () => {
    const { api } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/platform/tenants/globex/erasure') return status();
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<TenantDataCard />, session);

    await lookUp('globex');
    expect(await screen.findByText(/Suspend the tenant first/)).toBeInTheDocument();
    expect(screen.getByText('tenant is not suspended')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Erase tenant' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Export tenant data' })).toBeEnabled();
  });

  it('erases a suspended tenant only after the id is typed exactly', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/platform/tenants/globex/erasure') return status({ status: 'suspended', erasable: true, blockers: [] });
      if (method === 'DELETE' && path === '/platform/tenants/globex') return erased;
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<TenantDataCard />, session);

    await lookUp('globex');
    const erase = await screen.findByRole('button', { name: 'Erase tenant' });
    expect(erase).toBeEnabled();
    await userEvent.click(erase);

    const confirm = screen.getByRole('button', { name: 'Erase permanently' });
    expect(confirm).toBeDisabled();
    expect(screen.getByText(/hash-chained audit log/)).toBeInTheDocument();
    const field = screen.getByLabelText(/to confirm/);
    await userEvent.type(field, 'globe');
    expect(confirm).toBeDisabled();
    await userEvent.type(field, 'x ');
    expect(confirm).toBeDisabled();
    await userEvent.type(field, '{backspace}');
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);

    expect(await screen.findByText(/5 rows/)).toBeInTheDocument();
    expect(screen.getByText(/17 audit entries retained/)).toBeInTheDocument();
    const del = calls.find((c) => c.method === 'DELETE');
    expect(del?.body).toEqual({ confirm: 'globex' });
  });

  it('downloads the tenant export as a zip', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET') return status();
      if (method === 'POST' && path === '/platform/tenants/globex/export') return new Blob(['PK'], { type: 'application/zip' });
      throw new Error(`unexpected ${method} ${path}`);
    });
    URL.createObjectURL = vi.fn(() => 'blob:test/1');
    URL.revokeObjectURL = vi.fn();
    const names: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<TenantDataCard />, session);

    await lookUp('globex');
    await userEvent.click(await screen.findByRole('button', { name: 'Export tenant data' }));
    await waitFor(() => expect(names).toHaveLength(1));
    expect(names[0]).toMatch(/^lg-sotf-tenant-globex-\d{8}T\d{6}Z\.zip$/);
    expect(calls.some((c) => c.method === 'POST' && c.path === '/platform/tenants/globex/export')).toBe(true);
  });
});
