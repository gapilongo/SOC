import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, renderHook, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';

import { SessionProvider } from '../../../../auth/AuthContext';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { tenant } from '../../../../test/tenants';
import { ActingTenantBanner, TenantSwitcher, filterTenants, usePlatformTenants, type PlatformTenantsOptions } from './TenantSwitcher';

const TENANTS = [tenant('acme', 'Acme (MSSP)'), tenant('globex', 'Globex Corp'), tenant('initech', 'Initech', { status: 'suspended' })];

describe('tenant switcher', () => {
  it('filters by id or name, home tenant first', () => {
    expect(filterTenants(TENANTS, 'corp', 'acme').map((t) => t.id)).toEqual(['globex']);
    expect(filterTenants(TENANTS, 'INI', 'acme').map((t) => t.id)).toEqual(['initech']);
    expect(filterTenants(TENANTS, '', 'globex').map((t) => t.id)).toEqual(['globex', 'acme', 'initech']);
  });

  it('switches the acting tenant from a searchable list and shows the banner until returning home', async () => {
    const { api, calls } = fakeApi(() => TENANTS);
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(
      <>
        <TenantSwitcher />
        <ActingTenantBanner />
      </>,
      session,
    );
    expect(calls).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: /Switch tenant/ }));
    const search = screen.getByRole('combobox', { name: 'Search tenants' });
    expect(await screen.findByText('Globex Corp')).toBeInTheDocument();
    expect(calls.map((c) => c.path)).toEqual(['/platform/tenants']);
    expect(screen.getByText('suspended')).toBeInTheDocument();

    fireEvent.change(search, { target: { value: 'glob' } });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    fireEvent.keyDown(search, { key: 'Enter' });

    await waitFor(() => expect(session.auth.getState().actingTenant).toBe('globex'));
    expect(screen.getByText(/live updates are off/)).toHaveTextContent('Acting as tenant globex. Every request is recorded');
    expect(screen.getByText('Acting as tenant Globex Corp. Every request is recorded in that tenant\'s audit log.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Return to acme/ }));
    expect(session.auth.getState().actingTenant).toBeNull();
    expect(screen.queryByText(/live updates are off/)).not.toBeInTheDocument();
  });

  it('still accepts a typed tenant id when the list cannot be loaded', async () => {
    const { api } = fakeApi(() => {
      throw new Error('down');
    });
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    renderWithSession(<TenantSwitcher />, session);
    fireEvent.click(screen.getByRole('button', { name: /Switch tenant/ }));
    expect(await screen.findByText(/could not be loaded/)).toBeInTheDocument();
    const search = screen.getByRole('combobox', { name: 'Search tenants' });
    fireEvent.change(search, { target: { value: 'umbrella' } });
    fireEvent.keyDown(search, { key: 'Enter' });
    expect(session.auth.getState().actingTenant).toBe('umbrella');
  });

  it('is not shown to tenant admins', async () => {
    const { api } = fakeApi(() => TENANTS);
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<TenantSwitcher />, session);
    expect(screen.queryByRole('button', { name: /Switch tenant/ })).not.toBeInTheDocument();
  });
});

describe('usePlatformTenants', () => {
  async function observerOptions(options: PlatformTenantsOptions) {
    const { api } = fakeApi(() => TENANTS);
    const session = await signedInSession(api, { role: 'admin', is_platform_admin: true });
    const client = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <SessionProvider session={session}>
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      </SessionProvider>
    );
    const { result } = renderHook(() => usePlatformTenants(options), { wrapper });
    await waitFor(() => expect(result.current.isSuccess || !options.enabled).toBe(true));
    const query = client.getQueryCache().find({ queryKey: ['platform-tenants'] });
    return query?.observers[0]?.options;
  }

  it('applies the options a caller sets and keeps the client defaults for the rest', async () => {
    expect((await observerOptions({}))?.staleTime).toBe(10_000);
    expect((await observerOptions({ staleTime: undefined, refetchInterval: undefined }))?.staleTime).toBe(10_000);
    const set = await observerOptions({ staleTime: 60_000, refetchInterval: 5_000 });
    expect(set?.staleTime).toBe(60_000);
    expect(set?.refetchInterval).toBe(5_000);
    expect((await observerOptions({ enabled: false }))?.enabled).toBe(false);
  });
});
