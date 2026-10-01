import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { TenantSettingsOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import TenantSettingsPage, { phishingPatch, routesPatch } from './TenantSettingsPage';

const SETTINGS: TenantSettingsOut = {
  tenant_id: 'acme',
  name: 'Acme',
  status: 'active',
  settings: { phishing: { protected_brands: ['Example Bank'], executives: ['Smith, Jane'], trusted_authserv_ids: [] } },
  updated_at: '2026-09-01T00:00:00Z',
};

describe('TenantSettingsPage phishing context', () => {
  it('shows the stored lists one per line and saves the whole section', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (path === '/tenant/response/routes') return { dry_run_forced: true, routes: {} };
      return method === 'PATCH' ? { ...SETTINGS, updated_at: '2026-09-02T00:00:00Z' } : SETTINGS;
    });
    renderWithSession(<TenantSettingsPage />, await signedInSession(api, { role: 'admin' }));

    const brands = await screen.findByLabelText('Protected brands');
    expect(brands).toHaveValue('Example Bank');
    expect(screen.getByLabelText('Executives')).toHaveValue('Smith, Jane');
    await userEvent.type(brands, '\nexamplebank.example');
    await userEvent.type(screen.getByLabelText('Trusted mail servers (authserv-id)'), 'mx.acme.example');
    await userEvent.click(screen.getByRole('button', { name: 'Save phishing context' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')).toEqual({
      method: 'PATCH',
      path: '/tenant/settings',
      body: {
        phishing: {
          protected_brands: ['Example Bank', 'examplebank.example'],
          executives: ['Smith, Jane'],
          trusted_authserv_ids: ['mx.acme.example'],
        },
      },
      query: undefined,
    });
  });

  it('builds the patch within the backend limits', () => {
    const empty = { protected_brands: '', executives: '', trusted_authserv_ids: '' };
    expect(phishingPatch(empty)).toEqual({ phishing: null });
    expect(phishingPatch({ ...empty, executives: ' Jane Smith \r\n\nJane Smith\nJohn Doe' })).toEqual({
      phishing: { protected_brands: [], executives: ['Jane Smith', 'John Doe'], trusted_authserv_ids: [] },
    });
    const servers = Array.from({ length: 21 }, (_, i) => `mx${i}.example`).join('\n');
    expect(phishingPatch({ ...empty, trusted_authserv_ids: servers })).toBeInstanceOf(Error);
    expect(phishingPatch({ ...empty, executives: 'x'.repeat(129) })).toBeInstanceOf(Error);
  });
});

describe('TenantSettingsPage response routing', () => {
  const ROUTES = {
    dry_run_forced: true,
    routes: {
      isolate_host: { connector: 'microsoft', source: 'capability', capability: 'defender.isolation', live: false, problem: null },
      create_ticket: { connector: 'ticketing', source: 'ticketing', capability: null, live: null, problem: null },
      disable_user: { connector: 'microsoft', source: 'explicit', capability: null, live: null, problem: 'no enabled Microsoft capability executes disable_user' },
    },
  };

  it('shows each route, the dry-run banner and saves overrides', async () => {
    const settings = { ...SETTINGS, settings: { response: { routes: { disable_user: 'microsoft' } } } };
    const { api, calls } = fakeApi((method, path) => {
      if (path === '/tenant/response/routes') return ROUTES;
      return method === 'PATCH' ? { ...settings, updated_at: '2026-09-02T00:00:00Z' } : settings;
    });
    renderWithSession(<TenantSettingsPage />, await signedInSession(api, { role: 'admin' }));

    expect(await screen.findByText(/Dry run is on: nothing executes/)).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Response routes' });
    expect(within(table).getByText('Microsoft (Microsoft capability, defender.isolation, rehearsal)')).toBeInTheDocument();
    expect(within(table).getByText('no enabled Microsoft capability executes disable_user')).toBeInTheDocument();
    const disable = within(table).getByLabelText('Route for Disable user');
    expect(disable).toHaveValue('microsoft');
    const isolate = within(table).getByLabelText('Route for Isolate host');
    expect(within(isolate).getByRole('option', { name: 'Ticketing' })).toBeDisabled();
    await userEvent.selectOptions(isolate, 'webhook');
    await userEvent.selectOptions(disable, '');
    await userEvent.click(screen.getByRole('button', { name: 'Save response routing' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ response: { routes: { isolate_host: 'webhook' } } });
  });

  it('builds the routes patch', () => {
    expect(routesPatch({ a: '', b: '' })).toEqual({ response: { routes: null } });
    expect(routesPatch({ create_ticket: 'ticketing', block_ip: '' })).toEqual({ response: { routes: { create_ticket: 'ticketing' } } });
  });
});
