import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { TenantSettingsOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import TenantSettingsPage, { phishingPatch } from './TenantSettingsPage';

const SETTINGS: TenantSettingsOut = {
  tenant_id: 'acme',
  name: 'Acme',
  status: 'active',
  settings: { phishing: { protected_brands: ['Example Bank'], executives: ['Smith, Jane'], trusted_authserv_ids: [] } },
  updated_at: '2026-09-01T00:00:00Z',
};

describe('TenantSettingsPage phishing context', () => {
  it('shows the stored lists one per line and saves the whole section', async () => {
    const { api, calls } = fakeApi((method) => (method === 'PATCH' ? { ...SETTINGS, updated_at: '2026-09-02T00:00:00Z' } : SETTINGS));
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
