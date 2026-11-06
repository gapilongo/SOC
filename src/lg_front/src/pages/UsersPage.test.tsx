import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { ApiKeyCreatedOut, ApiKeyOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession, user } from '../test/helpers';
import UsersPage from './UsersPage';

const SECRET = 'lgs_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0';

function key(overrides: Partial<ApiKeyOut> = {}): ApiKeyOut {
  return {
    id: 'k-1',
    tenant_id: 'acme',
    name: 'siem forwarder',
    prefix: 'lgs_live_9f8e',
    scopes: ['ingest'],
    created_at: '2026-10-01T00:00:00Z',
    ...overrides,
  };
}

describe('UsersPage', () => {
  it('shows a new API key secret once and forgets it when the dialog closes', async () => {
    let keys: ApiKeyOut[] = [];
    const { api, calls } = fakeApi((method, path, body) => {
      if (method === 'GET' && path === '/users') return [user({ id: 'u-1', role: 'admin' })];
      if (method === 'GET' && path === '/api-keys') return keys;
      if (method === 'POST' && path === '/api-keys') {
        const created: ApiKeyCreatedOut = { ...key({ name: (body as { name: string }).name }), key: SECRET };
        keys = [key({ name: created.name })];
        return created;
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<UsersPage />, session);
    expect(await screen.findByText('No API keys')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Create key' }));
    const form = screen.getByRole('dialog', { name: 'Create API key' });
    await userEvent.type(within(form).getByLabelText('Name'), 'siem forwarder');
    await userEvent.click(within(form).getByRole('button', { name: 'Create key' }));

    const shown = await screen.findByRole('dialog', { name: 'API key siem forwarder created' });
    expect(within(shown).getByLabelText('API key')).toHaveValue(SECRET);
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ name: 'siem forwarder', scopes: ['ingest'] });

    await userEvent.click(within(shown).getByRole('button', { name: 'I have stored the key' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    // The list shows the key by name and prefix only; the secret is nowhere on the page.
    expect(await screen.findByText('siem forwarder')).toBeInTheDocument();
    expect(screen.queryByDisplayValue(SECRET)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it('lists users and refuses deleting yourself', async () => {
    const { api } = fakeApi((method, path) => {
      if (path === '/users') return [user({ id: 'u-1', email: 'me@acme.test', role: 'admin' }), user({ id: 'u-2', email: 'other@acme.test', mfa_enabled: true })];
      if (path === '/api-keys') return [];
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { id: 'u-1', role: 'admin' });
    renderWithSession(<UsersPage />, session);
    expect(await screen.findByText('other@acme.test')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete me@acme.test' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete other@acme.test' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Reset MFA of other@acme.test' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Reset MFA of me@acme.test' })).not.toBeInTheDocument();
  });
});
