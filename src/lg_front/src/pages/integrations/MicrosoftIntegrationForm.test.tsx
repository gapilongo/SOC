import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { IntegrationCreateIn, IntegrationOut, IntegrationUpdateIn } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { ISOLATION } from '../../test/microsoft';
import IntegrationsPage, { missingCredentials } from '../IntegrationsPage';
import { bindingChanged, buildMicrosoftConfig, type MicrosoftFormValues } from './MicrosoftIntegrationForm';

// Identifiers and credentials are generated at runtime (no credential-shaped literals in fixtures).
const DIRECTORY = crypto.randomUUID();
const CLIENT = crypto.randomUUID();
const TYPED_SECRET = ['typed', 'in', 'form'].join('-');
const CATALOG = { capabilities: [ISOLATION], clouds: [], defender_geos: ['us', 'eu'] };

function values(overrides: Partial<MicrosoftFormValues> = {}): MicrosoftFormValues {
  return {
    cloud: 'global',
    directory_tenant_id: DIRECTORY,
    client_id: CLIENT,
    credential: 'client_secret',
    certificate_pem: '',
    defender_geo: '',
    ...overrides,
  };
}

function stored(overrides: Partial<IntegrationOut> = {}): IntegrationOut {
  return {
    id: 'ms-1',
    tenant_id: 'acme',
    kind: 'microsoft',
    name: 'Microsoft 365',
    enabled: true,
    events: [],
    min_severity: 'low',
    config: { cloud: 'global', directory_tenant_id: DIRECTORY, client_id: CLIENT, credential: 'client_secret', capabilities: {} },
    secrets: { client_secret: true, private_key_pem: false },
    created_at: '2026-09-30T10:00:00Z',
    updated_at: '2026-09-30T10:00:00Z',
    ...overrides,
  };
}

describe('Microsoft integration form helpers', () => {
  it('builds a config without URLs and validates the GUIDs', () => {
    expect(buildMicrosoftConfig(values({ defender_geo: 'eu' }), {})).toEqual({
      cloud: 'global',
      directory_tenant_id: DIRECTORY,
      client_id: CLIENT,
      credential: 'client_secret',
      capabilities: {},
      defender_geo: 'eu',
    });
    expect(buildMicrosoftConfig(values({ cloud: 'usgov_dod', defender_geo: 'eu' }), {})).not.toHaveProperty('defender_geo');
    expect(() => buildMicrosoftConfig(values({ directory_tenant_id: 'common' }), {})).toThrow(/GUID/);
    expect(() => buildMicrosoftConfig(values({ credential: 'certificate' }), {})).toThrow(/certificate/);
  });

  it('knows when the stored credential must be entered again', () => {
    const config = stored().config;
    expect(bindingChanged(config, values())).toBe(false);
    expect(bindingChanged(config, values({ cloud: 'usgov_gcc_high' }))).toBe(true);
    expect(bindingChanged(config, values({ credential: 'certificate' }))).toBe(true);
    expect(missingCredentials(stored())).toEqual([]);
    expect(missingCredentials(stored({ config: { credential: 'certificate' } }))).toEqual(['private_key_pem']);
  });
});

describe('Microsoft integration through the integrations page', () => {
  it('creates the integration with a write-only secret and a rehearsing capability', async () => {
    const { api, calls } = fakeApi((method, path, body) => {
      if (method === 'GET' && path === '/integrations') return [];
      if (method === 'GET' && path === '/integrations/microsoft/catalog') return CATALOG;
      if (method === 'POST' && path === '/integrations') return stored({ ...(body as IntegrationCreateIn), id: 'ms-2' } as IntegrationOut);
      throw new Error(`unexpected ${method} ${path}`);
    });
    renderWithSession(<IntegrationsPage />, await signedInSession(api, { role: 'admin' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Add integration' }));
    await userEvent.selectOptions(screen.getByLabelText('Kind'), 'microsoft');
    const dialog = await screen.findByRole('dialog', { name: /Add Microsoft 365 direct response/ });
    await userEvent.type(within(dialog).getByLabelText('Directory (tenant) ID'), DIRECTORY);
    await userEvent.type(within(dialog).getByLabelText('Application (client) ID'), CLIENT);
    await userEvent.click(within(dialog).getByLabelText('Client secret'));
    const secret = within(dialog).getByLabelText(/^Client secret/, { selector: 'input[type="password"]' });
    await userEvent.type(secret, TYPED_SECRET);
    const card = await within(dialog).findByRole('article', { name: /Machine isolation/ });
    await userEvent.click(within(card).getByLabelText('Enabled'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create integration' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/integrations')).toBe(true));
    const body = calls.find((c) => c.method === 'POST' && c.path === '/integrations')?.body as IntegrationCreateIn;
    expect(body.kind).toBe('microsoft');
    expect(body.events).toEqual([]);
    expect(body.secret).toEqual({ client_secret: TYPED_SECRET });
    expect(body.config).toMatchObject({ cloud: 'global', directory_tenant_id: DIRECTORY, credential: 'client_secret' });
    expect((body.config?.capabilities as Record<string, unknown>)['defender.isolation']).toMatchObject({ enabled: true, live: false });
  });

  it('edits without resending the secret and removes the unused credential when switching type', async () => {
    const existing = stored({ config: { ...stored().config, certificate: { thumbprint_sha1: 'AB', not_after: '2027-01-01T00:00:00Z' } } });
    const { api, calls } = fakeApi((method, path, body) => {
      if (method === 'GET' && path === '/integrations') return [existing];
      if (method === 'GET' && path === '/integrations/microsoft/catalog') return CATALOG;
      if (method === 'PATCH' && path === '/integrations/ms-1') return { ...existing, ...(body as IntegrationUpdateIn) };
      throw new Error(`unexpected ${method} ${path}`);
    });
    renderWithSession(<IntegrationsPage />, await signedInSession(api, { role: 'admin' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Microsoft 365' }));
    const dialog = await screen.findByRole('dialog', { name: /Edit Microsoft 365/ });
    await within(dialog).findByRole('article', { name: /Machine isolation/ });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH')?.body as IntegrationUpdateIn;
    expect(patch.secret).toBeUndefined();
    expect(patch.config).not.toHaveProperty('certificate');
  });
});
