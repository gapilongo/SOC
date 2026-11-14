import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { SourceOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../test/helpers';
import SourcesPage, { buildConfig, splitConfig } from './SourcesPage';

function source(overrides: Partial<SourceOut> = {}): SourceOut {
  return {
    id: 'wazuh-1',
    tenant_id: 'acme',
    type: 'wazuh',
    name: 'Wazuh prod',
    enabled: true,
    config: { base_url: 'https://wazuh:9200', min_level: 7 },
    has_secret: true,
    poll_interval_s: 60,
    health: 'healthy',
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    ...overrides,
  };
}

async function fill(field: HTMLElement, value: string) {
  await userEvent.clear(field);
  await userEvent.click(field);
  await userEvent.paste(value);
}

async function renderSources(handler: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(handler);
  const session = await signedInSession(api, { role: 'admin' });
  renderWithSession(<SourcesPage />, session);
  return calls;
}

describe('SourcesPage', () => {
  it('creates a source with typed configuration and write-only credentials', async () => {
    let list: SourceOut[] = [];
    const calls = await renderSources((method, path, body) => {
      if (method === 'GET' && path === '/sources') return list;
      if (method === 'POST' && path === '/sources') {
        list = [source({ name: (body as { name: string }).name })];
        return list[0];
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    expect(await screen.findByText('No sources yet')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Add source' }));
    const dialog = screen.getByRole('dialog', { name: 'Add source' });
    const form = within(dialog);
    await userEvent.selectOptions(form.getByLabelText('Type'), 'wazuh');
    await fill(form.getByLabelText('Name'), 'Wazuh prod');
    await fill(form.getByLabelText('Indexer URL'), 'https://wazuh:9200');
    await fill(form.getByLabelText('Minimum rule level'), '7');
    await fill(form.getByLabelText('Username'), 'reader');
    await fill(form.getByLabelText('Password'), 'test-only');
    await userEvent.click(form.getByRole('button', { name: 'Create source' }));

    expect(await screen.findByText('Wazuh prod')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      type: 'wazuh',
      name: 'Wazuh prod',
      enabled: true,
      config: { base_url: 'https://wazuh:9200', min_level: 7 },
      poll_interval_s: 60,
      secret: { username: 'reader', password: 'test-only' },
    });
  });

  it('keeps stored credentials on edit unless new ones are entered', async () => {
    const calls = await renderSources((method, path, body) => {
      if (method === 'GET' && path === '/sources') return [source()];
      if (method === 'PATCH' && path === '/sources/wazuh-1') return source(body as Partial<SourceOut>);
      throw new Error(`unexpected ${method} ${path}`);
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Wazuh prod' }));
    const form = within(screen.getByRole('dialog', { name: 'Edit source Wazuh prod' }));
    expect(form.getByText('credentials configured')).toBeInTheDocument();
    expect(form.getByLabelText('Password')).toHaveValue('');
    await fill(form.getByLabelText('Name'), 'Wazuh primary');
    await userEvent.click(form.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({
      name: 'Wazuh primary',
      enabled: true,
      config: { base_url: 'https://wazuh:9200', min_level: 7 },
      poll_interval_s: 60,
    });
  });

  it('removes stored credentials on request', async () => {
    const calls = await renderSources((method, path) => {
      if (method === 'GET' && path === '/sources') return [source()];
      if (method === 'PATCH' && path === '/sources/wazuh-1') return source({ has_secret: false });
      throw new Error(`unexpected ${method} ${path}`);
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Wazuh prod' }));
    const form = within(screen.getByRole('dialog', { name: 'Edit source Wazuh prod' }));
    await userEvent.click(form.getByLabelText('Remove stored credentials'));
    expect(form.getByLabelText('Password')).toBeDisabled();
    await userEvent.click(form.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect((calls.find((c) => c.method === 'PATCH')?.body as { secret: unknown }).secret).toBeNull();
  });

  it('refuses additional configuration that is not a JSON object, without a request', async () => {
    const calls = await renderSources((method, path) => {
      if (method === 'GET' && path === '/sources') return [];
      throw new Error(`unexpected ${method} ${path}`);
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Add source' }));
    const form = within(screen.getByRole('dialog', { name: 'Add source' }));
    await fill(form.getByLabelText('Name'), 'Broken');
    await fill(form.getByLabelText(/Additional configuration/), '[1, 2]');
    await userEvent.click(form.getByRole('button', { name: 'Create source' }));
    expect(await form.findByText(/Additional configuration must be a JSON object/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
  });

  it('deletes a source after confirmation', async () => {
    let list = [source()];
    const calls = await renderSources((method, path) => {
      if (method === 'GET' && path === '/sources') return list;
      if (method === 'DELETE' && path === '/sources/wazuh-1') {
        list = [];
        return undefined;
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Wazuh prod' }));
    await userEvent.click(within(screen.getByRole('dialog', { name: 'Delete source' })).getByRole('button', { name: 'Delete source' }));
    expect(await screen.findByText('No sources yet')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/sources/wazuh-1')).toBe(true);
  });
});

describe('source configuration', () => {
  it('builds source configuration from typed fields and extra JSON', () => {
    expect(buildConfig('splunk', { base_url: ' https://splunk:8089 ', max_event_lag_s: '600' }, '{"verify": true}')).toEqual({
      verify: true,
      base_url: 'https://splunk:8089',
      max_event_lag_s: 600,
    });
    expect(() => buildConfig('splunk', { max_event_lag_s: 'soon' }, '')).toThrow(/number/);
    expect(() => buildConfig('splunk', {}, '[1]')).toThrow(/JSON object/);
    expect(splitConfig('qradar', { base_url: 'https://q', custom: 1 })).toEqual({ known: { base_url: 'https://q' }, extra: '{\n  "custom": 1\n}' });
  });
});
