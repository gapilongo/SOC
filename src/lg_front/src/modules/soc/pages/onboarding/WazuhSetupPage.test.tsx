import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { GuidedCheckOut, SetupCheckOut, SourceOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { checksSummary } from './SetupChecks';
import WazuhSetupPage, { pullConfig } from './WazuhSetupPage';

const CHECK_PATH = '/onboarding/connectors/wazuh/check';
const PULL_ORDER = ['settings', 'reachable', 'tls', 'credentials', 'index_permission', 'index', 'clock'];
// Built at run time: never a credential-shaped literal in the repository.
const PASSWORD = ['test', 'only', 'pw'].join('-');
const API_KEY = ['lgk', '0'.repeat(32), 'test-only'.repeat(4)].join('_');

function check(id: string, status: SetupCheckOut['status'], overrides: Partial<SetupCheckOut> = {}): SetupCheckOut {
  return { id, title: `Check ${id}`, status, message: `${id} ${status}`, fix: null, ...overrides };
}

/** The pull checks with `failed` failing: the ones before it passed, the ones after it were skipped. */
function pullResult(failed?: string, overrides: Partial<SetupCheckOut> = {}): GuidedCheckOut {
  const at = failed ? PULL_ORDER.indexOf(failed) : PULL_ORDER.length;
  return {
    ok: !failed,
    checks: PULL_ORDER.map((id, i) =>
      i < at ? check(id, 'passed') : i === at ? check(id, 'failed', overrides) : check(id, 'skipped', { message: 'Not checked: fix the failed check above first.' }),
    ),
  };
}

function source(overrides: Partial<SourceOut> = {}): SourceOut {
  return {
    id: 'wazuh',
    tenant_id: 'acme',
    type: 'wazuh',
    name: 'Wazuh',
    enabled: true,
    config: {},
    has_secret: true,
    poll_interval_s: 60,
    health: 'unknown',
    created_at: '2026-11-14T00:00:00Z',
    updated_at: '2026-11-14T00:00:00Z',
    ...overrides,
  };
}

async function renderPage(handler: Parameters<typeof fakeApi>[0]) {
  const { api, calls } = fakeApi(handler);
  const session = await signedInSession(api, { role: 'admin' });
  renderWithSession(
    <Routes>
      <Route path="/sources/wazuh" element={<WazuhSetupPage />} />
      <Route path="/sources" element={<h1>Sources list</h1>} />
    </Routes>,
    session,
    { route: '/sources/wazuh' },
  );
  return calls;
}

async function fill(label: string | RegExp, value: string) {
  const field = screen.getByLabelText(label);
  await userEvent.clear(field);
  await userEvent.click(field);
  await userEvent.paste(value);
}

describe('WazuhSetupPage, reading the indexer', () => {
  it('shows the failed check with its fix, and saves the source once every check passes', async () => {
    const answers: GuidedCheckOut[] = [
      pullResult('index_permission', {
        title: 'Permission to read the alerts index',
        message: 'The user signed in, but its role may not read wazuh-alerts-*: the permission indices:data/read/search is missing.',
        fix: 'In the Wazuh indexer, give the user a role with the index permission read on the index pattern wazuh-alerts-*.',
      }),
      pullResult(),
    ];
    const calls = await renderPage((method, path) => {
      if (method === 'POST' && path === CHECK_PATH) return answers.shift();
      if (method === 'POST' && path === '/sources') return source({ name: 'Wazuh lab' });
      throw new Error(`unexpected ${method} ${path}`);
    });

    expect(screen.getByRole('heading', { name: 'Connect Wazuh', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/Not run yet/)).toBeInTheDocument();
    expect(screen.getByText('Available once every check passes.')).toBeInTheDocument();
    await fill('Indexer URL', 'https://wazuh.example.com:9200');
    await fill('User name', 'soc-reader');
    await fill('Password', PASSWORD);
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));

    const list = await screen.findByRole('list', { name: 'Wazuh indexer checks' });
    const rows = within(list).getAllByRole('listitem');
    expect(rows.map((r) => r.getAttribute('data-status'))).toEqual(['passed', 'passed', 'passed', 'passed', 'failed', 'skipped', 'skipped']);
    const failed = within(rows[4]);
    expect(failed.getByText('Permission to read the alerts index')).toBeInTheDocument();
    expect(failed.getByText('Failed')).toBeInTheDocument();
    expect(failed.getByText(/the permission indices:data\/read\/search is missing/)).toBeInTheDocument();
    expect(failed.getByText('What to change')).toBeInTheDocument();
    expect(failed.getByText(/index permission read on the index pattern wazuh-alerts-\*/)).toBeInTheDocument();
    expect(within(rows[5]).getByText('Not checked')).toBeInTheDocument();
    const summary = screen.getByText('4 of 7 checks passed, 1 failed. Fix what failed, then run the checks again.');
    expect(summary).toHaveAttribute('role', 'status');
    expect(screen.queryByRole('button', { name: 'Save source' })).not.toBeInTheDocument();
    expect(calls[0].body).toEqual({
      pull: { config: { base_url: 'https://wazuh.example.com:9200' }, secret: { username: 'soc-reader', password: PASSWORD } },
    });

    // The role is fixed on the Wazuh side; the same values are checked again.
    await userEvent.click(screen.getByRole('button', { name: 'Run checks again' }));
    expect(await screen.findByText('All 7 checks passed.')).toBeInTheDocument();
    await fill('Source name', 'Wazuh lab');
    await userEvent.click(screen.getByRole('button', { name: 'Save source' }));

    expect(await screen.findByRole('heading', { name: 'Sources list' })).toBeInTheDocument();
    expect(await screen.findByText(/Source Wazuh lab saved/)).toBeInTheDocument();
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([`POST ${CHECK_PATH}`, `POST ${CHECK_PATH}`, 'POST /sources']);
    expect(calls[2].body).toEqual({
      type: 'wazuh',
      name: 'Wazuh lab',
      enabled: true,
      config: { base_url: 'https://wazuh.example.com:9200' },
      secret: { username: 'soc-reader', password: PASSWORD },
      poll_interval_s: 60,
    });
  });

  it('drops a result as soon as a value it was run with changes', async () => {
    const calls = await renderPage((method, path) => {
      if (method === 'POST' && path === CHECK_PATH) return pullResult();
      throw new Error(`unexpected ${method} ${path}`);
    });
    await fill('Indexer URL', 'https://wazuh.example.com:9200');
    await fill('User name', 'soc-reader');
    await fill('Password', PASSWORD);
    await fill('Index pattern', 'wazuh-archives-*');
    await fill(/^CA certificate/, '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    expect(await screen.findByRole('button', { name: 'Save source' })).toBeInTheDocument();
    expect(calls[0].body).toMatchObject({
      pull: { config: { index: 'wazuh-archives-*', ca_cert_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----' } },
    });

    await fill('Index pattern', 'wazuh-alerts-*');
    expect(screen.queryByRole('button', { name: 'Save source' })).not.toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Wazuh indexer checks' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run checks' })).toBeInTheDocument();
  });

  it('reports a refused request and a refused save without losing the form', async () => {
    let refuseCheck = true;
    await renderPage((method, path) => {
      if (method === 'POST' && path === CHECK_PATH) {
        if (refuseCheck) throw apiError(403, 'forbidden', 'not available under a grant');
        return pullResult();
      }
      if (method === 'POST' && path === '/sources') throw apiError(409, 'quota_exceeded', 'this tenant may have 1 source');
      throw new Error(`unexpected ${method} ${path}`);
    });
    await fill('Indexer URL', 'https://wazuh.example.com:9200');
    await fill('User name', 'soc-reader');
    await fill('Password', PASSWORD);
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    expect(await screen.findByText(/not available under a grant/)).toBeInTheDocument();
    expect(screen.queryByText(/Not run yet/)).not.toBeInTheDocument();

    refuseCheck = false;
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Save source' }));
    expect(await screen.findByText(/this tenant may have 1 source/)).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue(PASSWORD);
  });
});

describe('WazuhSetupPage, push from the manager', () => {
  it('creates the push source when it is missing and checks the key the manager sends', async () => {
    let sources: SourceOut[] = [source({ id: 'wazuh', name: 'Wazuh' })];
    const calls = await renderPage((method, path, body) => {
      if (method === 'GET' && path === '/sources') return sources;
      if (method === 'POST' && path === '/sources') {
        const created = source({ ...(body as Partial<SourceOut>), has_secret: false });
        sources = [...sources, created];
        return created;
      }
      if (method === 'POST' && path === CHECK_PATH) {
        const sent = (body as { push: { api_key?: string } }).push.api_key;
        return {
          ok: Boolean(sent),
          checks: [
            check('push_source', 'passed', { title: 'Push source' }),
            sent
              ? check('push_key', 'passed', { title: 'Webhook API key' })
              : check('push_key', 'skipped', { title: 'Webhook API key', message: 'Not checked: paste the key the Wazuh manager sends.' }),
          ],
        } satisfies GuidedCheckOut;
      }
      throw new Error(`unexpected ${method} ${path}`);
    });

    await userEvent.click(screen.getByRole('radio', { name: 'Push from the manager' }));
    expect(screen.getByLabelText('Source ID')).toHaveValue('wazuh-push');
    expect(await screen.findByText('No source wazuh-push yet')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create push source' }));
    await waitFor(() => expect(screen.queryByText('No source wazuh-push yet')).not.toBeInTheDocument());
    expect(calls.find((c) => c.method === 'POST' && c.path === '/sources')?.body).toEqual({
      id: 'wazuh-push',
      type: 'webhook',
      name: 'Wazuh (push)',
      enabled: true,
      config: { format: 'wazuh' },
      poll_interval_s: 60,
    });

    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    expect(await screen.findByText('1 of 2 checks passed; the others did not apply.')).toBeInTheDocument();
    expect(calls.at(-1)?.body).toEqual({ push: { source_id: 'wazuh-push' } });

    await fill(/^API key the manager sends/, API_KEY);
    expect(screen.queryByRole('list', { name: 'Wazuh push checks' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    expect(await screen.findByText('All 2 checks passed.')).toBeInTheDocument();
    expect(calls.at(-1)?.body).toEqual({ push: { source_id: 'wazuh-push', api_key: API_KEY } });
    // The key is typed into a password field and never rendered.
    expect(screen.getByLabelText(/^API key the manager sends/)).toHaveAttribute('type', 'password');
    expect(document.body.textContent).not.toContain(API_KEY);
  });

  it('shows why the source could not be created or checked', async () => {
    await renderPage((method, path) => {
      if (method === 'GET' && path === '/sources') return [];
      if (method === 'POST' && path === '/sources') throw apiError(409, 'conflict', 'a source with this id exists');
      if (method === 'POST' && path === CHECK_PATH) throw apiError(503, 'unavailable', 'the database is restarting');
      throw new Error(`unexpected ${method} ${path}`);
    });
    await userEvent.click(screen.getByRole('radio', { name: 'Push from the manager' }));
    await fill('Source ID', 'wazuh-lab');
    await userEvent.click(await screen.findByRole('button', { name: 'Create push source' }));
    expect(await screen.findByText(/a source with this id exists/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run checks' }));
    expect(await screen.findByText(/the database is restarting/)).toBeInTheDocument();
  });
});

describe('guided setup helpers', () => {
  it('leaves defaults out of the saved config', () => {
    const form = { baseUrl: ' https://wazuh:9200 ', index: ' wazuh-alerts-* ', username: 'u', password: 'p', caPem: '  ' };
    expect(pullConfig(form)).toEqual({ base_url: 'https://wazuh:9200' });
    expect(pullConfig({ ...form, index: '', caPem: ' PEM ' })).toEqual({ base_url: 'https://wazuh:9200', ca_cert_pem: 'PEM' });
  });

  it('summarises a run, reading an unknown status as not checked', () => {
    expect(checksSummary({ ok: true, checks: [check('a', 'passed'), check('b', 'passed')] })).toBe('All 2 checks passed.');
    expect(checksSummary({ ok: true, checks: [check('a', 'passed'), check('b', 'postponed')] })).toBe(
      '1 of 2 checks passed; the others did not apply.',
    );
    expect(checksSummary({ ok: false, checks: [check('a', 'failed'), check('b', 'skipped')] })).toBe(
      '0 of 2 checks passed, 1 failed. Fix what failed, then run the checks again.',
    );
  });
});
