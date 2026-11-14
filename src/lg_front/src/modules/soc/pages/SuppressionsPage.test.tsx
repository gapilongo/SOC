import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { SuppressionOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../test/helpers';
import SuppressionsPage, { buildMatch } from './SuppressionsPage';

function rule(overrides: Partial<SuppressionOut> = {}): SuppressionOut {
  return {
    id: 'r-1',
    tenant_id: 'acme',
    name: 'Scanner noise',
    match: { title: { regex: 'Port scan.*' } },
    disposition: 'benign',
    hit_count: 12,
    enabled: true,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    ...overrides,
  };
}

/** An in-memory suppressions API. */
function rulesApi(initial: SuppressionOut[]) {
  let rules = [...initial];
  return fakeApi((method, path, body) => {
    if (method === 'GET' && path === '/suppressions') return rules;
    if (method === 'POST' && path === '/suppressions') {
      const b = body as { name: string; match: SuppressionOut['match']; enabled: boolean };
      const created = rule({ id: 'r-new', name: b.name, match: b.match, enabled: b.enabled, hit_count: 0 });
      rules = [...rules, created];
      return created;
    }
    const id = path.split('/')[2];
    if (method === 'PATCH') {
      rules = rules.map((r) => (r.id === id ? { ...r, ...(body as object) } : r));
      return rules.find((r) => r.id === id);
    }
    if (method === 'DELETE') {
      rules = rules.filter((r) => r.id !== id);
      return undefined;
    }
    throw new Error(`unexpected ${method} ${path}`);
  });
}

async function fill(field: HTMLElement, value: string) {
  await userEvent.clear(field);
  await userEvent.click(field);
  await userEvent.paste(value);
}

describe('SuppressionsPage', () => {
  it('lets an admin create, disable, enable and delete a rule', async () => {
    const { api, calls } = rulesApi([rule()]);
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<SuppressionsPage />, session);
    expect(await screen.findByText('Scanner noise')).toBeInTheDocument();
    expect(screen.getByText('title regex Port scan.*')).toBeInTheDocument();

    // Create
    await userEvent.click(screen.getByRole('button', { name: 'New rule' }));
    const form = within(screen.getByRole('dialog', { name: 'New suppression rule' }));
    await fill(form.getByLabelText('Name'), 'Backup host');
    await fill(form.getByLabelText('Field 1'), 'entities.hosts');
    await userEvent.selectOptions(form.getByLabelText('Operator'), 'in');
    await fill(form.getByLabelText('Value'), 'bk-01, bk-02');
    await userEvent.click(form.getByRole('button', { name: 'Create rule' }));
    expect(await screen.findByText('Backup host')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      name: 'Backup host',
      match: { 'entities.hosts': { in: ['bk-01', 'bk-02'] } },
      expires_at: null,
      enabled: true,
    });

    // Disable, then find it under "All rules" and enable it again
    const item = () => screen.getByText('Scanner noise').closest('li') as HTMLElement;
    await userEvent.click(within(item()).getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(screen.queryByText('Scanner noise')).not.toBeInTheDocument());
    expect(calls.find((c) => c.method === 'PATCH')).toMatchObject({ path: '/suppressions/r-1', body: { enabled: false } });
    await userEvent.click(screen.getByRole('button', { name: 'All rules' }));
    await userEvent.click(within(item()).getByRole('button', { name: 'Enable' }));
    await waitFor(() => expect(within(item()).getByRole('button', { name: 'Disable' })).toBeInTheDocument());

    // Delete
    await userEvent.click(screen.getByRole('button', { name: 'Delete rule Scanner noise' }));
    await userEvent.click(within(screen.getByRole('dialog', { name: 'Delete suppression rule' })).getByRole('button', { name: 'Delete rule' }));
    await waitFor(() => expect(screen.queryByText('Scanner noise')).not.toBeInTheDocument());
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/suppressions/r-1')).toBe(true);
  });

  it('creates analyst rules disabled and offers no admin controls', async () => {
    const { api, calls } = rulesApi([rule({ id: 'r-2', name: 'Suggested', enabled: false, source_feedback_id: 'fb-1' })]);
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<SuppressionsPage />, session);
    await userEvent.click(await screen.findByRole('button', { name: 'Suggestions (1)' }));
    expect(screen.getByText('Suggested')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete rule/ })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'New rule' }));
    const form = within(screen.getByRole('dialog', { name: 'New suppression rule' }));
    expect(form.queryByLabelText('Enable immediately')).not.toBeInTheDocument();
    await fill(form.getByLabelText('Name'), 'Mine');
    await fill(form.getByLabelText('Value'), 'Test alert');
    await userEvent.click(form.getByRole('button', { name: 'Create rule' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect((calls.find((c) => c.method === 'POST')?.body as { enabled: boolean }).enabled).toBe(false);
  });

  it('refuses a rule without any condition value, without a request', async () => {
    const { api, calls } = rulesApi([]);
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<SuppressionsPage />, session);
    await userEvent.click(await screen.findByRole('button', { name: 'New rule' }));
    const form = within(screen.getByRole('dialog', { name: 'New suppression rule' }));
    await fill(form.getByLabelText('Name'), 'Empty');
    await userEvent.click(form.getByRole('button', { name: 'Create rule' }));
    expect(await form.findByText(/Add at least one condition/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
  });
});

describe('suppression predicates', () => {
  it('builds suppression predicates', () => {
    expect(
      buildMatch([
        { path: 'title', op: 'regex', value: '.*backup.*' },
        { path: 'entities.ips', op: 'cidr', value: '10.0.0.0/8, 192.168.0.0/16' },
        { path: 'severity', op: 'in', value: 'low,info' },
        { path: 'category', op: 'eq', value: '' },
      ]),
    ).toEqual({ title: { regex: '.*backup.*' }, 'entities.ips': { cidr: ['10.0.0.0/8', '192.168.0.0/16'] }, severity: { in: ['low', 'info'] } });
  });
});
