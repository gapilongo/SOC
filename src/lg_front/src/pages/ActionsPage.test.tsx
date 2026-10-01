import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { ActionOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import ActionsPage from './ActionsPage';

const ACTION: ActionOut = {
  id: 'a-1',
  tenant_id: 'acme',
  alert_id: 'alert-1',
  action_type: 'disable_user',
  target: 'alice@contoso.example',
  risk_level: 'critical',
  status: 'succeeded',
  connector: 'microsoft',
  executed_at: '2026-09-30T10:00:00Z',
  created_at: '2026-09-30T09:59:00Z',
  updated_at: '2026-09-30T10:00:00Z',
  verification: 'failed',
  verification_detail: { reason: 'synced_user_reenabled' },
  result: { summary: 'account disabled', changed: true },
  rollback: { available: true, action_type: 'enable_user', risk: 'critical' },
};

describe('ActionsPage', () => {
  it('shows verification, filters on it and expands a row', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/actions') return { items: [ACTION], next_cursor: null };
      throw new Error(`unexpected ${method} ${path}`);
    });
    renderWithSession(<ActionsPage />, await signedInSession(api, { role: 'admin' }));
    const row = (await screen.findByText('alice@contoso.example')).closest('tr') as HTMLElement;
    expect(within(row).getByText(/failed \(Synced user reenabled\)/i)).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: 'Roll back' })).toBeInTheDocument();
    await userEvent.click(within(row).getByRole('button', { name: /Show details of Disable user/i }));
    expect(screen.getByText('account disabled')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'inconclusive' }));
    await waitFor(() => expect(calls.some((c) => (c.query as { verification?: string[] })?.verification?.includes('inconclusive'))).toBe(true));
  });
});
