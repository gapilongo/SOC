import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { EscalationOut, Page } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import EscalationsPage from './EscalationsPage';

function escalation(id: string, status: string, assigned: string | null): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `alert-${id}`,
    level: 'L2',
    status,
    reason: `reason ${id}`,
    priority: 50,
    summary: { title: `Escalation ${id}` },
    assigned_to: assigned,
    sla_deadline: '2099-01-01T00:00:00Z',
    version: 3,
    created_at: '2026-09-29T10:00:00Z',
    updated_at: '2026-09-29T10:00:00Z',
  };
}

function card(title: string): HTMLElement {
  return screen.getByText(title).closest('li') as HTMLElement;
}

async function renderQueue(role: string, userId: string) {
  const page: Page<EscalationOut> = {
    items: [escalation('theirs', 'claimed', 'u-other'), escalation('late', 'expired', null), escalation('mine', 'claimed', userId)],
    next_cursor: null,
  };
  const { api } = fakeApi(() => page);
  const session = await signedInSession(api, { role, id: userId });
  renderWithSession(<EscalationsPage />, session);
  await screen.findByText('Escalation theirs');
}

describe('escalation queue gating mirrors the API', () => {
  it('stops an analyst deciding or claiming another analyst claim, but allows claiming an expired one', async () => {
    await renderQueue('analyst', 'u-1');
    const theirs = within(card('Escalation theirs'));
    expect(theirs.getByRole('button', { name: /Decide/ })).toBeDisabled();
    expect(theirs.getByText(/Claimed by another analyst/)).toBeInTheDocument();
    expect(theirs.queryByRole('button', { name: /Claim|Take over/ })).not.toBeInTheDocument();

    const late = within(card('Escalation late'));
    expect(late.getByRole('button', { name: 'Claim' })).toBeEnabled();
    expect(late.getByRole('button', { name: /Decide/ })).toBeEnabled();

    const mine = within(card('Escalation mine'));
    expect(mine.getByRole('button', { name: /Decide/ })).toBeEnabled();
    expect(mine.queryByRole('button', { name: /Claim|Take over/ })).not.toBeInTheDocument();
  });

  it('lets an admin take over and decide another analyst claim', async () => {
    await renderQueue('admin', 'u-9');
    const theirs = within(card('Escalation theirs'));
    expect(theirs.getByRole('button', { name: 'Take over' })).toBeEnabled();
    expect(theirs.getByRole('button', { name: /Decide/ })).toBeEnabled();
  });
});
