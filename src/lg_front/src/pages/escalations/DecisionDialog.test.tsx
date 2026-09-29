import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { DecisionIn, EscalationOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { DecisionDialog } from './DecisionDialog';

function escalation(overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id: 'esc-1',
    tenant_id: 'acme',
    alert_id: 'alert-1',
    level: 'L2',
    status: 'claimed',
    reason: 'low confidence',
    priority: 7,
    summary: { title: 'Suspicious PowerShell' },
    version: 3,
    created_at: '2026-09-29T10:00:00Z',
    updated_at: '2026-09-29T10:00:00Z',
    ...overrides,
  };
}

const decided = (e: EscalationOut) => ({ escalation: { ...e, status: 'decided' }, approved_actions: [], resumed_alert_ids: ['alert-1'], own_review_alert_ids: [], resumes_enqueued: 1, resumes_failed: 0 });

describe('DecisionDialog', () => {
  it('sends the version it was opened with and closes on success', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'POST' && path === '/escalations/esc-1/decision') return decided(escalation());
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api);
    const onClose = vi.fn();
    renderWithSession(<DecisionDialog escalation={escalation()} onClose={onClose} />, session);

    await userEvent.click(screen.getByLabelText('False positive'));
    await userEvent.click(screen.getByLabelText(/Suggest a suppression rule/));
    await userEvent.type(screen.getByLabelText('Notes'), 'known admin script');
    await userEvent.click(screen.getByRole('button', { name: 'Submit decision' }));

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const body = calls[0].body as DecisionIn;
    expect(body).toMatchObject({ decision: 'false_positive', version: 3, notes: 'known admin script', suggest_suppression: true, approved_actions: [] });
  });

  it('re-reads the escalation on 409, keeps the input, and retries with the new version', async () => {
    let attempts = 0;
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'POST' && path === '/escalations/esc-1/decision') {
        attempts += 1;
        if (attempts === 1) throw apiError(409, 'conflict', 'stale version');
        return decided(escalation({ version: 4 }));
      }
      if (method === 'GET' && path === '/escalations/esc-1') return escalation({ version: 4, assigned_to: 'u-2' });
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api);
    const onClose = vi.fn();
    renderWithSession(<DecisionDialog escalation={escalation()} onClose={onClose} />, session);

    await userEvent.type(screen.getByLabelText('Notes'), 'confirmed with owner');
    await userEvent.type(screen.getByLabelText(/Pre-approve response actions/), 'isolate_host:ws-042');
    await userEvent.click(screen.getByRole('button', { name: 'Submit decision' }));

    expect(await screen.findByText(/changed while you were reviewing it/)).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Notes')).toHaveValue('confirmed with owner');

    await userEvent.click(screen.getByRole('button', { name: 'Submit decision' }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const posts = calls.filter((c) => c.method === 'POST').map((c) => c.body as DecisionIn);
    expect(posts.map((b) => b.version)).toEqual([3, 4]);
    expect(posts[1]).toMatchObject({ decision: 'true_positive', notes: 'confirmed with owner', approved_actions: ['isolate_host:ws-042'] });
  });

  it('blocks resubmission when the escalation was decided by someone else', async () => {
    const { api } = fakeApi((method, path) => {
      if (method === 'POST') throw apiError(409, 'conflict');
      if (path === '/escalations/esc-1') return escalation({ version: 5, status: 'decided', decision: 'true_positive' });
      throw new Error('unexpected');
    });
    const session = await signedInSession(api);
    renderWithSession(<DecisionDialog escalation={escalation()} onClose={() => undefined} />, session);
    await userEvent.click(screen.getByRole('button', { name: 'Submit decision' }));
    expect(await screen.findByText(/can no longer be decided/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit decision' })).toBeDisabled();
  });

  it('shows other API errors with their request id', async () => {
    const { api } = fakeApi(() => {
      throw apiError(403, 'forbidden', 'actions above your approval authority', 'req-forbid-001');
    });
    const session = await signedInSession(api);
    renderWithSession(<DecisionDialog escalation={escalation()} onClose={() => undefined} />, session);
    await userEvent.click(screen.getByRole('button', { name: 'Submit decision' }));
    expect(await screen.findByText('actions above your approval authority')).toBeInTheDocument();
    expect(screen.getByText('req-forbid-001')).toBeInTheDocument();
  });
});
