import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { ActionOut } from '../../api/types';
import { ResponseActions } from '../../pages/alerts/AlertDrawer';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { ActionControls, ActionDetails, canRecheck, canRetry } from './ActionDetails';
import { VerificationBadge } from './VerificationBadge';

function action(overrides: Partial<ActionOut> = {}): ActionOut {
  return {
    id: 'a-1',
    tenant_id: 'acme',
    alert_id: 'alert-1',
    action_type: 'isolate_host',
    target: 'ws-042',
    risk_level: 'high',
    status: 'succeeded',
    connector: 'microsoft',
    executed_at: '2026-09-30T10:00:00Z',
    created_at: '2026-09-30T09:59:00Z',
    updated_at: '2026-09-30T10:00:00Z',
    execution_owner: 'workflow',
    attempts: 1,
    verification: 'verified',
    verified_at: '2026-09-30T10:01:00Z',
    result: { summary: 'isolation requested', changed: true },
    external_ref: { steps: [{ machine: 'm1', status: 'Succeeded' }] },
    rollback: { available: true, action_type: 'release_host', risk: 'high', until: null, reason: null },
    rolled_back_by: null,
    ...overrides,
  };
}

describe('verification badge and eligibility', () => {
  it('renders each state with its reason', () => {
    const { rerender } = render(<VerificationBadge value="pending" />);
    expect(screen.getByText('pending')).toBeInTheDocument();
    rerender(<VerificationBadge value="inconclusive" detail={{ reason: 'permission_denied' }} />);
    expect(screen.getByText(/inconclusive \(Permission denied\)/i)).toBeInTheDocument();
    rerender(<VerificationBadge value={null} />);
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('knows which actions can be retried and re-checked', () => {
    expect(canRetry(action({ status: 'failed', result: { error: 'throttled', retryable: true } }))).toBe(true);
    expect(canRetry(action({ status: 'failed', result: { error: 'partial' } }))).toBe(true);
    expect(canRetry(action({ status: 'failed', result: { error: 'invalid_target', retryable: false } }))).toBe(false);
    expect(canRetry(action({ status: 'failed', connector: 'webhook', result: { retryable: true } }))).toBe(false);
    // A partial failure being rolled back is not retried (the retry would redo what the rollback undoes).
    expect(canRetry(action({ status: 'failed', result: { error: 'partial' }, rolled_back_by: 'rollback-1' }))).toBe(false);
    expect(canRecheck(action())).toBe(true);
    expect(canRecheck(action({ verification: 'pending' }))).toBe(false);
    expect(canRecheck(action({ connector: 'webhook' }))).toBe(false);
  });

  it('shows the details: summary, steps, lineage and rollback availability', async () => {
    const { api } = fakeApi(() => ({}));
    renderWithSession(<ActionDetails action={action({ rollback_of: 'orig-1234567890' })} />, await signedInSession(api));
    expect(screen.getByText('isolation requested')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Steps' })).toBeInTheDocument();
    expect(screen.getByText('orig-123...')).toBeInTheDocument();
    expect(screen.getByText(/available \(Release host\)/)).toBeInTheDocument();
  });

  it('explains that a deleted integration can no longer roll back its actions', async () => {
    const { api } = fakeApi(() => ({}));
    const orphan = action({ integration_id: null, rollback: { available: false, reason: 'integration_gone' } });
    renderWithSession(<ActionDetails action={orphan} />, await signedInSession(api));
    expect(screen.getByText(/integration that executed this action was deleted/)).toBeInTheDocument();
  });
});

describe('rollback, retry and re-check', () => {
  it('an analyst requests a rollback that needs an admin', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'POST' && path === '/actions/a-1/rollback') {
        return { rollback: action({ id: 'r-1', action_type: 'release_host', status: 'awaiting_approval' }), original: action(), created: true };
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    renderWithSession(<ActionControls action={action()} />, await signedInSession(api, { role: 'analyst' }));
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Roll back' }));
    const dialog = await screen.findByRole('dialog', { name: /Roll back Isolate host/i });
    expect(within(dialog).getByText(/Needs admin approval/)).toBeInTheDocument();
    const submit = within(dialog).getByRole('button', { name: 'Request rollback' });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'host reimaged');
    await userEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.path === '/actions/a-1/rollback')).toBe(true));
    expect(calls.find((c) => c.path === '/actions/a-1/rollback')?.body).toEqual({ reason: 'host reimaged', approve: true });
    expect(await screen.findByText(/Rollback requested: Release host/i)).toBeInTheDocument();
  });

  it('an admin sees that they approve the rollback and can retry and re-check', async () => {
    const { api, calls } = fakeApi((_method, path) => {
      if (path === '/actions/a-2/retry') return action({ id: 'a-2', status: 'executing' });
      if (path === '/actions/a-1/verify') return action({ verification: 'pending' });
      throw apiError(409, 'conflict');
    });
    const session = await signedInSession(api, { role: 'admin' });
    const failed = action({ id: 'a-2', status: 'failed', verification: null, result: { error: 'throttled', retryable: true },
                            rollback: { available: false, reason: 'not_executed' } });
    const { unmount } = renderWithSession(<ActionControls action={failed} />, session);
    expect(screen.queryByRole('button', { name: 'Roll back' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    const dialog = await screen.findByRole('dialog', { name: /Retry Isolate host/i });
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'throttling is over');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry action' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/actions/a-2/retry')?.body).toEqual({ reason: 'throttling is over' }));
    unmount();

    renderWithSession(<ActionControls action={action()} />, session);
    await userEvent.click(screen.getByRole('button', { name: 'Roll back' }));
    expect(await screen.findByText(/Approved by you/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await userEvent.click(screen.getByRole('button', { name: 'Re-check' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/actions/a-1/verify')).toBe(true));
  });

  it('viewers get no controls', async () => {
    const { api } = fakeApi(() => ({}));
    renderWithSession(<ActionControls action={action()} />, await signedInSession(api, { role: 'viewer' }));
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });
});

describe('alert drawer response actions', () => {
  it("lists the alert's actions with verification and expandable details", async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/actions') return { items: [action(), action({ id: 'a-3', action_type: 'block_ip', target: '185.220.101.44', verification: null, connector: 'webhook' })] };
      throw new Error(`unexpected ${method} ${path}`);
    });
    renderWithSession(<ResponseActions alertId="alert-1" />, await signedInSession(api, { role: 'analyst' }));
    expect(await screen.findByText('ws-042')).toBeInTheDocument();
    expect(calls[0].query).toMatchObject({ alert_id: 'alert-1' });
    expect(screen.getByText('verified')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Show details of Isolate host on ws-042/i }));
    expect(screen.getByText('isolation requested')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Roll back' }).length).toBe(2);
  });
});
