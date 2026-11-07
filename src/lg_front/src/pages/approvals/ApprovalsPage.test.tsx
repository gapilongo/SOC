import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AppRoutes } from '../../app/App';
import type { ActionOut, UserOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import ApprovalsPage from './ApprovalsPage';

afterEach(() => {
  vi.unstubAllGlobals();
});

const NOW = new Date().toISOString();

function action(overrides: Partial<ActionOut> = {}): ActionOut {
  return {
    id: 'a-1',
    tenant_id: 'acme',
    alert_id: 'alert-1',
    action_type: 'isolate_host',
    target: 'ws-042',
    risk_level: 'high',
    status: 'awaiting_approval',
    requested_by: 'agent:workflow',
    created_at: NOW,
    updated_at: NOW,
    guardrail: { verdict: 'passed', evaluated: 'now', approval_reason: 'llm_only_evidence' },
    blast_radius: { target_kind: 'host', scope_hosts: ['ws-042'], hourly_limit: 5, executed_last_hour: 5, tenant_hourly_cap: 50, tenant_executed_last_hour: 12 },
    reversible: true,
    irreversible_note: null,
    ...overrides,
  };
}

const ISOLATE = action();
const BLOCK_IP = action({
  id: 'a-2',
  action_type: 'block_ip',
  target: '185.220.101.44',
  risk_level: 'medium',
  blast_radius: { target_kind: 'ip', scope_hosts: [], hourly_limit: null, executed_last_hour: 0, tenant_hourly_cap: 50, tenant_executed_last_hour: 12 },
});
const RESET = action({
  id: 'a-3',
  alert_id: 'alert-2',
  action_type: 'reset_password',
  target: 'j.moreau@acme.example',
  risk_level: 'medium',
  guardrail: { verdict: 'blocked', evaluated: 'now', code: 'protected_asset', reason: 'matches a protected user entry' },
  reversible: false,
  irreversible_note: 'The old password cannot be restored.',
});
const EXECUTED = action({
  id: 'x-1',
  alert_id: 'alert-9',
  action_type: 'disable_user',
  target: 'alice@contoso.example',
  risk_level: 'critical',
  status: 'succeeded',
  connector: 'microsoft',
  approved_by: 'policy:auto',
  executed_at: '2026-09-30T10:00:00Z',
  verification: 'failed',
  verification_detail: { reason: 'synced_user_reenabled' },
  result: { summary: 'account disabled', changed: true },
  rollback: { available: true, action_type: 'enable_user', risk: 'critical' },
  guardrail: null,
  blast_radius: { target_kind: 'user', scope_hosts: [] },
});
const FAILED = action({
  id: 'x-2',
  action_type: 'revoke_sessions',
  target: 'bob@contoso.example',
  risk_level: 'medium',
  status: 'failed',
  connector: 'microsoft',
  result: { error: 'throttled', retryable: true },
  rollback: { available: false, reason: 'not_executed' },
  guardrail: null,
});

const DASHBOARD = {
  unassigned_escalations: 0,
  pending_approvals: 2,
  pending_approvals_total: 3,
  pending_approvals_by_risk: { high: 1, medium: 2 },
};

/** Answers GET /actions by its status filter, the dashboard with `dashboard`, and POSTs with `post`. */
function approvalsApi({
  pending = [ISOLATE, BLOCK_IP, RESET],
  executed = [EXECUTED, FAILED],
  all = [EXECUTED],
  dashboard = DASHBOARD as unknown,
  post = (path: string): unknown => {
    throw new Error(`unexpected POST ${path}`);
  },
}: { pending?: ActionOut[]; executed?: ActionOut[]; all?: ActionOut[]; dashboard?: unknown; post?: (path: string, body: unknown) => unknown } = {}) {
  const fake = fakeApi((method, path, body) => {
    const query = (fake.calls[fake.calls.length - 1]?.query ?? {}) as { status?: string[] };
    if (method === 'GET' && path === '/actions') {
      if (query.status?.join() === 'awaiting_approval') return { items: pending, next_cursor: null };
      if (query.status?.includes('succeeded')) return { items: executed, next_cursor: null };
      return { items: all, next_cursor: null };
    }
    if (method === 'GET' && path === '/dashboard/summary') return dashboard;
    if (method === 'POST') return post(path, body);
    throw new Error(`unexpected ${method} ${path}`);
  });
  return fake;
}

async function renderPage(role: UserOut['role'], api = approvalsApi(), route = '/approvals') {
  const session = await signedInSession(api.api, { role });
  return { ...renderWithSession(<ApprovalsPage />, session, { route }), calls: api.calls };
}

function card(name: string): HTMLElement {
  return screen.getByRole('heading', { name, level: 3 }).closest('li') as HTMLElement;
}

describe('ApprovalsPage: pending approvals', () => {
  it('shows each pending action with its guardrail, blast radius and reversibility, and the queue figures', async () => {
    await renderPage('analyst');
    expect(await screen.findByRole('heading', { name: 'Approvals', level: 1 })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Isolate host', level: 3 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Pending · 3/, level: 2 })).toBeInTheDocument();

    const isolate = card('Isolate host');
    expect(within(isolate).getByText('high risk')).toBeInTheDocument();
    expect(within(isolate).getByText('ws-042', { selector: 'code' })).toBeInTheDocument();
    expect(within(isolate).getByText('1 host: ws-042')).toBeInTheDocument();
    expect(within(isolate).getByText('5 of 5 in the last hour')).toBeInTheDocument();
    expect(within(isolate).getByText(/limit reached/)).toBeInTheDocument();
    expect(within(isolate).getByText('12 of 50 in the last hour')).toBeInTheDocument();
    expect(within(isolate).getByText('Passed (checked now)')).toBeInTheDocument();
    expect(within(isolate).getByText(/model alone is never automatic/)).toBeInTheDocument();
    expect(within(isolate).getByText(/Yes, it can be rolled back/)).toBeInTheDocument();
    expect(within(isolate).getByText(/by the alert workflow/)).toBeInTheDocument();
    expect(within(isolate).getByRole('button', { name: 'Open alert alert-1' })).toBeInTheDocument();

    const reset = card('Reset password');
    expect(within(reset).getByText('Blocked (checked now)')).toBeInTheDocument();
    expect(within(reset).getByText(/protected assets list\. \(matches a protected user entry\)/)).toBeInTheDocument();
    expect(within(reset).getByText('No. The old password cannot be restored.')).toBeInTheDocument();

    const figures = screen.getByRole('region', { name: 'Approval queue' });
    expect(within(figures).getByText('You can approve').nextSibling).toHaveTextContent('2');
    expect(within(figures).getByText('Pending in total').nextSibling).toHaveTextContent('3');
    expect(within(within(figures).getByRole('list', { name: 'Pending approvals by risk' })).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'High 1',
      'Medium 2',
    ]);
  });

  it("locks what the analyst's role may not approve, with the reason, and keeps reject", async () => {
    await renderPage('analyst');
    const isolate = await screen.findByRole('heading', { name: 'Isolate host', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    const approve = within(isolate).getByRole('button', { name: 'Approve' });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAccessibleDescription('High risk needs an admin to approve.');
    expect(within(isolate).getByRole('button', { name: 'Reject' })).toBeEnabled();
    expect(within(card('Block ip')).getByRole('button', { name: 'Approve' })).toBeEnabled();
  });

  it('an admin approves, and the decision goes to the API with the toast', async () => {
    const api = approvalsApi({ post: (path) => ({ action: ISOLATE, resumed_alert_ids: ['alert-1'], resumes_enqueued: 1, resumes_failed: 0, path }) });
    const { calls } = await renderPage('admin', api);
    const isolate = await screen.findByRole('heading', { name: 'Isolate host', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    await userEvent.click(within(isolate).getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: 'Approve Isolate host' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve action' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/actions/a-1/approve')?.body).toEqual({ reject_remaining: false }));
    expect(await screen.findByText(/Approved isolate_host on ws-042\. The alert workflow resumed\./)).toBeInTheDocument();
  });

  it('warns before approving an action a guardrail blocks, and shows an API refusal in the dialog', async () => {
    const api = approvalsApi({
      post: () => {
        throw apiError(403, 'forbidden', 'medium risk action cannot be approved');
      },
    });
    const { calls } = await renderPage('admin', api);
    const reset = await screen.findByRole('heading', { name: 'Reset password', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    await userEvent.click(within(reset).getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: 'Approve Reset password' });
    expect(within(dialog).getByText('A guardrail blocks it right now')).toBeInTheDocument();
    expect(within(dialog).getByText(/It cannot be undone: The old password cannot be restored\./)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve action' }));
    expect(await within(dialog).findByText(/cannot be approved/)).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/actions/a-3/approve')).toBe(true);
  });

  it("rejects one action, or all of the alert's pending actions at once", async () => {
    const api = approvalsApi({ post: () => ({ action: ISOLATE, resumed_alert_ids: [], resumes_enqueued: 0, resumes_failed: 0 }) });
    const { calls } = await renderPage('analyst', api);
    const isolate = await screen.findByRole('heading', { name: 'Isolate host', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    // alert-2 has a single pending action: no "reject all" there.
    expect(within(card('Reset password')).queryByRole('button', { name: /Reject all/ })).not.toBeInTheDocument();

    await userEvent.click(within(isolate).getByRole('button', { name: 'Reject' }));
    let dialog = await screen.findByRole('dialog', { name: 'Reject Isolate host' });
    expect(within(dialog).getByLabelText("Reject the alert's other pending actions")).not.toBeChecked();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reject action' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/actions/a-1/reject')?.body).toEqual({ reject_remaining: false }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await userEvent.click(within(isolate).getByRole('button', { name: 'Reject all pending for this alert' }));
    dialog = await screen.findByRole('dialog', { name: 'Reject Isolate host' });
    expect(within(dialog).getByLabelText("Reject the alert's other pending actions")).toBeChecked();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reject action' }));
    await waitFor(() => expect(calls.filter((c) => c.path === '/actions/a-1/reject').at(-1)?.body).toEqual({ reject_remaining: true }));
  });

  it('a viewer sees the queue without buttons', async () => {
    await renderPage('viewer');
    const isolate = await screen.findByRole('heading', { name: 'Isolate host', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    expect(within(isolate).getByText('Requires the analyst role.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^(Approve|Reject)/ })).not.toBeInTheDocument();
    expect(screen.getByText(/approving and rejecting need the analyst role/)).toBeInTheDocument();
  });

  it('renders an older API: no guardrail, blast radius or reversibility, figures counted from the page', async () => {
    const old = action({ guardrail: undefined, blast_radius: undefined, reversible: undefined, irreversible_note: undefined, requested_by: undefined });
    await renderPage('analyst', approvalsApi({ pending: [old], executed: [], dashboard: { alerts_total: 0 } }));
    const isolate = await screen.findByRole('heading', { name: 'Isolate host', level: 3 }).then((h) => h.closest('li') as HTMLElement);
    for (const term of ['Guardrails', 'Blast radius', 'Reversible']) expect(within(isolate).queryByText(term)).not.toBeInTheDocument();
    expect(within(isolate).getByText('Target')).toBeInTheDocument();
    const figures = screen.getByRole('region', { name: 'Approval queue' });
    expect(within(figures).getByText('You can approve').nextSibling).toHaveTextContent('0');
    expect(within(figures).getByText('Pending in total').nextSibling).toHaveTextContent('1');
    expect(await screen.findByText('No action has been executed yet.')).toBeInTheDocument();
  });

  it('says when nothing is pending', async () => {
    await renderPage('analyst', approvalsApi({ pending: [], dashboard: { ...DASHBOARD, pending_approvals: 0, pending_approvals_total: 0, pending_approvals_by_risk: {} } }));
    expect(await screen.findByText('Nothing is waiting for approval.')).toBeInTheDocument();
    expect(screen.getByText('None pending')).toBeInTheDocument();
  });
});

describe('ApprovalsPage: recently executed', () => {
  it('shows status and verification, and an admin rolls back and retries', async () => {
    const api = approvalsApi({
      post: (path) => {
        if (path === '/actions/x-1/rollback') return { rollback: action({ id: 'r-1', action_type: 'enable_user', status: 'approved' }), original: EXECUTED, created: true };
        if (path === '/actions/x-2/retry') return { ...FAILED, status: 'executing' };
        throw new Error(`unexpected POST ${path}`);
      },
    });
    const { calls } = await renderPage('admin', api);
    const table = await screen.findByRole('table', { name: 'Recently executed actions' });
    const row = within(table).getByText('alice@contoso.example').closest('tr') as HTMLElement;
    expect(within(row).getByText(/failed \(Synced user reenabled\)/i)).toBeInTheDocument();
    expect(within(row).getByText('Automatic (autonomy policy)', { exact: false })).toBeInTheDocument();
    expect(within(row).getByText('succeeded')).toBeInTheDocument();

    await userEvent.click(within(row).getByRole('button', { name: 'Roll back' }));
    const dialog = await screen.findByRole('dialog', { name: 'Roll back Disable user' });
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'false positive');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Request rollback' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/actions/x-1/rollback')?.body).toEqual({ reason: 'false positive', approve: true }));
    expect(await screen.findByText(/Rollback requested: Enable user \(approved and queued\)/)).toBeInTheDocument();

    const failed = within(table).getByText('bob@contoso.example').closest('tr') as HTMLElement;
    await userEvent.click(within(failed).getByRole('button', { name: 'Retry' }));
    const retry = await screen.findByRole('dialog', { name: 'Retry Revoke sessions' });
    await userEvent.type(within(retry).getByLabelText(/Reason/), 'throttling is over');
    await userEvent.click(within(retry).getByRole('button', { name: 'Retry action' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/actions/x-2/retry')?.body).toEqual({ reason: 'throttling is over' }));
  });

  it('explains why an executed action has no rollback, and notes dry runs', async () => {
    const irreversible = { ...EXECUTED, id: 'x-3', target: 'carol@contoso.example', rollback: { available: false, reason: 'irreversible' } };
    const dry = { ...EXECUTED, id: 'x-4', target: 'dave@contoso.example', status: 'dry_run', rollback: { available: false, reason: 'not_executed' } };
    await renderPage('analyst', approvalsApi({ executed: [irreversible, dry] }));
    const table = await screen.findByRole('table', { name: 'Recently executed actions' });
    expect(within(table).getByText('This action cannot be undone.')).toBeInTheDocument();
    expect(within(table).getByText(/Recorded only \(dry run\)/)).toBeInTheDocument();
  });

  it('links to all executed actions when there are more than it shows', async () => {
    const many = Array.from({ length: 12 }, (_, i) => ({ ...EXECUTED, id: `x-${i}`, target: `user${i}@contoso.example` }));
    const { calls } = await renderPage('analyst', approvalsApi({ executed: many }));
    await userEvent.click(await screen.findByRole('button', { name: 'Show all executed actions' }));
    expect(await screen.findByRole('heading', { name: 'All actions', level: 2 })).toBeInTheDocument();
    await waitFor(() =>
      expect(calls.some((c) => c.path === '/actions' && (c.query as { status?: string[] }).status?.join() === 'succeeded,failed,dry_run')).toBe(true),
    );
  });
});

describe('ApprovalsPage: all actions', () => {
  it('keeps the ledger: verification, details, filters and the alert drawer', async () => {
    const { calls } = await renderPage('admin', approvalsApi(), '/approvals?view=all');
    const table = await screen.findByRole('table', { name: 'Response actions' });
    const row = within(table).getByText('alice@contoso.example').closest('tr') as HTMLElement;
    expect(within(row).getByText(/failed \(Synced user reenabled\)/i)).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: 'Roll back' })).toBeInTheDocument();
    await userEvent.click(within(row).getByRole('button', { name: /Show details of Disable user/i }));
    expect(screen.getByText('account disabled')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Verification: Any' }));
    await userEvent.click(screen.getByRole('option', { name: 'Inconclusive' }));
    await waitFor(() => expect(calls.some((c) => (c.query as { verification?: string[] })?.verification?.includes('inconclusive'))).toBe(true));
  });

  it('switches between the two views', async () => {
    await renderPage('analyst');
    await screen.findByRole('heading', { name: 'Isolate host', level: 3 });
    await userEvent.click(screen.getByRole('radio', { name: 'All actions' }));
    expect(await screen.findByRole('table', { name: 'Response actions' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'Pending and recent' }));
    expect(await screen.findByRole('heading', { name: 'Isolate host', level: 3 })).toBeInTheDocument();
  });

  it('offers approve and reject in the ledger as the role allows', async () => {
    await renderPage('analyst', approvalsApi({ all: [ISOLATE, BLOCK_IP] }), '/approvals?view=all');
    const table = await screen.findByRole('table', { name: 'Response actions' });
    const high = within(table).getByText('ws-042').closest('tr') as HTMLElement;
    expect(within(high).queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(within(high).getByText('High risk needs an admin to approve.')).toBeInTheDocument();
    const medium = within(table).getByText('185.220.101.44').closest('tr') as HTMLElement;
    await userEvent.click(within(medium).getByRole('button', { name: 'Approve' }));
    expect(await screen.findByRole('dialog', { name: 'Approve Block ip' })).toBeInTheDocument();
  });
});

describe('the /actions route', () => {
  it('redirects to /approvals, keeping the ledger filters', async () => {
    // No live socket in this test.
    vi.stubGlobal(
      'WebSocket',
      class {
        readyState = 0;
        onopen = null;
        onmessage = null;
        onclose = null;
        onerror = null;
        close() {}
      },
    );
    const api = approvalsApi();
    const session = await signedInSession(api.api, { role: 'analyst' });
    renderWithSession(<AppRoutes />, session, { route: '/actions?status=awaiting_approval' });
    expect(await screen.findByRole('heading', { name: 'Approvals', level: 1 })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Isolate host', level: 3 })).toBeInTheDocument();
  });

  it('opens the All actions view for any other ledger query', async () => {
    vi.stubGlobal('WebSocket', class { readyState = 0; close() {} });
    const api = approvalsApi();
    const session = await signedInSession(api.api, { role: 'analyst' });
    renderWithSession(<AppRoutes />, session, { route: '/actions?risk_level=critical' });
    expect(await screen.findByRole('table', { name: 'Response actions' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Risk: Critical' })).toBeInTheDocument();
  });
});
