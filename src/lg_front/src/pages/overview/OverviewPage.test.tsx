import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { DashboardOut, EscalationOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { handledFigure, mttaFigure, mttrFigure, windowPhrase } from './figures';
import OverviewPage from './OverviewPage';

const minutesFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

function summary(overrides: Partial<DashboardOut> = {}): DashboardOut {
  return {
    window_hours: 24,
    since: '2026-11-05T12:00:00Z',
    generated_at: new Date().toISOString(),
    alerts_total: 105,
    by_status: { waiting_human: 103, waiting_approval: 1, closed: 1 },
    by_severity: { high: 34, medium: 36, low: 35 },
    by_disposition: { benign: 1 },
    mtta_s: 90,
    mttr_s: 600,
    acknowledged: 1,
    resolved: 12,
    open_escalations: 103,
    runs_by_status: { queued: 2 },
    queue_depth: 2,
    llm_cost_usd: 1.5,
    llm_tokens: 42000,
    llm_model: 'deep-model-test',
    handled_without_human: 0,
    needed_human: 1,
    handled_without_human_rate: 0,
    analyst_hours_saved: 0,
    minutes_per_alert: 15,
    unassigned_escalations: 96,
    unassigned_breaching: 3,
    overdue_escalations: 4,
    next_sla_deadline: minutesFromNow(250),
    open_escalations_by_severity: { high: 40, medium: 63 },
    pending_approvals_total: 2,
    pending_approvals_by_risk: { medium: 1, high: 1 },
    pending_approvals: 1,
    my_claimed: 4,
    ...overrides,
  };
}

function escalation(id: string, overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `a-${id}`,
    level: 'L1',
    status: 'open',
    reason: 'Low confidence',
    priority: 1,
    version: 1,
    created_at: minutesFromNow(-600),
    updated_at: minutesFromNow(-600),
    ...overrides,
  };
}

const ESCALATIONS = [
  escalation('e-1', {
    summary: { title: 'Unusual sign-in pattern' },
    alert_severity: 'high',
    sla_deadline: minutesFromNow(-134),
    entities_preview: { items: [{ kind: 'user', value: 'j.moreau@acme.example' }], counts: { user: 1 } },
    routing: null,
    ai_reason_source: null,
  }),
  escalation('e-2', { rule: 'Phishing link clicked', sla_deadline: minutesFromNow(30), assigned_to: 'u-1', status: 'claimed' }),
  escalation('e-3', { summary: { title: 'Impossible travel', severity: 'medium' }, sla_deadline: minutesFromNow(700), assigned_to: 'u-9', assigned_to_email: 'n.haddad@acme.example' }),
];

function handler(dash: () => DashboardOut) {
  return (method: string, path: string) => {
    if (method === 'GET' && path === '/dashboard/summary') return dash();
    if (method === 'GET' && path === '/escalations') return { items: ESCALATIONS, next_cursor: null };
    if (method === 'GET' && path === '/onboarding/status') return { dismissed: true, complete: false, steps: [] };
    throw new Error(`unexpected ${method} ${path}`);
  };
}

describe('OverviewPage', () => {
  it("puts the analyst's work first and says what each figure counts", async () => {
    const { api, calls } = fakeApi(handler(() => summary()));
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);

    expect(await screen.findByRole('heading', { name: 'Overview', level: 1 })).toBeInTheDocument();
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(within(now).getByText('96')).toBeInTheDocument();
    expect(within(now).getByText('3 breaching SLA')).toBeInTheDocument();
    expect(within(now).getByRole('link', { name: 'Triage breaching first' })).toHaveAttribute(
      'href',
      '/escalations?assigned_to=none&overdue=true&order=sla_deadline',
    );
    expect(await within(now).findByText(/past its deadline/)).toHaveTextContent('Most overdue: Unusual sign-in pattern, 2h 14m past its deadline.');
    expect(within(now).getByText('4')).toBeInTheDocument();
    expect(within(now).getByText('and 1 more in your queue')).toBeInTheDocument();
    expect(within(now).getByText(/of 2 pending · 1 needs an admin/)).toBeInTheDocument();
    expect(within(now).getByRole('list', { name: 'Pending approvals by risk' })).toHaveTextContent('high risk 1medium risk 1');
    expect(within(now).getByRole('link', { name: 'Review approvals' })).toHaveAttribute('href', '/approvals');

    // Window figures: small samples are not shown as rates or means.
    const window = screen.getByRole('region', { name: 'Last 24 hours' });
    expect(within(window).getByText('Alerts ingested').closest('div')).toHaveTextContent('105In the last 24 hours');
    expect(within(window).getByText('Handled without a human').closest('div')).toHaveTextContent('Not enough data (n=1');
    expect(within(window).getByText('Mean time to acknowledge').closest('div')).toHaveTextContent('Not enough data (n=1');
    expect(within(window).getByText('Mean time to resolve').closest('div')).toHaveTextContent('10m 00sOver 12 alerts closed in the last 24 hours');
    expect(within(window).getByText('Pending approvals').closest('div')).toHaveTextContent('Right now · 1 you can approve');

    expect(screen.getByRole('region', { name: 'Open escalations by severity' })).toHaveTextContent('Right now · 103 open or claimed escalations');
    expect(screen.getByRole('region', { name: 'Alert severity' })).toHaveTextContent('105 alerts ingested in the last 24 hours');
    expect(screen.getByRole('link', { name: 'high' })).toHaveAttribute('href', '/alerts?severity=high&from=2026-11-05T12%3A00%3A00Z');
    expect(screen.getByRole('link', { name: /Waiting for an analyst/ })).toHaveAttribute(
      'href',
      '/alerts?status=waiting_human&from=2026-11-05T12%3A00%3A00Z',
    );

    // The deadlines table: owner, entities, SLA state in words.
    const table = await screen.findByRole('table');
    const rows = within(table).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('2h 14m over · breaching');
    expect(rows[1]).toHaveTextContent('Unusual sign-in pattern · j.moreau@acme.example');
    expect(rows[1]).toHaveTextContent('Unassigned');
    expect(rows[2]).toHaveTextContent('at risk');
    expect(rows[2]).toHaveTextContent('You');
    expect(rows[3]).toHaveTextContent('n.haddad@acme.example');
    expect(rows[3]).toHaveTextContent('medium');
    expect(within(rows[1]).getByRole('link', { name: 'Unusual sign-in pattern' })).toHaveAttribute('href', '/escalations/e-1');

    // Analysts see no platform health and do not query the onboarding status.
    expect(screen.queryByRole('region', { name: /admins only/ })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === '/onboarding/status')).toBe(false);
    const escalationQueries = calls.filter((c) => c.path === '/escalations').map((c) => c.query);
    expect(escalationQueries).toContainEqual({ status: ['open', 'claimed'], assigned_to: 'me', order: 'sla_deadline', cursor: undefined, limit: 3 });
    expect(escalationQueries).toContainEqual({ status: ['open', 'claimed'], order: 'sla_deadline', cursor: undefined, limit: 5 });

    await userEvent.click(screen.getByRole('radio', { name: 'Last 7 days' }));
    await waitFor(() => expect(calls.filter((c) => c.path === '/dashboard/summary').at(-1)?.query).toEqual({ window_hours: 168 }));
  });

  it('shows admins the platform health and the setup banner', async () => {
    const { api, calls } = fakeApi(handler(() => summary({ unassigned_breaching: 0, pending_approvals: 0, pending_approvals_total: 0, pending_approvals_by_risk: {} })));
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<OverviewPage />, session);

    const admin = await screen.findByRole('region', { name: 'Platform health · admins only' });
    expect(within(admin).getByText('Queue depth').closest('div')).toHaveTextContent('2Workflow runs waiting to start, right now');
    expect(within(admin).getByText('LLM cost').closest('div')).toHaveTextContent('42,000 tokens in the last 24 hours · deep-model-test');
    expect(within(admin).getByRole('table', { name: /Worker health/ })).toHaveTextContent('queued');
    expect(within(admin).getByRole('link', { name: 'benign' })).toHaveAttribute('href', '/alerts?disposition=benign&from=2026-11-05T12%3A00%3A00Z');
    expect(screen.getByRole('link', { name: 'Open the unassigned queue' })).toBeInTheDocument();
    expect(screen.getByText('Nothing waiting for approval.')).toBeInTheDocument();
    expect(screen.queryByText(/needs an admin/)).not.toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.path === '/onboarding/status')).toBe(true));
  });

  it('gives viewers the queue without the claim and approval cards', async () => {
    const { api } = fakeApi(handler(() => summary({ my_claimed: 0, llm_model: null })));
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<OverviewPage />, session);
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(within(now).queryByText('My claimed escalations')).not.toBeInTheDocument();
    expect(within(now).queryByText('Approvals you can act on')).not.toBeInTheDocument();
    expect(within(now).getByRole('link', { name: 'Triage breaching first' })).toBeInTheDocument();
  });

  it('shows an empty claim list and a clear queue', async () => {
    const { api } = fakeApi((method, path) => {
      if (path === '/dashboard/summary') return summary({ my_claimed: 0, unassigned_escalations: 0, unassigned_breaching: 0, next_sla_deadline: null, overdue_escalations: 0 });
      if (path === '/escalations') return { items: [], next_cursor: null };
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);
    expect(await screen.findByText(/You hold no escalations/)).toBeInTheDocument();
    expect(await screen.findByText('No open escalation. The queue is clear.')).toBeInTheDocument();
    expect(screen.getByText(/no deadline ahead/)).toBeInTheDocument();
  });

  it('omits the queue panels on an API without the queue figures', async () => {
    const older = summary();
    for (const k of ['unassigned_escalations', 'unassigned_breaching', 'pending_approvals_total', 'pending_approvals', 'my_claimed'] as const) delete older[k];
    const { api, calls } = fakeApi(handler(() => ({ ...older, alerts_total: 0, by_status: {}, by_severity: {} })));
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<OverviewPage />, session);
    expect(await screen.findByText(/No alerts were ingested in the last 24 hours/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Needs you now' })).not.toBeInTheDocument();
    expect(screen.queryByText('Pending approvals')).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === '/escalations')).toBe(false);
  });

  it('shows errors with a retry', async () => {
    const { api } = fakeApi(() => {
      throw apiError(503, 'unavailable', 'A backend service is unavailable.');
    });
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);
    expect(await screen.findByText('A backend service is unavailable.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('shows list errors inside their panels', async () => {
    const { api } = fakeApi((_m, path) => {
      if (path === '/dashboard/summary') return summary();
      throw apiError(500, 'internal', 'List failed.');
    });
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);
    await waitFor(() => expect(screen.getAllByText('List failed.')).toHaveLength(2));
  });
});

describe('figures', () => {
  it('names the window and guards small samples', () => {
    expect(windowPhrase(168)).toBe('the last 7 days');
    expect(windowPhrase(5)).toBe('the last 5 hours');
    const d = summary({ handled_without_human: 71, needed_human: 34, handled_without_human_rate: 0.676, acknowledged: 9, mtta_s: 420 });
    expect(handledFigure(d, 'the last 24 hours')).toEqual({ value: '68%', sub: '71 of 105 finished alerts ingested in the last 24 hours', enough: true });
    expect(mttaFigure(d, 'x')).toMatchObject({ value: '7m 00s', enough: true });
    expect(mttrFigure(summary({ resolved: 4 }), 'x')).toMatchObject({ value: '—', enough: false });
    expect(handledFigure(summary({ handled_without_human: 9, needed_human: 1, handled_without_human_rate: null }), 'x').enough).toBe(false);
  });
});
