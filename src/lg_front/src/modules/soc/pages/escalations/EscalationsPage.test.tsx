import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { BulkCloseIn, BulkItemIn, EscalationGroupsOut, EscalationOut } from '../../../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import EscalationsPage from './EscalationsPage';

const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

function escalation(id: string, overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `alert-${id}`,
    level: 'L1',
    status: 'open',
    reason: `reason ${id}`,
    priority: 50,
    summary: { title: `Escalation ${id}` },
    assigned_to: null,
    sla_deadline: inMinutes(600),
    version: 3,
    created_at: inMinutes(-600),
    updated_at: inMinutes(-600),
    ...overrides,
  };
}

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown, query: Record<string, unknown>) => unknown;

async function renderQueue(items: EscalationOut[], { role = 'analyst', id = 'u-1', route = '/escalations', handler }: { role?: string; id?: string; route?: string; handler?: Handler } = {}) {
  const { api, calls } = fakeApi((method, path, body) => {
    const query = (calls[calls.length - 1]?.query ?? {}) as Record<string, unknown>;
    const answer = handler?.(method, path, body, query);
    if (answer !== undefined) return answer;
    if (method === 'GET' && path === '/escalations') return { items, next_cursor: null };
    if (path.startsWith('/dashboard')) return { overdue_escalations: 2, unassigned_escalations: 5 };
    return {};
  });
  const session = await signedInSession(api, { role, id });
  const view = renderWithSession(
    <>
      <Routes>
        <Route path="/escalations" element={<EscalationsPage />} />
        <Route path="/escalations/:id" element={<p>decision page</p>} />
      </Routes>
      <LocationProbe />
    </>,
    session,
    { route },
  );
  return { ...view, calls };
}

const listQueries = (calls: Array<{ method: string; path: string; query?: unknown }>) =>
  calls.filter((c) => c.method === 'GET' && c.path === '/escalations').map((c) => c.query as Record<string, unknown>);

const row = (title: string) => screen.getByRole('link', { name: title }).closest('tr') as HTMLElement;

describe('escalation queue URL filters', () => {
  it('lists in SLA order by default, waiting statuses, pages of 50', async () => {
    const { calls } = await renderQueue([escalation('a')]);
    await screen.findByRole('link', { name: 'Escalation a' });
    expect(listQueries(calls)[0]).toMatchObject({ status: ['open', 'claimed', 'expired'], order: 'sla_deadline', limit: 50 });
    expect(screen.getByRole('link', { name: 'All waiting' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByText('Overdue first, then by time left on the SLA.')).toBeInTheDocument();
  });

  it('sends the Overview link filters to the API and marks the view', async () => {
    const { calls } = await renderQueue([], { route: '/escalations?assigned_to=none&overdue=true&order=sla_deadline&level=L2' });
    await screen.findByText('Nothing in this view');
    expect(listQueries(calls)[0]).toMatchObject({ assigned_to: 'none', overdue: true, order: 'sla_deadline', level: ['L2'] });
    expect(screen.getByRole('link', { name: 'Show my claimed escalations' })).toHaveAttribute('href', '/escalations?assigned_to=me');
    // Breaching count from the dashboard figures, read with its meaning.
    expect(screen.getByRole('link', { name: /Breaching/ })).toHaveTextContent('2 past their deadline');
  });

  it('writes views, the order and the grouping into the URL', async () => {
    const user = userEvent.setup();
    await renderQueue([escalation('a')], { route: '/escalations?level=L1' });
    await screen.findByRole('link', { name: 'Escalation a' });
    await user.click(screen.getByRole('link', { name: 'Mine' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations?assigned_to=me');
    await user.click(screen.getByRole('radio', { name: 'Newest first' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations?assigned_to=me&order=created_at');
    expect(screen.getByText('Newest first.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Group by rule: off' }));
    expect(screen.getByTestId('location')).toHaveTextContent('group=rule');
    expect(screen.getByRole('button', { name: 'Group by rule: on' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('shows a rule filter that can be removed', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue([escalation('a')], { route: '/escalations?source_id=s-1&rule=Spray' });
    await screen.findByRole('link', { name: 'Escalation a' });
    expect(listQueries(calls)[0]).toMatchObject({ source_id: 's-1', rule: 'Spray' });
    await user.click(screen.getByRole('button', { name: 'Remove the rule filter' }));
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/escalations$/);
  });
});

describe('escalation queue rows', () => {
  const items = () => [
    escalation('late', {
      sla_deadline: inMinutes(-30),
      alert_severity: 'high',
      ai_reason: 'TOR sign-in after a Lyon login.',
      ai_reason_source: 'model',
      routing: { code: 'grey_zone', confidence: 42, band: { min: 20, max: 60 } },
      entities_preview: { items: [{ kind: 'user', value: 'j.doe@acme.example' }], counts: { user: 1 } },
    }),
    escalation('theirs', { status: 'claimed', assigned_to: 'u-other', assigned_to_email: 'other@acme.example', routing: { code: 'false_positive_review' } }),
    escalation('mine', { status: 'claimed', assigned_to: 'u-1' }),
    escalation('done', { status: 'decided', decision: 'false_positive', decided_by: 'u-1', decided_at: inMinutes(-5) }),
  ];

  it('shows SLA, severity, entities, owner, routing against its band and the AI reason', async () => {
    await renderQueue(items());
    const late = within(await waitFor(() => row('Escalation late')));
    expect(late.getByText(/over/)).toHaveTextContent(/breaching/);
    expect(late.getByText('high')).toBeInTheDocument();
    expect(late.getByText('j.doe@acme.example')).toBeInTheDocument();
    expect(late.getByText('42%')).toBeInTheDocument();
    expect(late.getByText('band 20–60')).toBeInTheDocument();
    expect(late.getByText('TOR sign-in after a Lyon login.')).toBeInTheDocument();
    expect(late.getByText('by the model')).toBeInTheDocument();
    expect(late.getByText('Unassigned')).toBeInTheDocument();
    expect(within(row('Escalation theirs')).getByText('other@acme.example')).toBeInTheDocument();
    expect(within(row('Escalation theirs')).getByText('False-positive review')).toBeInTheDocument();
    expect(within(row('Escalation mine')).getByText('You')).toBeInTheDocument();
    expect(within(row('Escalation done')).getByText('False positive')).toBeInTheDocument();
    expect(within(row('Escalation done')).getByText('Decided by You')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Escalation late' })).toHaveAttribute('href', '/escalations/late');
  });

  it('offers Claim on unassigned rows, Decide on yours, and no take-over to an analyst', async () => {
    await renderQueue(items());
    await waitFor(() => row('Escalation late'));
    expect(within(row('Escalation late')).getByRole('button', { name: 'Claim Escalation late' })).toBeEnabled();
    expect(within(row('Escalation theirs')).queryByRole('button')).not.toBeInTheDocument();
    expect(within(row('Escalation mine')).getByRole('link', { name: 'Decide Escalation mine' })).toHaveAttribute('href', '/escalations/mine');
    expect(within(row('Escalation done')).queryByRole('button')).not.toBeInTheDocument();
  });

  it('lets an admin take over, and claims with the version shown', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(items(), {
      role: 'admin',
      id: 'u-9',
      handler: (method, path) => (method === 'POST' && path === '/escalations/theirs/claim' ? escalation('theirs', { assigned_to: 'u-9' }) : undefined),
    });
    await waitFor(() => row('Escalation theirs'));
    await user.click(within(row('Escalation theirs')).getByRole('button', { name: 'Take over Escalation theirs' }));
    expect(await screen.findByText('Escalation taken over.')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/escalations/theirs/claim')?.body).toEqual({ version: 3 });
  });

  it('reports a claim conflict without failing', async () => {
    const user = userEvent.setup();
    await renderQueue(items(), {
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/late/claim') throw apiError(409, 'conflict');
        return undefined;
      },
    });
    await waitFor(() => row('Escalation late'));
    await user.click(within(row('Escalation late')).getByRole('button', { name: 'Claim Escalation late' }));
    expect(await screen.findByText(/Someone else changed this escalation first/)).toBeInTheDocument();
  });

  it('says a decided escalation is no longer claimable, and repeated failures show one notice', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(items(), {
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/late/claim') throw apiError(409, 'invalid_transition');
        return undefined;
      },
    });
    await waitFor(() => row('Escalation late'));
    const claim = () => within(row('Escalation late')).getByRole('button', { name: 'Claim Escalation late' });
    await user.click(claim());
    expect(await screen.findByText('This escalation is already decided or closed; the list has been refreshed.')).toBeInTheDocument();
    expect(screen.queryByText(/Someone else changed this escalation first/)).not.toBeInTheDocument();
    await waitFor(() => expect(claim()).toBeEnabled());
    await user.click(claim());
    await waitFor(() => expect(calls.filter((c) => c.path === '/escalations/late/claim')).toHaveLength(2));
    expect(screen.getAllByText(/already decided or closed/)).toHaveLength(1);
  });

  it('gives a viewer neither checkboxes nor bulk actions nor claims', async () => {
    await renderQueue(items(), { role: 'viewer' });
    await waitFor(() => row('Escalation late'));
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Claim/ })).not.toBeInTheDocument();
  });
});

describe('bulk triage', () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => escalation(`e${i}`, { version: i + 1 }));

  it('selects up to 50 with the header checkbox and claims them, listing per-item failures', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(many(52), {
      handler: (method, path) =>
        method === 'POST' && path === '/escalations/bulk/claim'
          ? {
              succeeded: 49,
              failed: 1,
              results: [
                { escalation_id: 'e0', ok: true },
                { escalation_id: 'e3', ok: false, error: { status: 409, code: 'conflict', message: 'The escalation changed.' } },
              ],
            }
          : undefined,
    });
    await screen.findByRole('link', { name: 'Escalation e0' });
    const bar = within(screen.getByRole('region', { name: 'Bulk actions' }));
    expect(bar.getByRole('button', { name: 'Claim' })).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: 'Select the escalations shown (at most 50)' }));
    expect(bar.getByText(/50 selected/)).toHaveTextContent('at most 50 at a time');
    expect(screen.getByRole('checkbox', { name: 'Select Escalation e51' })).toBeDisabled();
    await user.click(bar.getByRole('button', { name: 'Claim 50' }));
    const result = await screen.findByText('Claim: 49 succeeded, 1 failed');
    const panel = result.closest('[role="status"]') as HTMLElement;
    expect(within(panel).getByRole('list', { name: 'Failed escalations' })).toHaveTextContent('Escalation e3: The escalation changed.');
    const items = (calls.find((c) => c.path === '/escalations/bulk/claim')?.body as { items: BulkItemIn[] }).items;
    expect(items).toHaveLength(50);
    expect(items[1]).toEqual({ escalation_id: 'e1', version: 2 });
    // The selection is cleared after the request.
    expect(bar.getByText('0 selected')).toBeInTheDocument();
    await user.click(within(panel).getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('Claim: 49 succeeded, 1 failed')).not.toBeInTheDocument();
  });

  it('closes N with a required note and a chosen verdict, optionally proposing a suppression', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(many(3), {
      handler: (method, path) =>
        method === 'POST' && path === '/escalations/bulk/close'
          ? { succeeded: 2, failed: 0, results: [], suppression: { id: 's-1', name: 'Spray from scanner' }, suppression_created: true }
          : undefined,
    });
    await screen.findByRole('link', { name: 'Escalation e0' });
    await user.click(screen.getByRole('checkbox', { name: 'Select Escalation e0' }));
    await user.click(screen.getByRole('checkbox', { name: 'Select Escalation e2' }));
    await user.click(screen.getByRole('button', { name: 'Close 2…' }));
    const dialog = within(screen.getByRole('dialog', { name: 'Close 2 escalations' }));
    await user.click(dialog.getByRole('button', { name: 'Close 2' }));
    expect(dialog.getByText('Choose false positive or benign positive.')).toBeInTheDocument();
    expect(dialog.getByText(/A note is required/)).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/escalations/bulk/close')).toBe(false);
    await user.click(dialog.getByRole('radio', { name: 'Benign positive' }));
    await user.type(dialog.getByLabelText('Note (required)'), '  known scanner  ');
    await user.click(dialog.getByLabelText('Propose a suppression rule from these escalations'));
    await user.click(dialog.getByRole('button', { name: 'Close 2' }));
    expect(await screen.findByText('Close: 2 succeeded, 0 failed')).toBeInTheDocument();
    expect(screen.getByText(/Proposed a disabled suppression rule/)).toHaveTextContent('Spray from scanner');
    const body = calls.find((c) => c.path === '/escalations/bulk/close')?.body as BulkCloseIn;
    expect(body).toEqual({
      items: [
        { escalation_id: 'e0', version: 1 },
        { escalation_id: 'e2', version: 3 },
      ],
      notes: 'known scanner',
      decision: 'benign_positive',
      propose_suppression: true,
    });
  });

  it('shows which escalations do not qualify when a suppression proposal is refused', async () => {
    const user = userEvent.setup();
    let attempt = 0;
    await renderQueue(many(2), {
      route: '/escalations?status=decided&decided_by=me',
      handler: (method, path) => {
        if (method !== 'POST' || path !== '/escalations/bulk/propose-suppression') return undefined;
        attempt += 1;
        if (attempt === 1) {
          throw apiError(422, 'not_confirmed_benign', 'every escalation needs a benign decision');
        }
        return { suppression: { id: 's-2', name: 'Proposed rule' }, created: true, escalation_ids: ['e0'] };
      },
    });
    await screen.findByRole('link', { name: 'Escalation e0' });
    await user.click(screen.getByRole('checkbox', { name: 'Select the escalations shown (at most 50)' }));
    await user.click(screen.getByRole('button', { name: 'Propose suppression…' }));
    const dialog = within(screen.getByRole('dialog', { name: 'Propose a suppression rule' }));
    await user.type(dialog.getByLabelText('Rule name (optional)'), 'Proposed rule');
    await user.click(dialog.getByRole('button', { name: 'Propose rule' }));
    const refused = await dialog.findByRole('alert');
    expect(refused).toHaveTextContent('Not every escalation qualifies');
    expect(within(refused).getByRole('list', { name: 'Escalations that do not qualify' })).toHaveTextContent('Escalation e0');
    await user.click(dialog.getByRole('button', { name: 'Propose rule' }));
    expect(await screen.findByText('Suppression rule “Proposed rule” proposed')).toBeInTheDocument();
  });

  it('lists the refused ids from the error details', async () => {
    const user = userEvent.setup();
    const { ApiError } = await import('../../../../api/client');
    await renderQueue(many(2), {
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/bulk/propose-suppression') {
          throw new ApiError({ status: 422, code: 'not_confirmed_benign', message: 'no', requestId: null, details: [{ escalation_id: 'e1' }] });
        }
        return undefined;
      },
    });
    await screen.findByRole('link', { name: 'Escalation e0' });
    await user.click(screen.getByRole('checkbox', { name: 'Select the escalations shown (at most 50)' }));
    await user.click(screen.getByRole('button', { name: 'Propose suppression…' }));
    const dialog = within(screen.getByRole('dialog', { name: 'Propose a suppression rule' }));
    await user.click(dialog.getByRole('button', { name: 'Propose rule' }));
    const list = await dialog.findByRole('list', { name: 'Escalations that do not qualify' });
    expect(list).toHaveTextContent('Escalation e1');
    expect(list).not.toHaveTextContent('Escalation e0');
  });

  it('says which escalations no rule can match when a proposal has no verdict key', async () => {
    const user = userEvent.setup();
    const { ApiError } = await import('../../../../api/client');
    await renderQueue(many(2), {
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/bulk/propose-suppression') {
          throw new ApiError({ status: 422, code: 'no_verdict_key', message: 'no', requestId: null, details: [{ escalation_id: 'e1' }] });
        }
        return undefined;
      },
    });
    await screen.findByRole('link', { name: 'Escalation e0' });
    await user.click(screen.getByRole('checkbox', { name: 'Select the escalations shown (at most 50)' }));
    await user.click(screen.getByRole('button', { name: 'Propose suppression…' }));
    const dialog = within(screen.getByRole('dialog', { name: 'Propose a suppression rule' }));
    await user.click(dialog.getByRole('button', { name: 'Propose rule' }));
    const refused = await dialog.findByRole('alert');
    expect(refused).toHaveTextContent('No rule can match these alerts');
    const list = within(refused).getByRole('list', { name: 'Escalations no rule can match' });
    expect(list).toHaveTextContent('Escalation e1');
    expect(list).not.toHaveTextContent('Escalation e0');
  });

  it('clears the selection when the filters change', async () => {
    const user = userEvent.setup();
    await renderQueue(many(2));
    await screen.findByRole('link', { name: 'Escalation e0' });
    await user.click(screen.getByRole('checkbox', { name: 'Select Escalation e0' }));
    expect(screen.getByText('1 selected')).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Unassigned' }));
    expect(await screen.findByText('0 selected')).toBeInTheDocument();
  });
});

describe('grouped by rule', () => {
  const groups: EscalationGroupsOut = {
    items: [
      {
        source_id: 'src-1',
        source_name: 'Entra ID',
        rule: 'Unusual sign-in pattern',
        size: 38,
        unassigned: 36,
        overdue: 1,
        earliest_sla_deadline: inMinutes(-10),
        min_confidence: 31,
        max_confidence: 48,
        by_severity: { high: 10, medium: 20, low: 8 },
        escalation_ids: ['g1', 'g2'],
      },
    ],
    truncated: true,
    generated_at: inMinutes(0),
  };
  const members = [escalation('g1', { rule: 'Unusual sign-in pattern', source_id: 'src-1' }), escalation('g2', { rule: 'Unusual sign-in pattern', source_id: 'src-1' })];

  it('shows groups with their mix, expands one through ?source_id=&rule=, and selects the whole group', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue([members[0], escalation('solo')], {
      route: '/escalations?group=rule&assigned_to=none',
      handler: (_method, path, _body, query) => {
        if (path === '/escalations/groups') return groups;
        if (path === '/escalations' && query.rule) return { items: members, next_cursor: null };
        return undefined;
      },
    });
    const toggle = await screen.findByRole('button', { name: 'Unusual sign-in pattern ×38' });
    const groupRow = toggle.closest('tr') as HTMLElement;
    expect(groupRow).toHaveTextContent('Entra ID · 36 unassigned · 1 overdue · confidence 31–48% · 10 high, 20 medium, 8 low');
    expect(within(groupRow).getByText('breaching')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/escalations/groups')?.query).toEqual({ assigned_to: 'none' });
    expect(screen.getByText(/More groups matched than are shown/)).toBeInTheDocument();
    expect(within(groupRow).getByRole('link', { name: 'Show as list' })).toHaveAttribute('href', '/escalations?source_id=src-1&rule=Unusual+sign-in+pattern');
    // Members of the group are not repeated as rows of their own until the group is expanded.
    expect(screen.queryByRole('link', { name: 'Escalation g1' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Escalation solo' })).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    await user.click(within(groupRow).getByRole('checkbox', { name: 'Select all 38 in the group Unusual sign-in pattern' }));
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await waitFor(() => expect(screen.getByText('2 selected')).toBeInTheDocument());
    const groupQuery = listQueries(calls).find((q) => q.rule);
    expect(groupQuery).toMatchObject({ source_id: 'src-1', rule: 'Unusual sign-in pattern', status: ['open', 'claimed'], assigned_to: 'none', order: 'sla_deadline' });
    expect(screen.getByRole('checkbox', { name: 'Select Escalation g2' })).toBeChecked();

    await user.click(within(groupRow).getByRole('checkbox', { name: 'Select all 38 in the group Unusual sign-in pattern' }));
    expect(screen.getByText('0 selected')).toBeInTheDocument();
    await user.click(toggle);
    expect(screen.queryByRole('link', { name: 'Escalation g2' })).not.toBeInTheDocument();
  });

  it('answers group members with the rule filter', async () => {
    const user = userEvent.setup();
    await renderQueue([], {
      route: '/escalations?group=rule',
      handler: (_method, path, _body, query) => {
        if (path === '/escalations/groups') return groups;
        if (path === '/escalations' && query.rule) return { items: members, next_cursor: 'more' };
        return undefined;
      },
    });
    // With no single row loaded the groups still show.
    const toggle = await screen.findByRole('button', { name: 'Unusual sign-in pattern ×38' });
    await user.click(toggle);
    expect(await screen.findByRole('link', { name: 'Escalation g1' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load more of Unusual sign-in pattern' })).toBeInTheDocument();
  });
});
