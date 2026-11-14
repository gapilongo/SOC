import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { AlertDetailOut, DecisionIn, EscalationOut, PreviewActionOut, ResponsePreviewOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import DecisionPage from './DecisionPage';

const inMinutes = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

function escalation(overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id: 'esc-1',
    tenant_id: 'acme',
    alert_id: 'alert-1',
    level: 'L1',
    status: 'claimed',
    reason: 'low confidence',
    priority: 7,
    summary: { title: 'Unusual sign-in pattern for j.doe', simulated_evidence: false },
    alert_severity: 'high',
    assigned_to: 'u-1',
    claimed_at: inMinutes(-2),
    sla_deadline: inMinutes(-10),
    routing: { code: 'grey_zone', confidence: 42, band: { min: 20, max: 60 } },
    version: 3,
    created_at: inMinutes(-600),
    updated_at: inMinutes(-600),
    ...overrides,
  };
}

function alert(overrides: Partial<AlertDetailOut> = {}): AlertDetailOut {
  return {
    id: 'alert-1',
    tenant_id: 'acme',
    source_id: 'src-1',
    source_alert_id: 'x-1',
    fingerprint: 'fp',
    title: 'Unusual sign-in pattern for j.doe',
    severity: 'high',
    status: 'waiting_human',
    occurred_at: inMinutes(-30),
    ingested_at: inMinutes(-29),
    updated_at: inMinutes(-29),
    summary: {
      triage: { rule_tp: ['TOR exit node as source'], llm_fp: ['No follow-on activity'] },
      analysis: { conclusion: 'Sign-in from a TOR exit node after a normal one.', verdict: 'inconclusive', llm_used: true, reasoning: ['Looked up the IP'], rule_evidence: ['tor_exit'] },
    },
    normalized: { entities: { users: ['j.doe@acme.example'], ips: ['192.0.2.10'] } },
    raw: { event: 'SignIn' },
    findings: [
      { origin: 'threat_intel', kind: 'ip', target: '192.0.2.10', source: 'AbuseIPDB', status: 'ok', verdict: 'malicious', checked_at: inMinutes(-28), data: { score: 100 } },
      { origin: 'history', kind: 'user', target: 'j.doe@acme.example', source: 'tenant history', status: 'ok', verdict: 'seen before', cached: true },
    ],
    ...overrides,
  };
}

function action(overrides: Partial<PreviewActionOut>): PreviewActionOut {
  return {
    action_type: 'revoke_sessions',
    target: 'j.doe@acme.example',
    description: 'Revoke all sessions for j.doe',
    risk: 'medium',
    reversible: true,
    connector: { name: 'Entra ID', source: 'microsoft', live: true, ready: true },
    guardrail: { verdict: 'passed' },
    autonomy: 'approval',
    without_preapproval: 'awaiting_approval',
    can_preapprove: true,
    role_lock: null,
    approval_entry: 'revoke_sessions:j.doe@acme.example',
    ...overrides,
  };
}

const preview: ResponsePreviewOut = {
  escalation_id: 'esc-1',
  alert_id: 'alert-1',
  generated_at: inMinutes(0),
  threat_type: 'account_compromise',
  evidence: 'analyst',
  dry_run_forced: true,
  actions: [
    action({}),
    action({ action_type: 'disable_user', description: 'Disable account j.doe', risk: 'high', can_preapprove: false, role_lock: 'admin', approval_entry: 'disable_user:j.doe@acme.example' }),
    action({ action_type: 'create_ticket', target: 'alert:alert-1', description: 'Open an incident ticket', risk: 'low', reversible: false, irreversible_note: 'Tickets stay open.', can_preapprove: false, without_preapproval: 'automatic', approval_entry: 'create_ticket:alert:alert-1' }),
    action({ action_type: 'block_ip', target: '192.0.2.10', description: 'Block 192.0.2.10', can_preapprove: false, without_preapproval: 'blocked', guardrail: { verdict: 'blocked', reason: 'no firewall connector' }, connector: { name: 'Firewall', source: 'webhook', live: false, ready: false }, approval_entry: 'block_ip:192.0.2.10' }),
    action({ action_type: 'isolate_host', target: 'LT-1', description: 'Isolate the laptop', can_preapprove: false, role_lock: 'disabled', approval_entry: 'isolate_host:LT-1' }),
  ],
};

/** A plan of these actions, as the answer to the preview request. */
const planOf = (...actions: PreviewActionOut[]): Handler => (method, path) =>
  method === 'GET' && path === '/escalations/esc-1/response-preview' ? { ...preview, actions } : undefined;

/** Two actions of one type and one description: only the target tells them apart. */
const terminate = (target: string) =>
  action({ action_type: 'terminate_process', target, description: 'Terminate a process through EDR', reversible: false, approval_entry: `terminate_process:${target}` });

const decided = (e: EscalationOut) => ({
  escalation: { ...e, status: 'decided' },
  approved_actions: [],
  resumed_alert_ids: ['alert-1'],
  own_review_alert_ids: [],
  resumes_enqueued: 1,
  resumes_failed: 0,
});

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown) => unknown;

async function renderDecision({ esc = escalation(), role = 'analyst', id = 'u-1', handler }: { esc?: EscalationOut; role?: string; id?: string; handler?: Handler } = {}) {
  let current = esc;
  const { api, calls } = fakeApi((method, path, body) => {
    const answer = handler?.(method, path, body);
    if (answer !== undefined) return answer;
    if (method === 'GET' && path === `/escalations/${esc.id}`) return current;
    if (method === 'GET' && path === '/alerts/alert-1') return alert();
    if (method === 'GET' && path === `/escalations/${esc.id}/response-preview`) return preview;
    if (method === 'POST' && path === `/escalations/${esc.id}/claim`) {
      current = { ...current, status: 'claimed', assigned_to: id, version: current.version + 1 };
      return current;
    }
    if (method === 'POST' && path === `/escalations/${esc.id}/decision`) {
      current = { ...current, status: 'decided', decision: (body as DecisionIn).decision, decided_by: id, decided_at: inMinutes(0) };
      return decided(current);
    }
    if (path === '/tickets') return [];
    if (path.endsWith('/events')) return { items: [{ id: 1, alert_id: 'alert-1', ts: inMinutes(-29), event_type: 'alert.ingested', actor_type: 'system', data: { status: 'new' } }], next_cursor: null };
    return {};
  });
  const session = await signedInSession(api, { role, id });
  const view = renderWithSession(
    <>
      <Routes>
        <Route path="/escalations/:id" element={<DecisionPage />} />
        <Route path="/escalations" element={<p>queue</p>} />
      </Routes>
      <LocationProbe />
    </>,
    session,
    { route: `/escalations/${esc.id}` },
  );
  await screen.findByRole('heading', { name: 'Unusual sign-in pattern for j.doe', level: 1 });
  return { ...view, calls };
}

const form = () => within(screen.getByRole('form', { name: 'Your decision' }));
const planRegion = () => screen.findByRole('region', { name: 'Expected response plan' });
const decisionBody = (calls: Array<{ method: string; path: string; body?: unknown }>) =>
  calls.find((c) => c.method === 'POST' && c.path.endsWith('/decision'))?.body as DecisionIn | undefined;

describe('decision page header and claim state', () => {
  it('shows severity, level, owner, routing against its band and the SLA', async () => {
    await renderDecision();
    expect(screen.getByText('Escalated because the assessed threat 42% is inside the review band (20–60%).')).toBeInTheDocument();
    expect(screen.getByText(/Grey zone/)).toHaveTextContent('Grey zone · confidence 42% (band 20–60)');
    expect(screen.getByText(/^SLA /)).toHaveTextContent(/over · breaching/);
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText(/Owner:/)).toHaveTextContent('Owner: You');
    expect(screen.getByText(/^Claimed by you/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Alert alert-1' })).toHaveAttribute('href', '/alerts?alert=alert-1');
    expect(screen.getByRole('link', { name: 'Escalations' })).toHaveAttribute('href', '/escalations?order=sla_deadline');
  });

  it('offers a prominent Claim on an unclaimed escalation; deciding waits for it', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision({ esc: escalation({ status: 'open', assigned_to: null, claimed_at: null }) });
    expect(screen.getByText('Claim this escalation to record a decision.')).toBeInTheDocument();
    expect(form().getByRole('radio', { name: /^True positive/ })).toBeDisabled();
    expect(form().getByText('Claim the escalation to record a decision.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Claim' }));
    expect(await screen.findByText('Escalation claimed.')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/escalations/esc-1/claim')?.body).toEqual({ version: 3 });
    await waitFor(() => expect(form().getByRole('radio', { name: /^True positive/ })).toBeEnabled());
  });

  it('shows who holds it to an analyst, without a take-over', async () => {
    await renderDecision({ esc: escalation({ assigned_to: 'u-other', assigned_to_email: 'other@acme.example' }) });
    const banner = screen.getByText(/^Claimed by other@acme.example/).closest('[role="status"]') as HTMLElement;
    expect(within(banner).getByText('Only they or an admin can record a decision.')).toBeInTheDocument();
    expect(within(banner).queryByRole('button', { name: 'Take over' })).not.toBeInTheDocument();
    expect(form().getByText('Claimed by another analyst; only they or an admin can decide it.')).toBeInTheDocument();
  });

  it('lets an admin take over', async () => {
    const user = userEvent.setup();
    await renderDecision({ esc: escalation({ assigned_to: 'u-other', assigned_to_email: 'other@acme.example' }), role: 'admin', id: 'u-9' });
    expect(form().getByText('Take over the escalation to record a decision.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Take over' }));
    expect(await screen.findByText('Escalation taken over.')).toBeInTheDocument();
  });

  it('tells a viewer the role is missing', async () => {
    await renderDecision({ esc: escalation({ status: 'open', assigned_to: null }), role: 'viewer' });
    expect(screen.queryByRole('button', { name: 'Claim' })).not.toBeInTheDocument();
    expect(screen.getAllByText('Requires the analyst role.').length).toBeGreaterThan(0);
  });

  it('shows a decided escalation without a form', async () => {
    await renderDecision({ esc: escalation({ status: 'decided', decision: 'benign_positive', decided_by: 'u-2', decided_by_email: 'lead@acme.example', decision_notes: 'Expected scan.' }) });
    expect(screen.getByText('Decided: Benign positive')).toBeInTheDocument();
    expect(screen.getByText('Expected scan.')).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Your decision' })).not.toBeInTheDocument();
  });

  it('says when the escalation does not exist', async () => {
    const { api } = fakeApi((_method, path) => {
      if (path === '/escalations/nope') throw apiError(404, 'not_found', 'escalation not found');
      return {};
    });
    const session = await signedInSession(api);
    renderWithSession(
      <Routes>
        <Route path="/escalations/:id" element={<DecisionPage />} />
      </Routes>,
      session,
      { route: '/escalations/nope' },
    );
    expect(await screen.findByRole('heading', { name: 'Escalation not found' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the escalation queue' })).toBeInTheDocument();
  });
});

describe('decision form', () => {
  it('preselects nothing and needs a verdict', async () => {
    await renderDecision();
    for (const name of [/^True positive/, /^False positive/, /^Benign positive/]) expect(form().getByRole('radio', { name })).not.toBeChecked();
    expect(form().queryByRole('radio', { name: /Needs more information/ })).not.toBeInTheDocument();
    expect(form().getByRole('button', { name: 'Record decision' })).toBeDisabled();
    expect(form().getByRole('button', { name: 'Record and open next' })).toBeDisabled();
    expect(form().getByText('Choose a verdict to continue.')).toBeInTheDocument();
  });

  it('requires notes for a true positive and shows the expected plan with pre-approvals and locks', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision();
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    expect(form().getByText('(required for this verdict)')).toBeInTheDocument();
    expect(form().queryByLabelText('Suggest a suppression rule')).not.toBeInTheDocument();

    const plan = within(await screen.findByRole('list', { name: 'Planned actions' }));
    expect(within(await planRegion()).getByText('Dry run')).toBeInTheDocument();
    const revoke = plan.getByRole('checkbox', { name: /Revoke all sessions for j.doe/ });
    expect(revoke).toBeEnabled();
    expect(plan.getAllByText('Entra ID · reversible · medium risk').length).toBeGreaterThan(0);
    const disable = plan.getByRole('checkbox', { name: /Disable account j.doe/ });
    expect(disable).toBeDisabled();
    expect(plan.getByText(/Requires admin approval/)).toBeInTheDocument();
    expect(plan.getByText('Runs automatically without pre-approval')).toBeInTheDocument();
    expect(plan.getByText('Tickets stay open.')).toBeInTheDocument();
    expect(plan.queryByRole('checkbox', { name: /Open an incident ticket/ })).not.toBeInTheDocument();
    expect(plan.getByText('Blocked without pre-approval')).toBeInTheDocument();
    expect(plan.getByText('Guardrail: blocked (no firewall connector)')).toBeInTheDocument();
    expect(plan.getByText('Firewall (not ready), dry run · reversible · medium risk')).toBeInTheDocument();
    expect(plan.getByText(/autonomy policy disables this action/)).toBeInTheDocument();

    await user.click(revoke);
    expect(plan.getByText('Pre-approved: runs after your decision')).toBeInTheDocument();
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    expect(form().getByText(/Notes are required for a true positive/)).toBeInTheDocument();
    expect(form().getByLabelText(/Notes for the record/)).toHaveFocus();
    expect(decisionBody(calls)).toBeUndefined();

    await user.type(form().getByLabelText(/Notes for the record/), 'Confirmed with the user.');
    expect(form().queryByText(/Notes are required/)).not.toBeInTheDocument();
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    expect(await screen.findByText('Decision recorded; 1 alert(s) resumed.')).toBeInTheDocument();
    expect(decisionBody(calls)).toEqual({
      decision: 'true_positive',
      version: 3,
      notes: 'Confirmed with the user.',
      approved_actions: ['revoke_sessions:j.doe@acme.example'],
      feedback: null,
      suggest_suppression: null,
    });
    // The decided escalation shows its decision and no form.
    expect(await screen.findByText('Decided: True positive')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations/esc-1');
  });

  it('offers the suppression suggestion only for false and benign positives, with optional notes and feedback', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision();
    await user.click(form().getByRole('radio', { name: /^Benign positive/ }));
    expect(form().getByLabelText('Suggest a suppression rule')).toBeInTheDocument();
    await user.click(form().getByRole('radio', { name: /^False positive/ }));
    expect(form().getByText('(optional)')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Planned actions' })).not.toBeInTheDocument();
    await user.click(form().getByLabelText('Suggest a suppression rule'));
    await user.click(form().getByText('Rate the automated triage (optional)'));
    await user.selectOptions(form().getByLabelText('Triage correct'), 'no');
    await user.type(form().getByLabelText('Your confidence (0-100)'), '140');
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(decisionBody(calls)).toEqual({
      decision: 'false_positive',
      version: 3,
      notes: null,
      approved_actions: [],
      feedback: { confidence: 100, triage_correct: false, analysis_accurate: null, correlation_helpful: null },
      suggest_suppression: true,
    });
  });

  it('keeps the input on a 409 and explains the change', async () => {
    const user = userEvent.setup();
    let attempts = 0;
    const { calls } = await renderDecision({
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/esc-1/decision') {
          attempts += 1;
          if (attempts === 1) throw apiError(409, 'conflict', 'stale version');
        }
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^False positive/ }));
    await user.type(form().getByLabelText(/Notes for the record/), 'Known VPN.');
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    expect(await screen.findByText(/changed while you were reviewing it \(now claimed, assigned to u-1\)/)).toBeInTheDocument();
    expect(form().getByLabelText(/Notes for the record/)).toHaveValue('Known VPN.');
    expect(form().getByRole('radio', { name: /^False positive/ })).toBeChecked();
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(calls.filter((c) => c.path.endsWith('/decision'))).toHaveLength(2);
  });

  it('reports a conflict that closed the escalation', async () => {
    const user = userEvent.setup();
    let reads = 0;
    await renderDecision({
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/esc-1/decision') throw apiError(409, 'conflict');
        if (method === 'GET' && path === '/escalations/esc-1') {
          reads += 1;
          // The page's own read, then the form's re-read after the conflict.
          return reads > 1 ? escalation({ status: 'cancelled', version: 9 }) : undefined;
        }
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^False positive/ }));
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    expect(await screen.findByText(/This escalation is cancelled/)).toBeInTheDocument();
  });

  it('shows other API errors in the form', async () => {
    const user = userEvent.setup();
    await renderDecision({
      handler: (method, path) => {
        if (method === 'POST' && path === '/escalations/esc-1/decision') throw apiError(403, 'forbidden', 'role analyst may not approve high risk action');
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^False positive/ }));
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    expect(await form().findByText('role analyst may not approve high risk action')).toBeInTheDocument();
  });

  it('records and opens the next escalation in SLA order that the user may decide', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision({
      handler: (method, path) => {
        if (method === 'GET' && path === '/escalations') {
          return {
            items: [
              escalation({ id: 'esc-1' }),
              escalation({ id: 'theirs', assigned_to: 'u-other' }),
              escalation({ id: 'next-up', status: 'open', assigned_to: null }),
            ],
            next_cursor: null,
          };
        }
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^Benign positive/ }));
    await user.click(form().getByRole('button', { name: 'Record and open next' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/escalations/next-up'));
    expect(calls.find((c) => c.method === 'GET' && c.path === '/escalations')?.query).toMatchObject({ status: ['open', 'claimed', 'expired'], order: 'sla_deadline' });
  });

  it('returns to the queue when nothing else is waiting', async () => {
    const user = userEvent.setup();
    await renderDecision({
      handler: (method, path) => (method === 'GET' && path === '/escalations' ? { items: [escalation({ id: 'esc-1' })], next_cursor: null } : undefined),
    });
    await user.click(form().getByRole('radio', { name: /^Benign positive/ }));
    await user.click(form().getByRole('button', { name: 'Record and open next' }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/escalations\?order=sla_deadline$/);
  });

  it('looks through further pages for the next escalation', async () => {
    const user = userEvent.setup();
    await renderDecision({
      handler: (method, path) => {
        if (method === 'GET' && path === '/escalations') {
          return { items: [escalation({ id: 'theirs', assigned_to: 'u-other' })], next_cursor: 'c-2' };
        }
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^Benign positive/ }));
    await user.click(form().getByRole('button', { name: 'Record and open next' }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
  });
});

describe('expected response plan', () => {
  it('names the target of every planned action, outside the form, which keeps Record decision', async () => {
    const user = userEvent.setup();
    await renderDecision();
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    const region = await planRegion();
    const items = await within(region).findAllByRole('listitem');
    expect(items.map((li) => li.querySelector('code')?.textContent)).toEqual(['j.doe@acme.example', 'j.doe@acme.example', 'alert:alert-1', '192.0.2.10', 'LT-1']);
    for (const li of items) expect(li).toHaveTextContent(/Target: \S/);
    // The plan is in the main column, under the investigation; the form holds the verdict, the notes and the buttons.
    expect(screen.getByRole('region', { name: 'Investigation' }).parentElement).toContainElement(region);
    expect(screen.getByRole('form', { name: 'Your decision' })).not.toContainElement(region);
    expect(form().queryByRole('checkbox')).not.toBeInTheDocument();
    expect(form().getByRole('button', { name: 'Record decision' })).toBeEnabled();
    expect(form().getByText(/^No action is pre-approved\. Choose them in the response plan, under the investigation\.$/)).toBeInTheDocument();
  });

  it('tells two actions of one type apart by their targets, and pre-approves only the one ticked', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision({ handler: planOf(terminate('powershell.exe'), terminate('rundll32.exe')) });
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    const plan = within(await screen.findByRole('list', { name: 'Planned actions' }));
    expect(plan.getAllByText('Terminate a process through EDR')).toHaveLength(2);
    const first = plan.getByRole('checkbox', { name: /Target: powershell\.exe/ });
    const second = plan.getByRole('checkbox', { name: /Target: rundll32\.exe/ });
    expect(first).not.toBe(second);
    await user.click(second);
    expect(first).not.toBeChecked();
    expect(form().getByText(/^1 action is pre-approved\./)).toBeInTheDocument();
    await user.type(form().getByLabelText(/Notes for the record/), 'Injected loader.');
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(decisionBody(calls)?.approved_actions).toEqual(['terminate_process:rundll32.exe']);
  });

  it('does not let an action without a target be pre-approved', async () => {
    const user = userEvent.setup();
    const { calls } = await renderDecision({
      handler: planOf(terminate(''), action({ action_type: 'quarantine_file', target: '  ', description: 'Quarantine a file', approval_entry: 'quarantine_file' }), terminate('rundll32.exe')),
    });
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    const plan = within(await screen.findByRole('list', { name: 'Planned actions' }));
    const boxes = plan.getAllByRole('checkbox');
    expect(boxes.map((b) => (b as HTMLInputElement).disabled)).toEqual([true, true, false]);
    expect(plan.getAllByText('not sent')).toHaveLength(2);
    expect(plan.getAllByText(/The plan sent no target for this action, so it cannot be pre-approved here; approve it on the Approvals page\./)).toHaveLength(2);
    await user.click(boxes[0]);
    await user.click(boxes[1]);
    expect(boxes[0]).not.toBeChecked();
    expect(form().getByText(/^No action is pre-approved\./)).toBeInTheDocument();
    await user.type(form().getByLabelText(/Notes for the record/), 'Confirmed.');
    await user.click(form().getByRole('button', { name: 'Record decision' }));
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(decisionBody(calls)?.approved_actions).toEqual([]);
  });

  it('drops the pre-approvals with the form when the page moves to another escalation', async () => {
    const user = userEvent.setup();
    await renderDecision({
      handler: (method, path) => {
        if (method === 'GET' && path === '/escalations') return { items: [escalation({ id: 'esc-1' }), escalation({ id: 'esc-2' })], next_cursor: null };
        if (method === 'GET' && path === '/escalations/esc-2') return escalation({ id: 'esc-2' });
        if (method === 'GET' && path === '/escalations/esc-2/response-preview') return preview;
        return undefined;
      },
    });
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    await user.click(await screen.findByRole('checkbox', { name: /Revoke all sessions for j.doe/ }));
    await user.type(form().getByLabelText(/Notes for the record/), 'Confirmed.');
    await user.click(form().getByRole('button', { name: 'Record and open next' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/escalations/esc-2'));
    await waitFor(() => expect(form().getByRole('radio', { name: /^True positive/ })).not.toBeChecked());
    expect(screen.queryByRole('region', { name: 'Expected response plan' })).not.toBeInTheDocument();
    await user.click(form().getByRole('radio', { name: /^True positive/ }));
    expect(await screen.findByRole('checkbox', { name: /Revoke all sessions for j.doe/ })).not.toBeChecked();
    expect(form().getByText(/^No action is pre-approved\./)).toBeInTheDocument();
  });
});

describe('investigation tabs', () => {
  it('shows the findings with source and time, the evidence for and against, and every section', async () => {
    const user = userEvent.setup();
    await renderDecision();
    const tabs = screen.getByRole('tablist', { name: 'Investigation sections' });
    expect(within(tabs).getAllByRole('tab').map((t) => t.textContent)).toEqual(['Summary', 'Evidence', 'Entities', 'Timeline', 'Raw']);
    const summary = within(screen.getByRole('tabpanel', { name: 'Summary' }));
    expect(await summary.findByText('Sign-in from a TOR exit node after a normal one.')).toBeInTheDocument();
    expect(summary.getByText('IP 192.0.2.10: malicious')).toBeInTheDocument();
    expect(summary.getAllByText(/Source: AbuseIPDB · checked/).length).toBe(1);
    expect(within(summary.getByRole('list', { name: 'Basis of this verdict' })).getByText('Written by the model')).toBeInTheDocument();
    expect(within(summary.getByRole('region', { name: 'Points to malicious' })).getByText('TOR exit node as source')).toBeInTheDocument();
    expect(within(summary.getByRole('region', { name: 'Points to benign' })).getByText(/No follow-on activity/)).toHaveTextContent('(model)');
    expect(screen.queryByText('Some evidence was simulated')).not.toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Evidence' }));
    const evidence = within(screen.getByRole('tabpanel', { name: 'Evidence' }));
    await user.click(evidence.getByRole('button', { name: 'View raw' }));
    expect(evidence.getByRole('region', { name: 'Raw result of AbuseIPDB for 192.0.2.10' })).toHaveTextContent('"score": 100');
    expect(evidence.getByText(/from cache/)).toBeInTheDocument();
    expect(evidence.getByText('tor_exit')).toBeInTheDocument();
    expect(evidence.getByText('Looked up the IP')).toBeInTheDocument();
    expect(evidence.getByRole('button', { name: 'Download evidence pack (JSON)' })).toBeInTheDocument();

    await user.keyboard('{ArrowRight}');
    await user.click(screen.getByRole('tab', { name: 'Entities' }));
    expect(within(screen.getByRole('tabpanel', { name: 'Entities' })).getByText('j.doe@acme.example')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Timeline' }));
    expect(await within(screen.getByRole('tabpanel', { name: 'Timeline' })).findByText('Alert ingested')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Raw' }));
    expect(within(screen.getByRole('tabpanel', { name: 'Raw' })).getByRole('region', { name: 'Raw alert JSON' })).toHaveTextContent('SignIn');
  });

  it('warns in red when evidence was simulated', async () => {
    await renderDecision({ esc: escalation({ summary: { title: 'Unusual sign-in pattern for j.doe', simulated_evidence: true } }) });
    const warning = screen.getAllByRole('alert').find((el) => el.textContent?.includes('simulated')) as HTMLElement;
    expect(warning).toHaveTextContent('Some evidence was simulated');
    expect(warning).toHaveAttribute('data-tone', 'warning');
  });

  it('falls back to the escalation summary while the alert cannot be read', async () => {
    await renderDecision({
      esc: escalation({ summary: { title: 'Unusual sign-in pattern for j.doe', conclusion: 'From the escalation.' }, entities_preview: { items: [{ kind: 'host', value: 'LT-1' }], counts: { host: 1 } } }),
      handler: (_method, path) => {
        if (path === '/alerts/alert-1') throw apiError(500, 'internal', 'alert store down');
        return undefined;
      },
    });
    expect(await screen.findByText('alert store down')).toBeInTheDocument();
    expect(screen.getByText('From the escalation.')).toBeInTheDocument();
    expect(screen.getByText('Evidence: no lookups recorded')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('tab', { name: 'Entities' }));
    expect(screen.getByText('LT-1')).toBeInTheDocument();
  });
});
