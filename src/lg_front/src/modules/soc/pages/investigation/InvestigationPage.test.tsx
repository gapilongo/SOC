import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import type { AlertDetailOut, AlertEventOut, DecisionIn, EscalationOut, InvestigationOut, ProposedActionOut, ResponsePreviewOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import {
  ALERT_ID,
  ESCALATION_ID,
  inMinutes,
  investigationAlert,
  investigationEscalation,
  investigationEvents,
  investigationPreview,
} from '../../../../test/investigation';
import { AI_CLOSED_INVESTIGATION, ESCALATED_INVESTIGATION, RESPONSE_PLAN_INVESTIGATION } from '../../../../test/investigationReadModels';
import { AlertSidePanel } from '../alerts/AlertPanel';
import { NEEDS_MORE_EFFECT, effectOf } from './DecisionDock';
import InvestigationPage from './InvestigationPage';
import { checkLine, entityHref, pendingWhy } from './InvestigationPage';
import { isTyping } from './keys';
import { preapproval, preapprovedEntries } from './ResponseTable';

const TITLE = 'Encoded PowerShell launched by Microsoft Word';
const TERMINATE = /^Run on true positive ?: Terminate process on powershell.exe PID 7340$/;

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown) => unknown;

interface Setup {
  /** The read model the API serves; null: the API predates it and answers 404. */
  model?: InvestigationOut | null;
  alert?: AlertDetailOut;
  esc?: EscalationOut | null;
  events?: AlertEventOut[];
  preview?: ResponsePreviewOut;
  role?: string;
  id?: string;
  handler?: Handler;
}

async function renderPage({
  model = ESCALATED_INVESTIGATION,
  alert = investigationAlert(),
  esc = investigationEscalation(),
  events = investigationEvents(),
  preview = investigationPreview(),
  role = 'analyst',
  id = 'u-1',
  handler,
}: Setup = {}) {
  let current = esc;
  const { api, calls } = fakeApi((method, path, body) => {
    const answer = handler?.(method, path, body);
    if (answer !== undefined) return answer;
    if (method === 'GET' && path === `/alerts/${ALERT_ID}/investigation`) {
      if (model) return model;
      throw apiError(404, 'not_found', 'Not Found');
    }
    if (method === 'GET' && path === `/alerts/${ALERT_ID}`) return alert;
    if (method === 'GET' && path === `/alerts/${ALERT_ID}/events`) return { items: events, next_cursor: null };
    if (method === 'GET' && path === `/escalations/${ESCALATION_ID}` && current) return current;
    if (method === 'GET' && path === `/escalations/${ESCALATION_ID}/response-preview`) return preview;
    if (method === 'POST' && path === `/escalations/${ESCALATION_ID}/claim` && current) {
      current = { ...current, status: 'claimed', assigned_to: id, version: current.version + 1 };
      return current;
    }
    if (method === 'POST' && path === `/escalations/${ESCALATION_ID}/decision` && current) {
      current = { ...current, status: 'decided', decision: (body as DecisionIn).decision, decision_notes: (body as DecisionIn).notes, decided_by: id, decided_at: inMinutes(0) };
      return { escalation: current, approved_actions: [], resumed_alert_ids: [ALERT_ID], own_review_alert_ids: [], resumes_enqueued: 1, resumes_failed: 0 };
    }
    if (method === 'GET' && path === '/escalations') return { items: [], next_cursor: null };
    if (method === 'GET' && path === '/actions') return { items: [], next_cursor: null };
    if (method === 'GET' && path === '/alerts/next-alert') return investigationAlert({ id: 'next-alert', title: 'The next alert', status: 'closed', summary: {}, findings: [] });
    if (method === 'GET' && path === '/alerts/next-alert/investigation') return { ...AI_CLOSED_INVESTIGATION, alert_id: 'next-alert' };
    if (method === 'GET' && path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password', tenant_name: 'Northwind Logistics' };
    throw apiError(404, 'not_found', 'Not found');
  });
  const session = await signedInSession(api, { role, id });
  const view = renderWithSession(
    <>
      <Routes>
        <Route path="/alerts/:id" element={<InvestigationPage />} />
        <Route path="/alerts" element={<p>alert list</p>} />
      </Routes>
      <LocationProbe />
    </>,
    session,
    { route: `/alerts/${ALERT_ID}` },
  );
  await screen.findByRole('heading', { level: 1 });
  return { ...view, calls };
}

const closedAlert = (overrides: Partial<AlertDetailOut> = {}) => investigationAlert({ status: 'closed', disposition: 'benign', summary: {}, findings: [], ...overrides });
const dock = () => within(screen.getByRole('region', { name: 'Your decision' }));
const effect = () => screen.getByTestId('decision-effect');
const verdictButton = (name: RegExp) => dock().getByRole('button', { name });
const claimButton = (n: number) => screen.getByRole('button', { name: `Claim ${n}, select` });
const claimRow = (n: number) => claimButton(n).closest('[data-claim]') as HTMLElement;
const decisionBody = (calls: Array<{ method: string; path: string; body?: unknown }>) =>
  calls.find((c) => c.method === 'POST' && c.path.endsWith('/decision'))?.body as DecisionIn | undefined;
const section = (name: string | RegExp) => within(screen.getByRole('region', { name }));
const paths = (calls: Array<{ path: string }>) => calls.map((c) => c.path);

// The single-key switch is a stored preference: each test starts without one.
beforeEach(() => window.localStorage.clear());

describe('investigation view on the read model: an escalated alert', () => {
  it('opens with the outcome and the verdict as a sentence, why it is with a person and what blocks an AI close', async () => {
    const { container, calls } = await renderPage();
    expect(screen.getByRole('heading', { level: 1, name: TITLE })).toBeInTheDocument();
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-source', 'api');
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'needs_decision');
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the model')).toBeInTheDocument();
    expect(screen.getByText(/^Word ran a hidden, encoded PowerShell command/)).toHaveTextContent("Isolate the host and reset the user's sessions.");
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent(
      'Why it is with you. No automatic rule applies to this alert, so a person decides. 1 of the 5 claims is backed by what the tools returned; 4 cite no fact.',
    );
    expect(within(screen.getByRole('list', { name: 'Why the AI may not close it on its own' })).getAllByRole('listitem')).toHaveLength(3);
    // The alert's own description comes next, marked as observed.
    expect(screen.getByText('The alert, as Wazuh manager sent it')).toBeInTheDocument();
    expect(screen.getByText(/^Rule 92213 \(level 12\)/)).toBeInTheDocument();
    // One request gives the page its explanation: the timeline and the response preview are not fetched.
    expect(paths(calls)).toContain(`/alerts/${ALERT_ID}/investigation`);
    expect(paths(calls).some((p) => p.endsWith('/events') || p.endsWith('/response-preview') || p === '/actions')).toBe(false);
  });

  it('draws the track record from the read model’s counts, and never a percentage', async () => {
    const { container } = await renderPage();
    const track = screen.getByRole('complementary', { name: 'Track record of this outcome' });
    expect(track.querySelector('[data-track]')).toHaveAttribute('data-track', 'counted');
    expect(track).toHaveTextContent('Analysts confirmed 31 of 34 alerts sent to a person as likely malicious.');
    expect(within(track).getByRole('img', { name: '34 alerts: 31 confirmed, 3 not' }).querySelectorAll('[data-square]')).toHaveLength(34);
    expect(await within(track).findByText(/^Northwind Logistics, last 90 days, analyst decisions\./)).toBeInTheDocument();
    expect(container).not.toHaveTextContent(/\d\s?%/);
    expect(container).not.toHaveTextContent('0.9118');
  });

  it('names the tenant, the case, the severity in words, the deadline and the owner; entity chips lead to the alert list searched for the entity', async () => {
    await renderPage();
    const crumb = within(screen.getByRole('navigation', { name: 'Breadcrumb' }));
    expect(crumb.getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/alerts');
    expect(crumb.getByText('Case CASE-2291')).toBeInTheDocument();
    expect(await crumb.findByText('Northwind Logistics')).toBeInTheDocument();
    expect(screen.getByText('High', { selector: '[data-severity="high"]' })).not.toHaveClass('capitalize');
    expect(screen.getByText(/left$/)).toHaveAttribute('title', expect.stringMatching(/^Deadline /));
    expect(screen.getByText('Owner').parentElement).toHaveTextContent('Owneryou');
    const subject = within(screen.getByRole('list', { name: 'Subject of the alert' }));
    const host = subject.getByRole('link', { name: /^Host ?WS-FIN-0142 ?: alerts whose title names it$/ });
    expect(host).toHaveAttribute('href', '/alerts?view=all&q=WS-FIN-0142');
    expect(host).toHaveAttribute('title', 'Alerts whose title names WS-FIN-0142');
    expect(subject.getByRole('link', { name: /m\.keller/ })).toHaveAttribute('href', '/alerts?view=all&q=m.keller');
    expect(subject.getByText('+1 more').parentElement).toHaveTextContent('Process+1 more');
    expect(subject.getByText('+1 more').closest('a')).toBeNull();
    expect(subject.getByText('T1059.001, T1204.002').parentElement).toHaveTextContent('ATT&CK');
    expect(subject.getByText('Office application starts a script host')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Evidence record' })).toHaveAttribute('href', '#evidence-record');
    expect(screen.getByRole('group', { name: 'Export evidence' })).toBeInTheDocument();
  });

  it('puts each claim beside the observation it rests on, with its typed outcome and its hash where the read model has one', async () => {
    await renderPage();
    const claims = section('Claims, each beside the fact it rests on');
    // The model's claims cite nothing yet: unsupported, with the read model's reason.
    const bare = claimRow(1);
    expect(bare).toHaveAttribute('data-check', 'unsupported');
    expect(within(bare).getByText('Unsupported')).toBeInTheDocument();
    expect(within(bare).getByText('The model named no observation for it.')).toBeInTheDocument();
    expect(within(bare).getByText('No observation is cited for this claim.')).toBeInTheDocument();
    expect(within(claimRow(4)).getByText('Points to benign')).toBeInTheDocument();
    // The rule claim is marked as the rules' and backed by the lookup that returned data.
    const backed = claimRow(5);
    expect(backed).toHaveAttribute('data-check', 'supported');
    expect(within(backed).getByText('Stated by the rules')).toBeInTheDocument();
    expect(within(backed).getByText('Backed by O-03')).toBeInTheDocument();
    const observed = backed.querySelector('[data-observation="O-03"]') as HTMLElement;
    expect(observed).toHaveAttribute('data-outcome', 'success');
    expect(observed).toHaveTextContent('Threat-intelligence reputation: domain cdn-invoice-portal.example');
    expect(within(observed).getByText('returned data')).toBeInTheDocument();
    expect(within(observed).getByText('Verdict suspicious')).toBeInTheDocument();
    expect(within(observed).getByText('sha256 9f2c…41e1')).toBeInTheDocument();
    expect(observed.querySelector('details pre')).toHaveTextContent(/input sha256 41be7d0c.*output sha256 9f2c81d7/);
    // The read model sets no highlight range yet: nothing is highlighted, and the page says why.
    expect(observed.querySelector('mark')).toBeNull();
    const pending = claims.getByText('Not yet available in this section (4)').closest('details') as HTMLElement;
    expect(within(pending).getAllByRole('listitem').map((li) => li.textContent)).toEqual(
      ESCALATED_INVESTIGATION.pending_harness.filter((p) => p.field.startsWith('claims') || p.field.startsWith('observations')).map((p) => p.why),
    );
  });

  it('lists what is not established in three kinds, from the read model', async () => {
    await renderPage();
    const ne = screen.getByRole('region', { name: 'What is not established' });
    expect(within(ne.querySelector('[data-kind="empty"]') as HTMLElement).getByText('Show the 4 lookups')).toBeInTheDocument();
    expect(ne.querySelector('[data-kind="empty"]')).toHaveTextContent('threat-intelligence reputation: IP address 203.0.113.50, file hash 5d1e');
    expect(ne.querySelector('[data-kind="not"]')).toHaveTextContent('What else happened on the host and for the user around the alert');
    expect(ne.querySelector('[data-kind="cannot"]')).toHaveTextContent('virustotal: The source did not answer.');
    expect(within(ne).getByText("Not yet available: Without a playbook the list names only the lookups today's analysis could have made.")).toBeInTheDocument();
  });

  it('shows the steps in the read model’s words and the response a true positive would propose, with exact targets', async () => {
    await renderPage();
    const steps = screen.getByRole('region', { name: 'What the investigation did' });
    expect(steps.querySelectorAll('li[data-actor]')).toHaveLength(ESCALATED_INVESTIGATION.steps.length);
    expect(steps).toHaveTextContent('Deeper analysis: the model read the alert, chose reputation lookups and wrote its conclusion.');
    expect(steps).toHaveTextContent('level L2 · priority 8');
    expect(steps).not.toHaveTextContent(/node\.completed|await_analyst|plan_response/);
    expect(within(steps).getByText(/^Not yet available: The steps come from the workflow's timeline\./)).toBeInTheDocument();
    const plan = section('Proposed response');
    expect(plan.getByRole('link', { name: 'Approvals' })).toHaveAttribute('href', '/approvals');
    expect(plan.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Action', 'Exact target', 'Can it be undone', 'Guardrail', 'Approval']);
    const rows = plan.getAllByRole('row').slice(1);
    expect(rows).toHaveLength(6);
    expect(rows[0]).toHaveTextContent('Isolate hostIsolate the host from the network');
    expect(within(rows[0]).getByText('WS-FIN-0142').tagName).toBe('CODE');
    expect(rows[0]).toHaveTextContent('Needs an admin');
    expect(rows[0]).toHaveTextContent('High risk');
    expect(rows[0]).toHaveTextContent('YesRelease host');
    expect(within(rows[0]).queryByRole('checkbox')).not.toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('NoA stopped process is not restarted');
    expect(within(rows[1]).getByRole('checkbox', { name: TERMINATE })).not.toBeChecked();
    expect(rows[5]).toHaveTextContent("BlockedThe tenant's autonomy policy switches off critical-risk actions");
    expect(rows[5]).toHaveTextContent('Not available');
  });

  it('says "not yet available" only for what the read model lists as pending', async () => {
    const complete: InvestigationOut = { ...ESCALATED_INVESTIGATION, pending_harness: [] };
    const { container } = await renderPage({ model: complete });
    expect(container).not.toHaveTextContent(/not yet available/i);
    expect(container.querySelector('[data-pending]')).toBeNull();
    expect(container).not.toHaveTextContent('no hash yet');
  });
});

describe('investigation view on the read model: other outcomes', () => {
  it('needs your decision, unsure, with no response to propose', async () => {
    const outcome = { ...ESCALATED_INVESTIGATION.outcome, category: 'needs_review', reason: { code: 'grey_zone', sentence: 'The assessment is in the grey zone: not low enough to close, not high enough to respond.' }, blockers: [], evidence: [], closed_by: null };
    const model: InvestigationOut = {
      ...ESCALATED_INVESTIGATION,
      outcome,
      summary: { text: 'A sign-in from a new country, by a user who travels.', written_by: 'rules' },
      track_record: { category: 'needs_review', basis: 'analyst_decisions', window_days: 90, total: 0, confirmed: 0, min_samples: 30, rate: null },
      response: { source: 'none', actions: [] },
    };
    const { container } = await renderPage({ model });
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'needs_review');
    expect(screen.getByText('Needs your decision: unsure')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the rules')).toBeInTheDocument();
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent('The assessment is in the grey zone');
    expect(screen.queryByRole('list', { name: 'Why the AI may not close it on its own' })).not.toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('None of the alerts sent to a person as unsure has been decided yet.');
    expect(section('Proposed response').getByText('A true positive would propose no response action for this alert.')).toBeInTheDocument();
    expect(effect()).toHaveTextContent('Choose a verdict to see what it sets in motion.');
  });

  it('closed by the AI and sampled for audit: why it was closed, a small-sample track record without a rate, and no decision bar', async () => {
    const { container, calls } = await renderPage({ model: AI_CLOSED_INVESTIGATION, alert: closedAlert(), esc: null });
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'ai_closed_audit');
    expect(screen.getByText('Closed by AI, sampled for audit')).toBeInTheDocument();
    expect(screen.getByText('A routine package install by the configuration management agent, seen on 38 hosts this week.')).toBeInTheDocument();
    expect(screen.getByText('Why it was closed.').parentElement).toHaveTextContent("The AI closed it on the model's word. No independent evidence backs the close, so it is sampled for audit.");
    const track = screen.getByRole('complementary', { name: 'Track record of this outcome' });
    expect(track.querySelector('[data-track]')).toHaveAttribute('data-track', 'few');
    expect(track).toHaveTextContent('Blind-audit labels agreed with the AI on 11 of 12 alerts the AI closed and sampled for audit.');
    expect(within(track).getByText('too few for a rate')).toBeInTheDocument();
    expect(section('Response').getByText('No response is proposed for this alert.')).toBeInTheDocument();
    expect(section('Decision').getByText('No decision was asked of a person for this alert.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
    expect(screen.queryByText(/left$/)).not.toBeInTheDocument();
    expect(paths(calls).some((p) => p.startsWith('/escalations'))).toBe(false);
  });

  it('a response plan on the ledger: every action with its status, nothing to tick, and the decision on record', async () => {
    await renderPage({
      model: RESPONSE_PLAN_INVESTIGATION,
      alert: investigationAlert({ status: 'waiting_approval' }),
      esc: investigationEscalation({ status: 'decided', decision: 'true_positive', decision_notes: 'Confirmed with the user.', decided_by: 'u-9', decided_by_email: 'lead@acme.test', decided_at: '2026-11-14T10:20:00Z' }),
    });
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('Analysts confirmed 96 of 120');
    expect(screen.getByRole('img', { name: '96 of 120 alerts confirmed' })).toBeInTheDocument();
    const plan = section('Response');
    expect(plan.getByText(/^The actions the workflow recorded for this alert, each with its status\./)).toBeInTheDocument();
    expect(plan.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Action', 'Exact target', 'Can it be undone', 'Guardrail', 'Status']);
    const rows = plan.getAllByRole('row').slice(1);
    expect(rows.map((r) => r.querySelector('[data-status]')?.textContent)).toEqual(['Ran', 'Waits for an approval', 'Dry run: recorded, nothing changed', 'Blocked']);
    expect(within(rows[0]).getByText('powershell.exe PID 7340').tagName).toBe('CODE');
    expect(rows[0]).toHaveTextContent('Not checked again');
    expect(rows[1]).toHaveTextContent('Passed');
    expect(rows[3]).toHaveTextContent("BlockedThe tenant's autonomy policy switches off critical-risk actions");
    expect(plan.queryByRole('checkbox')).not.toBeInTheDocument();
    const decision = section('Decision');
    expect(decision.getByText('Decided by a person')).toBeInTheDocument();
    expect(decision.getByText('True positive')).toBeInTheDocument();
    expect(decision.getByText('by lead@acme.test')).toBeInTheDocument();
    expect(decision.getByText('Confirmed with the user.')).toBeInTheDocument();
    expect(decision.getByRole('link', { name: 'Open the escalation' })).toHaveAttribute('href', `/escalations/${ESCALATION_ID}`);
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'its panel on the alert list' })).toHaveAttribute('href', `/alerts?alert=${ALERT_ID}`);
  });

  it('closed by a suppression rule before any analysis: who closed it, the rule, and no track record to show', async () => {
    const reason = { code: 'suppression_rule', sentence: 'A suppression rule closed it before any analysis.' };
    const model: InvestigationOut = {
      ...AI_CLOSED_INVESTIGATION,
      outcome: { category: null, reason, blockers: [], evidence: [], closed_by: { kind: 'suppression_rule', reason, at: '2026-11-14T09:44:27Z', decision: null, rule_id: 'r1', rule_name: 'Patch window', source_alert_id: null } },
      summary: { text: null, written_by: null },
      claims: [],
      observations: [],
      not_established: { empty: [], not_checked: [{ what: 'Everything an investigation would look up', why: 'No investigation ran: a rule closed the alert first.' }], unavailable: [] },
      steps: [],
      track_record: null,
    };
    await renderPage({ model, alert: closedAlert({ normalized: {} }), esc: null });
    expect(screen.getByText('Closed by a suppression rule')).toBeInTheDocument();
    expect(screen.getAllByText('A suppression rule closed it before any analysis.')).toHaveLength(1);
    expect(screen.getByText('Patch window')).toBeInTheDocument();
    expect(screen.getByText('No investigation ran for this alert: there are no claims and no observations.')).toBeInTheDocument();
    expect(screen.getByText('No step is recorded for this alert yet.')).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('The track record counts the four AI outcomes. This alert has none of them.');
  });

  it('still being investigated: no outcome yet, and the page says so', async () => {
    const model: InvestigationOut = { ...AI_CLOSED_INVESTIGATION, outcome: null, summary: { text: null, written_by: null }, claims: [], observations: [], steps: [], track_record: null, not_established: { empty: [], not_checked: [], unavailable: [] } };
    const { container } = await renderPage({ model, alert: investigationAlert({ status: 'processing', summary: {} }), esc: null });
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'investigating');
    expect(screen.getByText('The investigation is still running.')).toBeInTheDocument();
  });

  it('says when the alert does not exist, and offers a retry when the alert or its investigation cannot be read', async () => {
    const reject = (path: string, status: number, message: string): Handler => (m, p) => (m === 'GET' && p === path ? Promise.reject(apiError(status, status === 404 ? 'not_found' : 'internal', message)) : undefined);
    const first = await renderPage({ model: null, handler: reject(`/alerts/${ALERT_ID}`, 404, 'Alert not found') });
    expect(screen.getByRole('heading', { level: 1, name: 'Alert not found' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the alerts' })).toHaveAttribute('href', '/alerts');
    first.unmount();
    const second = await renderPage({ handler: reject(`/alerts/${ALERT_ID}`, 500, 'Boom') });
    expect(screen.getByRole('heading', { level: 1, name: 'Alert' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    second.unmount();
    // The alert is there but its investigation fails with something other than 404: no silent fallback.
    await renderPage({ handler: reject(`/alerts/${ALERT_ID}/investigation`, 403, 'Not allowed for this tenant') });
    expect(await screen.findByText('Not allowed for this tenant')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: TITLE })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'What the investigation did' })).not.toBeInTheDocument();
  });

  it('says when the escalation cannot be read instead of claiming no decision was asked', async () => {
    await renderPage({ handler: (m, p) => (m === 'GET' && p === `/escalations/${ESCALATION_ID}` ? Promise.reject(apiError(503, 'unavailable', 'The escalation cannot be read now')) : undefined) });
    expect(await section('Decision').findByText('The escalation cannot be read now')).toBeInTheDocument();
    expect(screen.queryByText('No decision was asked of a person for this alert.')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
  });
});

describe('investigation view: an API without the read model (404) falls back to the adapter', () => {
  it('builds the same page from the alert, its escalation, its timeline and the response preview, and says what that API cannot give', async () => {
    const { container, calls } = await renderPage({ model: null });
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-source', 'adapter');
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent('The AI did not close this alert: high severity alerts are closed only by an analyst.');
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('Not yet available: This API version does not count how often analysts confirmed an outcome.');
    const backed = claimRow(3);
    expect(within(backed).getByText('Backed by O-01')).toBeInTheDocument();
    expect(backed.querySelector('[data-observation="O-01"]')).toHaveTextContent('Threat-intelligence reputation: domain cdn-invoice-portal.example');
    const steps = await screen.findByRole('region', { name: 'What the investigation did' });
    await waitFor(() => expect(steps.querySelectorAll('li[data-actor]')).toHaveLength(6));
    expect(steps).toHaveTextContent('Decision policy: send it to an analyst. High severity alerts are closed only by an analyst.');
    const rows = (await section('Proposed response').findAllByRole('row')).slice(1);
    expect(rows).toHaveLength(4);
    expect(within(rows[1]).getByRole('checkbox', { name: /^Run on true positive ?: Kill process on powershell.exe PID 7340$/ })).toBeEnabled();
    expect(paths(calls)).toEqual(expect.arrayContaining([`/alerts/${ALERT_ID}/events`, `/escalations/${ESCALATION_ID}/response-preview`]));
    // A 404 is an answer: the read model is not asked for again.
    expect(calls.filter((c) => c.path === `/alerts/${ALERT_ID}/investigation`)).toHaveLength(1);
  });

  it('shows the ledger’s own list for an alert that no longer waits, and the states of the fallback requests', async () => {
    const closed = closedAlert({ summary: { close_reason: 'ai_closed:audit_required', analysis: { verdict: 'benign', llm_used: true, conclusion: 'A routine package install.' } } });
    const first = await renderPage({ model: null, alert: closed, esc: null, events: [] });
    expect(screen.getByText('Closed by AI, sampled for audit')).toBeInTheDocument();
    expect(await section('Response').findByText('No response action was planned for this alert.')).toBeInTheDocument();
    expect(await screen.findByText('No step is recorded for this alert yet.')).toBeInTheDocument();
    first.unmount();
    const second = await renderPage({ model: null, preview: investigationPreview([]) });
    expect(await section('Proposed response').findByText('A true positive would propose no response action for this alert.')).toBeInTheDocument();
    second.unmount();
    await renderPage({
      model: null,
      handler: (_m, p) => (p.endsWith('/response-preview') || p.endsWith('/events') ? Promise.reject(apiError(503, 'unavailable', p.endsWith('/events') ? 'The timeline cannot be read now' : 'The plan cannot be computed now')) : undefined),
    });
    expect(await section('Proposed response').findByText('The plan cannot be computed now')).toBeInTheDocument();
    expect(await section('What the investigation did').findByText('The timeline cannot be read now')).toBeInTheDocument();
    expect(screen.queryByText('No step is recorded for this alert yet.')).not.toBeInTheDocument();
  });
});

describe('investigation view: verdict hidden', () => {
  it('"Hide the verdict" and V withhold the verdict, the claims and the model’s assessment; the evidence stays', async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    const toggle = screen.getByRole('button', { name: /^Hide the verdict/ });
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText('4 lookups · verdict malicious')).toBeInTheDocument();
    await user.click(toggle);
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
    expect(screen.getByRole('button', { name: /^Show the verdict/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('note')).toHaveTextContent('The verdict and the claims are hidden.');
    for (const withheld of [/^Word ran a hidden, encoded PowerShell command/, 'Needs your decision: likely malicious', 'Why it is with you.', 'Backed by O-03', 'Points to malicious', 'Stated by the rules', '4 lookups · verdict malicious', 'The deeper analysis did not judge it benign.', /^Not yet available in this section/]) {
      expect(screen.queryByText(withheld)).not.toBeInTheDocument();
    }
    expect(screen.queryByText(/^Word started PowerShell directly/)).not.toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('Hidden with the verdict.');
    // The evidence, the subject, what is not established and the decision bar stay.
    expect(claimRow(5).querySelector('[data-observation="O-03"]')).toBeInTheDocument();
    expect(claimRow(5)).not.toHaveAttribute('data-check');
    expect(screen.getByRole('list', { name: 'Subject of the alert' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'What is not established' })).toBeInTheDocument();
    expect(verdictButton(/True positive/)).toBeEnabled();

    await user.keyboard('v');
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'shown');
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    await user.keyboard('V');
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
  });

  it('a blind-audit sample stays hidden: the read model withholds the AI’s side and there is nothing to reveal', async () => {
    const user = userEvent.setup();
    const model: InvestigationOut = {
      ...ESCALATED_INVESTIGATION,
      hidden_for_blind_audit: true,
      outcome: null,
      summary: { text: null, written_by: null },
      claims: [],
      observations: [],
      not_established: { empty: [], not_checked: [], unavailable: [] },
      track_record: null,
      response: { source: 'none', actions: [] },
    };
    const { container } = await renderPage({ model, alert: investigationAlert({ summary: { escalation_id: ESCALATION_ID } }) });
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
    expect(screen.getByRole('note')).toHaveTextContent('withheld for everyone until an analyst labels it on the Blind audit page');
    expect(screen.getByRole('button', { name: /^Show the verdict/ })).toBeDisabled();
    expect(screen.getByText('The claims and the observations are withheld with the verdict.')).toBeInTheDocument();
    await user.keyboard('v');
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
  });
});

describe('investigation view: the decision bar', () => {
  it('one key chooses the verdict, the bar says what it sets in motion, and Ctrl+Enter records it and opens the next alert', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage({
      handler: (m, p) =>
        m === 'GET' && p === '/escalations' ? { items: [investigationEscalation(), investigationEscalation({ id: 'esc-next', alert_id: 'next-alert', status: 'open', assigned_to: null })], next_cursor: null } : undefined,
    });
    expect(effect()).toHaveTextContent('Choose a verdict to see what it sets in motion.');
    expect(dock().getByText('analyst@acme.test')).toBeInTheDocument();

    await user.keyboard('b');
    expect(verdictButton(/Benign, expected here/)).toHaveAttribute('aria-pressed', 'true');
    expect(effect()).toHaveTextContent('Closes it as real activity that is expected for this customer.');
    await user.keyboard('f');
    expect(verdictButton(/False positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(verdictButton(/Benign, expected here/)).toHaveAttribute('aria-pressed', 'false');
    expect(effect()).toHaveTextContent('Closes it as not malicious and feeds the verdict back to triage.');
    await user.keyboard('T');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(effect()).toHaveTextContent('Marks it malicious, runs no action now and sends 5 others to Approvals. A note is required.');

    // Ticking an action changes what the verdict sets in motion; a key pressed on the checkbox is still a shortcut.
    await user.click(screen.getByRole('checkbox', { name: TERMINATE }));
    expect(effect()).toHaveTextContent('Marks it malicious, runs 1 action now (1 ticked) and sends 4 others to Approvals. A note is required.');
    await user.keyboard('2');
    expect(claimButton(2)).toHaveAttribute('aria-pressed', 'true');
    expect(claimButton(1)).toHaveAttribute('aria-pressed', 'false');

    // A true positive needs a note: Ctrl+Enter stops at the note field.
    await user.keyboard('{Control>}{Enter}{/Control}');
    const note = dock().getByLabelText('What did you check');
    expect(dock().getByText('A true positive needs a note: what did you check?')).toBeInTheDocument();
    expect(note).toHaveFocus();
    expect(note).toHaveAttribute('aria-invalid', 'true');
    expect(decisionBody(calls)).toBeUndefined();

    // Typing in the note is typing: no shortcut fires.
    await user.keyboard('fbvn Checked the process tree');
    expect(note).toHaveValue('fbvn Checked the process tree');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /^Hide the verdict/ })).toBeInTheDocument();
    expect(dock().queryByText('A true positive needs a note: what did you check?')).not.toBeInTheDocument();

    await user.keyboard('{Control>}{Enter}{/Control}');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/alerts/next-alert'));
    expect(decisionBody(calls)).toEqual({
      decision: 'true_positive',
      version: 3,
      notes: 'fbvn Checked the process tree',
      approved_actions: ['terminate_process:powershell.exe PID 7340'],
      feedback: null,
      suggest_suppression: null,
    });
    expect(await screen.findByText('Decision recorded; 1 alert(s) resumed.')).toBeInTheDocument();
    // The next alert opens on a fresh page.
    expect(await screen.findByRole('heading', { level: 1, name: 'The next alert' })).toBeInTheDocument();
  });

  it('N asks for more information as the API does it today: says exactly what happens, needs a note, and records needs_more_info', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage();
    const more = verdictButton(/Needs more/);
    expect(more).toBeEnabled();
    expect(more).not.toHaveAttribute('aria-disabled');
    await user.click(screen.getByRole('checkbox', { name: TERMINATE }));
    await user.keyboard('n');
    expect(more).toHaveAttribute('aria-pressed', 'true');
    expect(effect()).toHaveTextContent(
      'Records no verdict. The analysis runs again and reads your note, once per alert by default; then the alert comes back to an analyst as a new escalation. No response action runs. A note is required.',
    );
    expect(effect()).toHaveTextContent(NEEDS_MORE_EFFECT);
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(dock().getByText('Say what is missing: the analysis reads your note.')).toBeInTheDocument();
    expect(dock().getByLabelText('What did you check')).toHaveFocus();
    expect(decisionBody(calls)).toBeUndefined();
    await user.keyboard('Who else received this email?');
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
    // No action is pre-approved by a request for more information, even when one was ticked.
    expect(decisionBody(calls)).toEqual({ decision: 'needs_more_info', version: 3, notes: 'Who else received this email?', approved_actions: [], feedback: null, suggest_suppression: null });
    expect(await section('Decision').findByText('Needs more information')).toBeInTheDocument();
  });

  it('records with the buttons too; a false positive needs no note, pre-approves nothing, and the page then shows the decision and reloads the read model', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage();
    await user.click(screen.getByRole('checkbox', { name: /^Run on true positive ?: Block domain/ }));
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(effect()).toHaveTextContent('Choose a verdict first: T, B, F or N.');
    await user.click(verdictButton(/False positive/));
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
    expect(decisionBody(calls)).toEqual({ decision: 'false_positive', version: 3, notes: null, approved_actions: [], feedback: null, suggest_suppression: false });
    expect(screen.getByTestId('location')).toHaveTextContent(`/alerts/${ALERT_ID}`);
    expect(await section('Decision').findByText('False positive')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
    await waitFor(() => expect(calls.filter((c) => c.path === `/alerts/${ALERT_ID}/investigation`).length).toBeGreaterThan(1));
  });

  it('records once when Ctrl+Enter is pressed again before the answer, and not from inside a dialog', async () => {
    const user = userEvent.setup();
    let release: (() => void) | undefined;
    const { calls, container } = await renderPage({
      handler: (m, p) =>
        m === 'POST' && p.endsWith('/decision')
          ? new Promise<void>((resolve) => (release = resolve)).then(() => ({ escalation: investigationEscalation({ status: 'decided' }), approved_actions: [], resumed_alert_ids: [ALERT_ID], own_review_alert_ids: [], resumes_enqueued: 1, resumes_failed: 0 }))
          : undefined,
    });
    const sent = () => calls.filter((c) => c.method === 'POST' && c.path.endsWith('/decision'));
    await user.keyboard('f');
    // A shortcut pressed inside a dialog belongs to the dialog.
    const dialog = document.createElement('div');
    dialog.setAttribute('role', 'dialog');
    dialog.innerHTML = '<button type="button">inside</button>';
    container.appendChild(dialog);
    (dialog.firstElementChild as HTMLElement).focus();
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(sent()).toHaveLength(0);
    dialog.remove();
    await user.keyboard('{Control>}{Enter}{/Control}');
    await user.keyboard('{Control>}{Enter}{/Control}');
    await waitFor(() => expect(sent()).toHaveLength(1));
    release?.();
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(sent()).toHaveLength(1);
    expect(dock().queryByText('This escalation changed')).not.toBeInTheDocument();
  });

  it('single-key shortcuts can be switched off, a choice each user keeps; Ctrl+Enter still works', async () => {
    const user = userEvent.setup();
    const { unmount } = await renderPage();
    const toggle = dock().getByRole('button', { name: 'Single-key shortcuts: on' });
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await user.click(toggle);
    expect(dock().getByRole('button', { name: 'Single-key shortcuts: off' })).toHaveAttribute('aria-pressed', 'false');
    await user.keyboard('tnv1');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'false');
    expect(verdictButton(/Needs more/)).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /^Hide the verdict/ })).toBeInTheDocument();
    expect(claimButton(1)).toHaveAttribute('aria-pressed', 'false');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(effect()).toHaveTextContent('Choose a verdict first: T, B, F or N.');
    // Stored for this user only, as a display preference.
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-1')).toBe('off');
    expect(window.localStorage).toHaveLength(1);
    unmount();
    // Another user on the same browser has their own switch.
    const other = await renderPage({ id: 'u-2', esc: investigationEscalation({ assigned_to: 'u-2' }) });
    expect(dock().getByRole('button', { name: 'Single-key shortcuts: on' })).toBeInTheDocument();
    other.unmount();
    // The same user finds it off on the next alert, and can switch it back on.
    await renderPage();
    await user.click(dock().getByRole('button', { name: 'Single-key shortcuts: off' }));
    expect(dock().getByRole('button', { name: 'Single-key shortcuts: on' })).toBeInTheDocument();
    expect(window.localStorage.getItem('lg-sotf.single-keys.u-1')).toBe('on');
    await user.keyboard('t');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
  });

  it('an unclaimed escalation is claimed first: "Claim to decide"', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage({ esc: investigationEscalation({ status: 'open', assigned_to: null, assigned_to_email: null, claimed_at: null }) });
    expect(screen.queryByText('Owner')?.parentElement).toHaveTextContent('OwnerUnassigned');
    expect(screen.getByRole('checkbox', { name: TERMINATE })).toBeDisabled();
    await user.keyboard('t');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(effect()).toHaveTextContent('Claim first: a decision is recorded under the name of the analyst who holds the escalation.');
    expect(dock().queryByRole('button', { name: /^Record and open next/ })).not.toBeInTheDocument();
    await user.click(dock().getByRole('button', { name: 'Claim to decide' }));
    expect(await screen.findByText('Escalation claimed.')).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith('/claim'))?.body).toEqual({ version: 3 });
    expect(await dock().findByRole('button', { name: /^Record and open next/ })).toBeEnabled();
    await waitFor(() => expect(screen.getByRole('checkbox', { name: TERMINATE })).toBeEnabled());
    // The verdict chosen before the claim is kept.
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
  });

  it('an admin takes over an escalation held by someone else; a failed claim says why', async () => {
    const user = userEvent.setup();
    let fail = true;
    await renderPage({
      role: 'admin',
      esc: investigationEscalation({ assigned_to: 'u-other', assigned_to_email: 'other@acme.test' }),
      handler: (m, p) => {
        if (m === 'POST' && p.endsWith('/claim') && fail) {
          fail = false;
          throw apiError(409, 'conflict', 'stale');
        }
        return undefined;
      },
    });
    expect(screen.getByText('Owner').parentElement).toHaveTextContent('Ownerother@acme.test');
    await user.click(dock().getByRole('button', { name: 'Take over to decide' }));
    expect(await screen.findByText('Someone else changed this escalation first; it has been reloaded.')).toBeInTheDocument();
    await user.click(dock().getByRole('button', { name: 'Take over to decide' }));
    expect(await screen.findByText('Escalation taken over.')).toBeInTheDocument();
  });

  it('is read-only for a viewer and for an analyst when someone else holds the escalation, and says why', async () => {
    const user = userEvent.setup();
    const { unmount, calls } = await renderPage({ role: 'viewer' });
    expect(effect()).toHaveTextContent('Requires the analyst role.');
    for (const name of [/True positive/, /Benign, expected here/, /False positive/, /Needs more/]) expect(verdictButton(name)).toBeDisabled();
    expect(dock().getByLabelText('What did you check')).toBeDisabled();
    expect(dock().getByRole('button', { name: /^Record and open next/ })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: TERMINATE })).toBeDisabled();
    await user.keyboard('tn');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(effect()).toHaveTextContent('Requires the analyst role.');
    expect(decisionBody(calls)).toBeUndefined();
    unmount();
    await renderPage({ esc: investigationEscalation({ assigned_to: 'u-other', assigned_to_email: 'other@acme.test' }) });
    expect(effect()).toHaveTextContent('Claimed by another analyst; only they or an admin can decide it.');
    expect(dock().queryByRole('button', { name: /to decide$/ })).not.toBeInTheDocument();
  });

  it('keeps the verdict and the note on a version conflict and explains the change; shows other errors', async () => {
    const user = userEvent.setup();
    let attempts = 0;
    const { calls } = await renderPage({
      esc: investigationEscalation({ status: 'expired' }),
      handler: (m, p) => {
        if (m === 'POST' && p.endsWith('/decision')) {
          attempts += 1;
          if (attempts === 1) throw apiError(409, 'conflict', 'stale version');
          if (attempts === 2) throw apiError(403, 'forbidden', 'role analyst may not approve high risk action');
        }
        return undefined;
      },
    });
    expect(dock().getByText('The SLA of this escalation has expired. A decision is still accepted and audited as late.')).toBeInTheDocument();
    await user.click(verdictButton(/Benign, expected here/));
    await user.type(dock().getByLabelText('What did you check'), 'Known admin tool.');
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(await dock().findByText(/changed while you were reviewing it \(now expired, assigned to analyst@acme.test\)/)).toBeInTheDocument();
    expect(dock().getByLabelText('What did you check')).toHaveValue('Known admin tool.');
    expect(verdictButton(/Benign, expected here/)).toHaveAttribute('aria-pressed', 'true');
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(await dock().findByText('role analyst may not approve high risk action')).toBeInTheDocument();
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    await screen.findByText('Decision recorded; 1 alert(s) resumed.');
    expect(calls.filter((c) => c.path.endsWith('/decision'))).toHaveLength(3);
    expect(decisionBody(calls)).toMatchObject({ decision: 'benign_positive', notes: 'Known admin tool.', suggest_suppression: false });
  });
});

describe('investigation view: rules and helpers', () => {
  const action = (overrides: Partial<ProposedActionOut> = {}): ProposedActionOut => ({ ...ESCALATED_INVESTIGATION.response.actions[1], ...overrides });

  it('pre-approves only what the preview allows, and never an action without a target or an entry', () => {
    const ok = action();
    const noTarget = action({ target: ' ', approval_entry: 'terminate_process: ' });
    const noEntry = action({ approval_entry: null });
    const admin = action({ role_lock: 'admin', can_preapprove: false, approval_entry: 'isolate_host:WS-1' });
    const off = action({ role_lock: 'disabled', can_preapprove: false });
    const blocked = action({ without_preapproval: 'blocked', can_preapprove: false });
    const automatic = action({ without_preapproval: 'automatic', can_preapprove: false, approval_entry: 'create_ticket:SOC' });
    const waits = action({ can_preapprove: false });
    const planned = RESPONSE_PLAN_INVESTIGATION.response.actions[1];
    expect(preapproval(ok)).toEqual({ allowed: true, instead: null });
    expect(preapproval(noTarget)).toEqual({ allowed: false, instead: 'No target sent: approve it on the Approvals page' });
    expect(preapproval(noEntry).allowed).toBe(false);
    expect(preapproval(admin).instead).toBe('Needs an admin');
    expect(preapproval(off).instead).toBe('Not available');
    expect(preapproval(blocked).instead).toBe('Not available');
    expect(preapproval(automatic).instead).toBe('Runs automatically');
    expect(preapproval(waits).instead).toBe('Waits on the Approvals page');
    expect(preapproval(planned).allowed).toBe(false);
    const all = [ok, noTarget, noEntry, admin, automatic];
    expect(preapprovedEntries(all, new Set(all.flatMap((a) => (a.approval_entry ? [a.approval_entry] : []))))).toEqual(['terminate_process:powershell.exe PID 7340']);
  });

  it('says what a verdict sets in motion from the plan', () => {
    const plan = [action(), action({ without_preapproval: 'automatic', can_preapprove: false, approval_entry: 'create_ticket:SOC' })];
    const entry = 'terminate_process:powershell.exe PID 7340';
    expect(effectOf('true_positive', [], new Set())).toBe('Marks it malicious and plans the response. A note is required.');
    expect(effectOf('true_positive', plan, new Set([entry]))).toBe('Marks it malicious, runs 2 actions now (1 ticked). A note is required.');
    expect(effectOf('true_positive', plan, new Set())).toBe('Marks it malicious, runs 1 action now (0 ticked) and sends 1 other to Approvals. A note is required.');
    expect(effectOf(null, plan, new Set())).toBe('Choose a verdict to see what it sets in motion.');
    expect(effectOf('needs_more_info', plan, new Set([entry]))).toBe(NEEDS_MORE_EFFECT);
    // A ticked action is counted once, whatever it would do without the tick: the count of the others never goes negative.
    const tickable = [action({ without_preapproval: 'automatic' }), action({ target: 'u-7', approval_entry: 'disable_user:u-7' })];
    expect(effectOf('true_positive', tickable, new Set([entry]))).toBe('Marks it malicious, runs 1 action now (1 ticked) and sends 1 other to Approvals. A note is required.');
    expect(effectOf('true_positive', tickable, new Set([entry, 'disable_user:u-7']))).toBe('Marks it malicious, runs 2 actions now (2 ticked). A note is required.');
  });

  it('counts the claims that are backed, rejected and bare', () => {
    const c = (check: string) => ({ check });
    expect(checkLine([])).toBeUndefined();
    expect(checkLine([c('supported')])).toBe('1 of the 1 claim is backed by what the tools returned.');
    expect(checkLine([c('supported'), c('supported'), c('rejected'), c('unsupported')])).toBe('2 of the 4 claims are backed by what the tools returned; 1 was rejected; 1 cites no fact.');
    expect(checkLine([c('rejected'), c('rejected'), c('unsupported'), c('unsupported')])).toBe('0 of the 4 claims are backed by what the tools returned; 2 were rejected; 2 cite no fact.');
  });

  it('reads what is pending for a section from the read model, each reason once', () => {
    const pending_harness = [
      { field: 'claims[].check', why: 'No checker yet.', issue: 207 },
      { field: 'claims[].observation_ids', why: 'No checker yet.', issue: 201 },
      { field: 'observations', why: 'Only reputation lookups.', issue: 200 },
      { field: 'not_established.not_checked', why: 'No playbook.', issue: 205 },
      { field: 'stepsize', why: 'Not a step field.', issue: 1 },
    ];
    expect(pendingWhy({ pending_harness }, 'claims', 'observations')).toEqual(['No checker yet.', 'Only reputation lookups.']);
    expect(pendingWhy({ pending_harness }, 'not_established')).toEqual(['No playbook.']);
    expect(pendingWhy({ pending_harness }, 'steps')).toEqual([]);
    expect(pendingWhy({ pending_harness: [] }, 'claims')).toEqual([]);
    expect(entityHref('a b&c')).toBe('/alerts?view=all&q=a+b%26c');
  });

  it('treats text fields as typing and leaves checkboxes and buttons to the shortcuts', () => {
    const make = (tag: string, attrs: Record<string, string> = {}) => Object.assign(document.createElement(tag), attrs);
    expect(isTyping(make('input'))).toBe(true);
    expect(isTyping(make('input', { type: 'search' }))).toBe(true);
    expect(isTyping(make('textarea'))).toBe(true);
    expect(isTyping(make('select'))).toBe(true);
    expect(isTyping(make('input', { type: 'checkbox' }))).toBe(false);
    expect(isTyping(make('button'))).toBe(false);
    expect(isTyping(null)).toBe(false);
  });

  it('the alert side panel links to the full page', async () => {
    const { api } = fakeApi((_m, path) => (path === `/alerts/${ALERT_ID}` ? investigationAlert({ summary: {} }) : path.endsWith('/events') ? { items: [], next_cursor: null } : path === '/actions' ? { items: [], next_cursor: null } : []));
    const session = await signedInSession(api);
    renderWithSession(<AlertSidePanel alertId={ALERT_ID} onClose={() => undefined} />, session);
    expect(await screen.findByRole('link', { name: 'Open full page' })).toHaveAttribute('href', `/alerts/${ALERT_ID}`);
  });
});
