import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { AlertDetailOut, AlertEventOut, DecisionIn, EscalationOut, ResponsePreviewOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import {
  ALERT_ID,
  ESCALATION_ID,
  event,
  inMinutes,
  investigationAlert,
  investigationEscalation,
  investigationEvents,
  investigationPreview,
  plannedAction,
} from '../../test/investigation';
import { AlertSidePanel } from '../alerts/AlertPanel';
import { effectOf } from './DecisionDock';
import InvestigationPage from './InvestigationPage';
import { checkLine } from './InvestigationPage';
import { isTyping } from './keys';
import { preapproval, preapprovedEntries } from './ResponseTable';

const TITLE = 'Encoded PowerShell launched by Microsoft Word';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown) => unknown;

interface Setup {
  alert?: AlertDetailOut;
  esc?: EscalationOut | null;
  events?: AlertEventOut[];
  preview?: ResponsePreviewOut;
  role?: string;
  id?: string;
  handler?: Handler;
}

async function renderPage({ alert = investigationAlert(), esc = investigationEscalation(), events = investigationEvents(), preview = investigationPreview(), role = 'analyst', id = 'u-1', handler }: Setup = {}) {
  let current = esc;
  const { api, calls } = fakeApi((method, path, body) => {
    const answer = handler?.(method, path, body);
    if (answer !== undefined) return answer;
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
    if (method === 'GET' && path === '/alerts/next-alert') return investigationAlert({ id: 'next-alert', title: 'The next alert', summary: {}, findings: [] });
    if (path.endsWith('/events')) return { items: [], next_cursor: null };
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

const dock = () => within(screen.getByRole('region', { name: 'Your decision' }));
const effect = () => screen.getByTestId('decision-effect');
const verdictButton = (name: RegExp) => dock().getByRole('button', { name });
const claimButton = (n: number) => screen.getByRole('button', { name: `Claim ${n}, select` });
const claimRow = (n: number) => claimButton(n).closest('[data-claim]') as HTMLElement;
const decisionBody = (calls: Array<{ method: string; path: string; body?: unknown }>) =>
  calls.find((c) => c.method === 'POST' && c.path.endsWith('/decision'))?.body as DecisionIn | undefined;
const section = (name: string | RegExp) => within(screen.getByRole('region', { name }));

describe('investigation view: needs your decision, likely malicious', () => {
  it('opens with the outcome and the verdict as a sentence, then why it is with a person', async () => {
    const { container } = await renderPage();
    expect(screen.getByRole('heading', { level: 1, name: TITLE })).toBeInTheDocument();
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'needs_decision_malicious');
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the model')).toBeInTheDocument();
    expect(screen.getByText(/^Word ran a hidden, encoded PowerShell command/)).toHaveTextContent('Two minutes later the same host read LSASS memory.');
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent(
      'Why it is with you. The AI did not close this alert: high severity alerts are closed only by an analyst. 1 of the 5 claims is backed by what the tools returned; 4 cite no fact.',
    );
    // The alert's own description comes next, marked as observed.
    expect(screen.getByText('The alert, as Wazuh manager sent it')).toBeInTheDocument();
    expect(screen.getByText(/^Rule 92213 \(level 12\)/)).toBeInTheDocument();
  });

  it('names the tenant, the case, the severity in words, the deadline and the owner, and resolves the subject to chips', async () => {
    await renderPage();
    const crumb = within(screen.getByRole('navigation', { name: 'Breadcrumb' }));
    expect(crumb.getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/alerts');
    expect(crumb.getByText('Case CASE-2291')).toBeInTheDocument();
    expect(await crumb.findByText('Northwind Logistics')).toBeInTheDocument();
    const severity = screen.getByText('High', { selector: '[data-severity="high"]' });
    expect(severity).not.toHaveClass('capitalize');
    expect(screen.getByText(/left$/)).toHaveAttribute('title', expect.stringMatching(/^Deadline /));
    expect(screen.getByText('Owner').parentElement).toHaveTextContent('Owneryou');
    const subject = within(screen.getByRole('list', { name: 'Subject of the alert' }));
    expect(subject.getByText('WS-FIN-0142').parentElement).toHaveTextContent('HostWS-FIN-0142');
    expect(subject.getByText('m.keller').parentElement).toHaveTextContent('Userm.keller');
    expect(subject.getByText('+1 more').parentElement).toHaveTextContent('Process+1 more');
    expect(subject.getByText('T1059.001, T1204.002').parentElement).toHaveTextContent('ATT&CK');
    expect(subject.getByText('Office application starts a script host')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Evidence record' })).toHaveAttribute('href', '#evidence-record');
    expect(screen.getByRole('group', { name: 'Export evidence' })).toBeInTheDocument();
  });

  it('puts each claim beside the observation it rests on, with the decisive token highlighted', async () => {
    await renderPage();
    const claims = section('Claims, each beside the fact it rests on');
    expect(claims.getByText('Left: what the model says. Right: what a tool returned, unedited.')).toBeInTheDocument();
    const first = claimRow(1);
    expect(first).toHaveAttribute('data-check', 'supported');
    expect(within(first).getByText('Backed by O-01')).toBeInTheDocument();
    const observed = first.querySelector('[data-observation="O-01"]') as HTMLElement;
    expect(observed).toHaveAttribute('data-outcome', 'success');
    expect(within(observed).getByText('returned data')).toBeInTheDocument();
    expect([...observed.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['malicious']);
    expect(observed).toHaveTextContent('no hash yet');
    // What a tool returned and no claim cites is still on the page.
    const uncited = claims.getByRole('heading', { name: 'Returned by the tools, cited by no claim' }).parentElement as HTMLElement;
    expect(uncited.querySelector('[data-observation="O-03"]')).toHaveTextContent('Earlier alerts of this tenant for host WS-FIN-0142');
    expect(claims.getByText(/^Not yet available: the evidence checker\./)).toBeInTheDocument();
  });

  it('marks a claim unsupported beside a lookup that returned nothing, and shows a failed lookup as failed', async () => {
    const base = investigationAlert();
    const analysis = { ...(base.summary?.analysis as object), reasoning: ['The download address 203.0.113.50 has no reputation record.', 'The file 5d1e0c9a7b3f4e2d8c6a1b0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a29b07c is unknown.', 'It names nothing.'] };
    await renderPage({ alert: investigationAlert({ summary: { ...base.summary, analysis, triage: {} } }) });
    const empty = claimRow(1);
    expect(empty).toHaveAttribute('data-check', 'unsupported');
    expect(within(empty).getByText('Unsupported')).toBeInTheDocument();
    expect(within(empty).getByText('The lookup it names returned nothing, and nothing found is never counted as proof.')).toBeInTheDocument();
    const nothing = empty.querySelector('[data-observation="O-02"]') as HTMLElement;
    expect(nothing).toHaveAttribute('data-outcome', 'empty');
    expect(within(nothing).getByText('returned nothing')).toBeInTheDocument();
    expect(nothing).toHaveTextContent('No record for this IP address.');
    const failed = claimRow(2).querySelector('[data-observation="O-04"]') as HTMLElement;
    expect(failed).toHaveAttribute('data-outcome', 'failed');
    expect(within(failed).getByText('failed')).toBeInTheDocument();
    expect(failed).toHaveTextContent('virustotal answered with an error.');
    expect(failed).toHaveTextContent('time not recorded');
    const bare = claimRow(3);
    expect(within(bare).getByText('It names no lookup.')).toBeInTheDocument();
    expect(within(bare).getByText('No observation is cited for this claim.')).toBeInTheDocument();
  });

  it('lists what is not established in three kinds, and says the track record is not measured yet', async () => {
    const { container } = await renderPage();
    const ne = screen.getByRole('region', { name: 'What is not established' });
    expect(ne.querySelector('[data-kind="empty"]')).toHaveTextContent('Reputation of IP address 203.0.113.50.');
    expect(ne.querySelector('[data-kind="not"]')).toHaveTextContent('Reputation of domain unchecked.exampleNo lookup was recorded for it.');
    expect(ne.querySelector('[data-kind="cannot"]')).toHaveTextContent('virustotal answered with an error.');
    expect(within(ne).getByText(/^Not yet available: what the playbook leaves out\./)).toBeInTheDocument();
    const track = screen.getByRole('complementary', { name: 'Track record of this outcome' });
    expect(track.querySelector('[data-track]')).toHaveAttribute('data-track', 'none');
    expect(track).toHaveTextContent('How often analysts confirmed the alerts sent to a person as likely malicious is not counted yet');
    expect(container).not.toHaveTextContent(/\d\s?%/);
  });

  it('writes the steps in plain words and the proposed response with exact targets', async () => {
    await renderPage();
    const steps = screen.getByRole('region', { name: 'What the investigation did' });
    expect(steps.querySelectorAll('li[data-actor]')).toHaveLength(6);
    expect(steps).toHaveTextContent('Decision policy: send it to an analyst. High severity alerts are closed only by an analyst.');
    expect(steps).not.toHaveTextContent(/node|gate|plan_response/i);
    const plan = section('Proposed response');
    expect(plan.getByRole('link', { name: 'Approvals' })).toHaveAttribute('href', '/approvals');
    const rows = (await plan.findAllByRole('row')).slice(1);
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent('Isolate host');
    expect(within(rows[0]).getByText('WS-FIN-0142').tagName).toBe('CODE');
    expect(rows[0]).toHaveTextContent('Needs an admin');
    expect(rows[0]).toHaveTextContent('High risk');
    expect(rows[0]).toHaveTextContent('YesRelease host');
    expect(within(rows[0]).queryByRole('checkbox')).not.toBeInTheDocument();
    expect(within(rows[1]).getByText('powershell.exe PID 7340')).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('NoA stopped process is not restarted');
    expect(within(rows[1]).getByRole('checkbox', { name: /^Run on true positive ?: Kill process on powershell.exe PID 7340$/ })).not.toBeChecked();
    expect(rows[3]).toHaveTextContent('BlockedThe autonomy policy switches off critical-risk actions');
    expect(rows[3]).toHaveTextContent('Not available');
    for (const row of rows) expect(row).toHaveTextContent('Not available yet');
  });
});

describe('investigation view: other outcomes', () => {
  it('needs your decision, unsure', async () => {
    const base = investigationAlert();
    const { container } = await renderPage({
      alert: investigationAlert({ summary: { ...base.summary, analysis: { verdict: 'inconclusive', conclusion: 'A sign-in from a new country, by a user who travels.', llm_used: false } } }),
      esc: investigationEscalation({ reason: 'assessment in the grey zone', summary: { verdict: 'inconclusive' } }),
    });
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'needs_decision_unsure');
    expect(screen.getByText('Needs your decision: unsure')).toBeInTheDocument();
    expect(screen.getByText('Summary written by the rules')).toBeInTheDocument();
    expect(screen.getByText('Why it is with you.').parentElement).toHaveTextContent('The AI did not close this alert: assessment in the grey zone.');
    expect(screen.getByText('Left: what the analysis rules state. Right: what a tool returned, unedited.')).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('alerts sent to a person as unsure');
  });

  it('closed by the AI and sampled for audit: why it was closed, what ran, and no decision bar', async () => {
    const { container, calls } = await renderPage({
      alert: investigationAlert({
        status: 'closed',
        disposition: 'benign',
        summary: {
          close_reason: 'ai_closed:audit_required',
          analysis: { verdict: 'benign', llm_used: true, conclusion: 'A routine package install by the configuration management agent.' },
          decision: { route: 'close', reason: 'AI-closed, audit required: the analysis judged it benign', code: 'model_closed' },
        },
        findings: [],
      }),
      esc: null,
      events: [event('2026-11-14T09:44:36Z', 'node.completed', 'close', { disposition: 'benign', close_reason: 'ai_closed:audit_required' })],
    });
    expect(container.querySelector('[data-headline]')).toHaveAttribute('data-headline', 'ai_closed_audit');
    expect(screen.getByText('Closed by AI, sampled for audit')).toBeInTheDocument();
    expect(screen.getByText('A routine package install by the configuration management agent.')).toBeInTheDocument();
    expect(screen.getByText('Why it was closed.').parentElement).toHaveTextContent('Why it was closed. AI-closed, audit required: the analysis judged it benign.');
    expect(screen.getByText('The analysis recorded no claim for this alert.')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'What the investigation did' })).toHaveTextContent('Closed as benign on the analysis alone; it stays in the pool for the blind audit.');
    expect(await section('Response').findByText('No response action was planned for this alert.')).toBeInTheDocument();
    expect(section('Decision').getByText('No decision was asked of a person for this alert.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
    expect(screen.queryByText(/left$/)).not.toBeInTheDocument();
    expect(calls.some((c) => c.path.endsWith('/response-preview'))).toBe(false);
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('alerts the AI closed and sampled for audit');
  });

  it('closed by a suppression rule without an investigation', async () => {
    await renderPage({
      alert: investigationAlert({ status: 'closed', summary: { close_reason: 'suppression_rule', suppressed_by: { type: 'suppression_rule', name: 'Patch window' } }, findings: [], normalized: {} }),
      esc: null,
      events: [],
    });
    expect(screen.getByText('Closed by a suppression rule')).toBeInTheDocument();
    expect(screen.getByText('Suppression rule "Patch window" matched this alert.')).toBeInTheDocument();
    expect(screen.getByText('No investigation ran for this alert: there are no claims and no observations.')).toBeInTheDocument();
    expect(screen.getByText('No step is recorded for this alert yet.')).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('alerts with this outcome');
  });

  it('an escalation already decided: the decision on record instead of the bar', async () => {
    await renderPage({
      alert: investigationAlert({ status: 'waiting_approval' }),
      esc: investigationEscalation({ status: 'decided', decision: 'true_positive', decision_notes: 'Confirmed with the user.', decided_by: 'u-9', decided_by_email: 'lead@acme.test', decided_at: '2026-11-14T10:20:00Z' }),
    });
    expect(screen.getByText('Waiting for an approval')).toBeInTheDocument();
    const decision = section('Decision');
    expect(decision.getByText('Decided by a person')).toBeInTheDocument();
    expect(decision.getByText('True positive')).toBeInTheDocument();
    expect(decision.getByText('by lead@acme.test')).toBeInTheDocument();
    expect(decision.getByText('Confirmed with the user.')).toBeInTheDocument();
    expect(decision.getByRole('link', { name: 'Open the escalation' })).toHaveAttribute('href', `/escalations/${ESCALATION_ID}`);
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'its panel on the alert list' })).toHaveAttribute('href', `/alerts?alert=${ALERT_ID}`);
  });

  it('says when the alert does not exist, and offers a retry on another error', async () => {
    const { unmount } = await renderPage({ handler: (m, p) => (m === 'GET' && p === `/alerts/${ALERT_ID}` ? Promise.reject(apiError(404, 'not_found', 'Alert not found')) : undefined) });
    expect(screen.getByRole('heading', { level: 1, name: 'Alert not found' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the alerts' })).toHaveAttribute('href', '/alerts');
    unmount();
    await renderPage({ handler: (m, p) => (m === 'GET' && p === `/alerts/${ALERT_ID}` ? Promise.reject(apiError(500, 'internal', 'Boom')) : undefined) });
    expect(screen.getByRole('heading', { level: 1, name: 'Alert' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('says when the escalation cannot be read instead of claiming no decision was asked', async () => {
    await renderPage({ handler: (m, p) => (m === 'GET' && p === `/escalations/${ESCALATION_ID}` ? Promise.reject(apiError(503, 'unavailable', 'The escalation cannot be read now')) : undefined) });
    expect(await section('Decision').findByText('The escalation cannot be read now')).toBeInTheDocument();
    expect(screen.queryByText('No decision was asked of a person for this alert.')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
  });

  it('says when the response plan is empty, forced to a dry run, or cannot be computed', async () => {
    const { unmount } = await renderPage({ preview: { ...investigationPreview([]), dry_run_forced: true } });
    expect(await screen.findByText('The policy plans no response action for this alert.')).toBeInTheDocument();
    expect(screen.getByText('Dry run')).toBeInTheDocument();
    expect(effect()).toHaveTextContent('Choose a verdict to see what it sets in motion.');
    unmount();
    await renderPage({ handler: (_m, p) => (p.endsWith('/response-preview') ? Promise.reject(apiError(503, 'unavailable', 'The plan cannot be computed now')) : undefined) });
    expect(await section('Proposed response').findByText('The plan cannot be computed now')).toBeInTheDocument();
  });
});

describe('investigation view: verdict hidden', () => {
  it('"Hide the verdict" and V withhold the verdict, the claims and the model’s assessment; the evidence stays', async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    const toggle = screen.getByRole('button', { name: /^Hide the verdict/ });
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText(/^assessed as malicious/)).toBeInTheDocument();
    await user.click(toggle);
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
    expect(screen.getByRole('button', { name: /^Show the verdict/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('note')).toHaveTextContent('The verdict and the claims are hidden.');
    for (const withheld of [/^Word ran a hidden, encoded PowerShell command/, 'Needs your decision: likely malicious', 'Why it is with you.', 'Backed by O-01', 'Points to malicious', /^assessed as malicious/, /^Not yet available: the evidence checker/]) {
      expect(screen.queryByText(withheld)).not.toBeInTheDocument();
    }
    expect(screen.queryByText(/The script came from cdn-invoice-portal.example/)).not.toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Track record of this outcome' })).toHaveTextContent('Hidden with the verdict.');
    // The evidence, the subject, what is not established and the decision bar stay.
    expect(claimRow(1).querySelector('[data-observation="O-01"]')).toBeInTheDocument();
    expect(claimRow(1)).not.toHaveAttribute('data-check');
    expect(screen.getByRole('list', { name: 'Subject of the alert' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'What is not established' })).toBeInTheDocument();
    expect(verdictButton(/True positive/)).toBeEnabled();

    await user.keyboard('v');
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'shown');
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    await user.keyboard('V');
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
  });

  it('a blind-audit sample stays hidden: nothing to reveal', async () => {
    const user = userEvent.setup();
    const { container } = await renderPage({ alert: investigationAlert({ hidden_for_blind_audit: true, summary: { escalation_id: ESCALATION_ID } }) });
    expect(container.querySelector('[data-investigation]')).toHaveAttribute('data-investigation', 'hidden');
    expect(screen.getByRole('note')).toHaveTextContent('withheld for everyone until an analyst labels it on the Blind audit page');
    expect(screen.getByRole('button', { name: /^Show the verdict/ })).toBeDisabled();
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
    await section('Proposed response').findAllByRole('checkbox');
    expect(effect()).toHaveTextContent('Choose a verdict to see what it sets in motion.');
    expect(dock().getByText('analyst@acme.test')).toBeInTheDocument();

    await user.keyboard('b');
    expect(verdictButton(/Benign, expected here/)).toHaveAttribute('aria-pressed', 'true');
    expect(effect()).toHaveTextContent('Closes it as real activity that is expected for this customer.');
    await user.keyboard('f');
    expect(verdictButton(/False positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(verdictButton(/Benign, expected here/)).toHaveAttribute('aria-pressed', 'false');
    expect(effect()).toHaveTextContent('Closes it as not malicious and feeds the verdict back to triage.');
    await user.keyboard('n');
    expect(effect()).toHaveTextContent('Needs more information is not offered here yet');
    expect(verdictButton(/Needs more/)).toHaveAttribute('aria-disabled', 'true');
    expect(verdictButton(/False positive/)).toHaveAttribute('aria-pressed', 'true');
    await user.keyboard('T');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(effect()).toHaveTextContent('Marks it malicious, runs no action now and sends 3 others to Approvals. A note is required.');

    // Ticking an action changes what the verdict sets in motion; a key pressed on the checkbox is still a shortcut.
    await user.click(screen.getByRole('checkbox', { name: /^Run on true positive ?: Kill process/ }));
    expect(effect()).toHaveTextContent('Marks it malicious, runs 1 action now (1 ticked) and sends 2 others to Approvals. A note is required.');
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
    await user.keyboard('fbv Checked the process tree');
    expect(note).toHaveValue('fbv Checked the process tree');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /^Hide the verdict/ })).toBeInTheDocument();
    expect(dock().queryByText('A true positive needs a note: what did you check?')).not.toBeInTheDocument();

    await user.keyboard('{Control>}{Enter}{/Control}');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/alerts/next-alert'));
    expect(decisionBody(calls)).toEqual({
      decision: 'true_positive',
      version: 3,
      notes: 'fbv Checked the process tree',
      approved_actions: ['kill_process:powershell.exe PID 7340'],
      feedback: null,
      suggest_suppression: null,
    });
    expect(await screen.findByText('Decision recorded; 1 alert(s) resumed.')).toBeInTheDocument();
    // The next alert opens on a fresh page.
    expect(await screen.findByRole('heading', { level: 1, name: 'The next alert' })).toBeInTheDocument();
  });

  it('records with the buttons too; a false positive needs no note, pre-approves nothing, and stays when nothing else waits', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage();
    await user.click(await screen.findByRole('checkbox', { name: /^Run on true positive ?: Block domain/ }));
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(effect()).toHaveTextContent('Choose a verdict first: T, B or F.');
    await user.click(verdictButton(/False positive/));
    await user.click(dock().getByRole('button', { name: /^Record and open next/ }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
    expect(decisionBody(calls)).toEqual({ decision: 'false_positive', version: 3, notes: null, approved_actions: [], feedback: null, suggest_suppression: false });
    expect(screen.getByTestId('location')).toHaveTextContent(`/alerts/${ALERT_ID}`);
    // The page reloads the escalation: the decision is now on record.
    expect(await section('Decision').findByText('False positive')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).not.toBeInTheDocument();
  });

  it('single-key shortcuts can be switched off for the tab, without browser storage; Ctrl+Enter still works', async () => {
    const user = userEvent.setup();
    const { unmount } = await renderPage();
    const toggle = dock().getByRole('button', { name: 'Single-key shortcuts: on' });
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await user.click(toggle);
    expect(dock().getByRole('button', { name: 'Single-key shortcuts: off' })).toHaveAttribute('aria-pressed', 'false');
    await user.keyboard('tv1');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /^Hide the verdict/ })).toBeInTheDocument();
    expect(claimButton(1)).toHaveAttribute('aria-pressed', 'false');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(effect()).toHaveTextContent('Choose a verdict first: T, B or F.');
    expect(window.localStorage).toHaveLength(0);
    unmount();
    // The next alert opened in the tab keeps the switch.
    await renderPage();
    await user.click(dock().getByRole('button', { name: 'Single-key shortcuts: off' }));
    expect(dock().getByRole('button', { name: 'Single-key shortcuts: on' })).toBeInTheDocument();
    await user.keyboard('t');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
  });

  it('an unclaimed escalation is claimed first: "Claim to decide"', async () => {
    const user = userEvent.setup();
    const { calls } = await renderPage({ esc: investigationEscalation({ status: 'open', assigned_to: null, assigned_to_email: null, claimed_at: null }) });
    expect(screen.queryByText('Owner')?.parentElement).toHaveTextContent('OwnerUnassigned');
    expect(await screen.findByRole('checkbox', { name: /^Run on true positive ?: Kill process/ })).toBeDisabled();
    await user.keyboard('t');
    expect(verdictButton(/True positive/)).toHaveAttribute('aria-pressed', 'true');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(effect()).toHaveTextContent('Claim first: a decision is recorded under the name of the analyst who holds the escalation.');
    expect(dock().queryByRole('button', { name: /^Record and open next/ })).not.toBeInTheDocument();
    await user.click(dock().getByRole('button', { name: 'Claim to decide' }));
    expect(await screen.findByText('Escalation claimed.')).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith('/claim'))?.body).toEqual({ version: 3 });
    expect(await dock().findByRole('button', { name: /^Record and open next/ })).toBeEnabled();
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /^Run on true positive ?: Kill process/ })).toBeEnabled());
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
    for (const name of [/True positive/, /Benign, expected here/, /False positive/]) expect(verdictButton(name)).toBeDisabled();
    expect(dock().getByLabelText('What did you check')).toBeDisabled();
    expect(dock().getByRole('button', { name: /^Record and open next/ })).toBeDisabled();
    expect(await screen.findByRole('checkbox', { name: /^Run on true positive ?: Kill process/ })).toBeDisabled();
    await user.keyboard('tn');
    await user.click(verdictButton(/Needs more/));
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
  it('pre-approves only what the preview allows, and never an action without a target', () => {
    const ok = plannedAction('block_ip', '203.0.113.50');
    const noTarget = plannedAction('block_ip', ' ');
    const admin = plannedAction('isolate_host', 'WS-1', { role_lock: 'admin', can_preapprove: false });
    const off = plannedAction('reset_password', 'u', { role_lock: 'disabled', can_preapprove: false });
    const blocked = plannedAction('block_domain', 'x.example', { without_preapproval: 'blocked', can_preapprove: false });
    const automatic = plannedAction('create_ticket', 'SOC', { without_preapproval: 'automatic', can_preapprove: false });
    const waits = plannedAction('disable_user', 'u', { can_preapprove: false });
    expect(preapproval(ok)).toEqual({ allowed: true, instead: null });
    expect(preapproval(noTarget)).toEqual({ allowed: false, instead: 'No target sent: approve it on the Approvals page' });
    expect(preapproval(admin).instead).toBe('Needs an admin');
    expect(preapproval(off).instead).toBe('Not available');
    expect(preapproval(blocked).instead).toBe('Not available');
    expect(preapproval(automatic).instead).toBe('Runs automatically');
    expect(preapproval(waits).instead).toBe('Waits on the Approvals page');
    const all = [ok, noTarget, admin, automatic];
    expect(preapprovedEntries(all, new Set(all.map((a) => a.approval_entry)))).toEqual(['block_ip:203.0.113.50']);
  });

  it('says what a verdict sets in motion from the plan', () => {
    const plan = [plannedAction('block_ip', '203.0.113.50'), plannedAction('create_ticket', 'SOC', { without_preapproval: 'automatic', can_preapprove: false })];
    expect(effectOf('true_positive', [], new Set())).toBe('Marks it malicious and plans the response. A note is required.');
    expect(effectOf('true_positive', plan, new Set(['block_ip:203.0.113.50']))).toBe('Marks it malicious, runs 2 actions now (1 ticked). A note is required.');
    expect(effectOf('true_positive', plan, new Set())).toBe('Marks it malicious, runs 1 action now (0 ticked) and sends 1 other to Approvals. A note is required.');
    expect(effectOf(null, plan, new Set())).toBe('Choose a verdict to see what it sets in motion.');
  });

  it('counts the claims that are backed, rejected and bare', () => {
    const c = (check: string) => ({ id: check, text: check, direction: null, observation_ids: [], check });
    expect(checkLine([])).toBeUndefined();
    expect(checkLine([c('supported')])).toBe('1 of the 1 claim is backed by what the tools returned.');
    expect(checkLine([c('supported'), c('supported'), c('rejected'), c('unsupported')])).toBe('2 of the 4 claims are backed by what the tools returned; 1 was rejected; 1 cites no fact.');
    expect(checkLine([c('rejected'), c('rejected'), c('unsupported'), c('unsupported')])).toBe('0 of the 4 claims are backed by what the tools returned; 2 were rejected; 2 cite no fact.');
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
