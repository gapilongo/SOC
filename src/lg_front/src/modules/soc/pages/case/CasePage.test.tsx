import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import type { CaseAlertOut, CaseOut, DecisionIn, EscalationOut } from '../../api/types';
import { DECIDED_CASE, OPEN_CASE } from '../../../../test/caseReadModels';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { investigationEscalation } from '../../../../test/investigation';
import CasePage, { personLabel, statement } from './CasePage';

const CASE_ID = OPEN_CASE.id;
const OWNER = OPEN_CASE.owner?.user_id as string;
const TITLE = 'Encoded PowerShell launched by Microsoft Word';
const LINKED_TITLE = 'Outlook opened a Word attachment from the internet zone';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown) => unknown;

interface Setup {
  model?: CaseOut | null;
  esc?: EscalationOut;
  role?: string;
  id?: string;
  next?: EscalationOut[];
  handler?: Handler;
}

const escalation = (overrides: Partial<EscalationOut> = {}): EscalationOut =>
  investigationEscalation({ id: CASE_ID, alert_id: OPEN_CASE.alert_id, assigned_to: OWNER, assigned_to_email: OPEN_CASE.owner?.email, ...overrides });

async function renderPage({ model = OPEN_CASE, esc = escalation(), role = 'analyst', id = OWNER, next = [], handler }: Setup = {}) {
  let current = esc;
  const { api, calls } = fakeApi((method, path, body) => {
    const answer = handler?.(method, path, body);
    if (answer !== undefined) return answer;
    if (method === 'GET' && path === `/cases/${CASE_ID}`) {
      if (model) return model;
      throw apiError(404, 'not_found', 'Not Found');
    }
    if (method === 'GET' && path === `/escalations/${CASE_ID}`) return current;
    if (method === 'POST' && path === `/escalations/${CASE_ID}/claim`) {
      current = { ...current, status: 'claimed', assigned_to: id, version: current.version + 1 };
      return current;
    }
    if (method === 'POST' && path === `/escalations/${CASE_ID}/decision`) {
      current = { ...current, status: 'decided', decision: (body as DecisionIn).decision, decision_notes: (body as DecisionIn).notes, decided_by: id };
      return { escalation: current, approved_actions: [], resumed_alert_ids: [OPEN_CASE.alert_id], own_review_alert_ids: [], resumes_enqueued: 1, resumes_failed: 0 };
    }
    if (method === 'POST' && /^\/actions\/[^/]+\/(approve|reject)$/.test(path)) return { action: {}, resumed_alert_ids: [], resumes_enqueued: 1, resumes_failed: 0 };
    if (method === 'GET' && path === '/escalations') return { items: next, next_cursor: null };
    if (method === 'GET' && path === '/auth/me') return { kind: 'user', tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'password', tenant_name: 'Northwind Logistics' };
    throw apiError(404, 'not_found', 'Not found');
  });
  const session = await signedInSession(api, { role, id });
  const view = renderWithSession(
    <>
      <Routes>
        <Route path="/cases/:key" element={<CasePage />} />
        <Route path="/queue" element={<p>the queue</p>} />
        <Route path="/alerts/:id" element={<p>investigation view</p>} />
      </Routes>
      <LocationProbe />
    </>,
    session,
    { route: `/cases/${CASE_ID}` },
  );
  await screen.findByRole('heading', { level: 1 });
  return { ...view, calls };
}

const section = (name: string | RegExp) => within(screen.getByRole('region', { name }));
const row = (container: HTMLElement, id: string) => container.querySelector(`tr[data-alert="${id}"]`) as HTMLElement;
const dock = () => within(screen.getByRole('region', { name: 'Your decision' }));
/** The decision bar, once the escalation it records against is read. */
const dockReady = async () => within(await screen.findByRole('region', { name: 'Your decision' }));
const posts = (calls: Array<{ method: string; path: string; body?: unknown }>) => calls.filter((c) => c.method === 'POST');
const withAlert = (model: CaseOut, id: string, change: Partial<CaseAlertOut>): CaseOut => ({ ...model, alerts: model.alerts.map((a) => (a.id === id ? { ...a, ...change } : a)) });

// The single-key switch is a stored preference: each test starts without one.
beforeEach(() => window.localStorage.clear());

describe('case page: an open case', () => {
  it('opens with the state, the severity, the deadline and the owner, and says how its alerts stand', async () => {
    const { container, calls } = await renderPage();
    expect(screen.getByRole('heading', { level: 1, name: TITLE })).toBeInTheDocument();
    expect(container.querySelector('[data-case]')).toHaveAttribute('data-case', 'claimed');
    const crumb = within(screen.getByRole('navigation', { name: 'Breadcrumb' }));
    expect(crumb.getByRole('link', { name: 'Queue' })).toHaveAttribute('href', '/queue');
    expect(crumb.getByText('esc-2291')).toHaveAttribute('title', CASE_ID);
    expect(await crumb.findByText('Northwind Logistics')).toBeInTheDocument();
    expect(screen.getByText('Needs your decision: likely malicious')).toBeInTheDocument();
    expect(screen.getAllByText('Critical', { selector: '[data-severity="critical"]' })[0].closest('table')).toBeNull();
    expect(screen.getByText('Owner', { selector: 'span' })).toHaveTextContent('Owneryou');
    expect(screen.getByRole('link', { name: 'Review the evidence' })).toHaveAttribute('href', `/alerts/${OPEN_CASE.alert_id}`);
    expect(container.querySelector('[data-statement]')).toHaveTextContent('9 alerts: 3 with a person, 1 being investigated, 5 closed.');
    // The facts: who holds it, since when, why it is with a person, what waits.
    expect(screen.getByText('Why it is with a person').nextElementSibling).toHaveTextContent('No automatic rule applies to this alert, so a person decides.');
    expect(screen.getByRole('link', { name: '3 actions wait for an approval' })).toHaveAttribute('href', '#case-response');
    expect(screen.getByText('Deadline')).toBeInTheDocument();
    // One read gives the page its content; the escalation is read for the decision bar only.
    expect(calls.filter((c) => c.method === 'GET').map((c) => c.path).filter((p) => p !== '/auth/me').sort()).toEqual([`/cases/${CASE_ID}`, `/escalations/${CASE_ID}`]);
  });

  it('lists every alert oldest first with who or what closed it and the recorded reason', async () => {
    const { container } = await renderPage();
    const table = section('Alerts in this case').getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Time', 'Severity', 'Alert', 'State and closed by', 'Why']);
    const rows = [...container.querySelectorAll('tr[data-alert]')];
    expect(rows.map((r) => r.getAttribute('data-alert'))).toEqual(OPEN_CASE.alerts.map((a) => a.id));
    expect(rows.map((r) => r.querySelector('[data-closed-by]')?.getAttribute('data-closed-by'))).toEqual([
      'analyst', 'ai_audit', 'ai_audit', 'needs_decision', 'needs_decision', 'waiting_approval', 'suppression_rule', 'cached_verdict', 'investigating',
    ]);
    // What the AI closed on the model's word: linked, left closed, with the rule of the policy and the tier.
    const linked = row(container, 'alr-48212');
    expect(linked).toHaveAttribute('data-role', 'linked');
    expect(within(linked).getByRole('link', { name: LINKED_TITLE })).toHaveAttribute('href', '/alerts/alr-48212');
    expect(within(linked).getByText('Linked')).toBeInTheDocument();
    expect(linked).toHaveTextContent('The AI judged the alert benign and closed it on the model\'s word.');
    expect(linked).toHaveTextContent('Closure tier when it was decided');
    expect(row(container, 'alr-48190')).toHaveTextContent('Blind audit: labelled benign, agrees with the AI');
    // An analyst, a rule and an earlier verdict each name their reference.
    expect(row(container, 'alr-47702')).toHaveTextContent('by you');
    expect(row(container, 'alr-48226')).toHaveTextContent('rule “Defender definition updates”');
    expect(within(row(container, 'alr-48231')).getByRole('link', { name: 'alr-46011' })).toHaveAttribute('href', '/alerts/alr-46011');
    // The alert the case was opened for says so, and open alerts are marked as open.
    expect(row(container, OPEN_CASE.alert_id)).toHaveTextContent('The case was opened for this alert.');
    expect(row(container, OPEN_CASE.alert_id)).toHaveAttribute('data-state', 'open');
    expect(row(container, 'alr-48247')).toHaveTextContent('No decision yet: the investigation is still running.');
  });

  it('says once why the AI-closed alerts were linked, and lists them as left closed', async () => {
    const { container } = await renderPage();
    const notice = screen.getByText('2 alerts closed by the AI are linked here and stay closed');
    expect(notice.parentElement).toHaveTextContent('A model\'s judgement is not a confirmation');
    const net = section('Linked by the safety net');
    expect(net.getByRole('heading', { name: '2 alerts are linked and left closed' })).toBeInTheDocument();
    expect([...container.querySelectorAll('[data-linked-alert]')].map((li) => li.getAttribute('data-linked-alert'))).toEqual(['alr-48190', 'alr-48212']);
    expect(container.querySelector('[data-linked-alert="alr-48212"]')).toHaveTextContent(/stays closed$/);
    expect(container.querySelector('[data-reopened]')).toBeNull();
  });

  it('shows the response with each status and guardrail result, for the alert it belongs to', async () => {
    const { container } = await renderPage();
    const response = section('Response');
    const statuses = [...container.querySelectorAll('#case-response [data-status]')].map((s) => s.getAttribute('data-status'));
    expect(statuses).toEqual(['awaiting_approval', 'awaiting_approval', 'awaiting_approval', 'blocked', 'dry_run', 'succeeded', 'failed']);
    const blocked = container.querySelector('#case-response tr[data-action="00000000-0000-0000-0000-000048213004"]') as HTMLElement;
    expect(blocked).toHaveTextContent("The tenant's autonomy policy disables actions of this risk.");
    expect(blocked).toHaveTextContent('Blocked');
    expect(response.getAllByRole('link', { name: 'Periodic HTTPS beacon to a newly registered domain' })).toHaveLength(2);
    expect(response.getByText('Dry run: recorded, nothing changed')).toBeInTheDocument();
    expect(response.getByRole('link', { name: 'Approvals' })).toHaveAttribute('href', '/approvals');
  });

  it('an analyst approves what the role may approve, through the dialog of the Approvals page; high risk is locked with the reason', async () => {
    const { calls } = await renderPage();
    const response = section('Response');
    // Low and medium risk: approve and reject. High risk: reject only, and why.
    expect(response.getAllByRole('button', { name: /^Approve ?: / })).toHaveLength(2);
    expect(response.getAllByRole('button', { name: /^Reject ?: / })).toHaveLength(3);
    expect(response.getByText('High risk needs an admin to approve.')).toBeInTheDocument();
    expect(response.queryByRole('button', { name: /Reset password/ })).toBeNull();
    await userEvent.click(response.getByRole('button', { name: /^Approve ?: Block ip on 203\.0\.113\.50$/ }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('203.0.113.50');
    const before = calls.filter((c) => c.path === `/cases/${CASE_ID}`).length;
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve action' }));
    await waitFor(() => expect(posts(calls)).toEqual([expect.objectContaining({ path: '/actions/00000000-0000-0000-0000-000048213003/approve', body: { reject_remaining: false } })]));
    // The approval may fold a linked alert into the case: the case is read again.
    await waitFor(() => expect(calls.filter((c) => c.path === `/cases/${CASE_ID}`).length).toBeGreaterThan(before));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('rejects through the same dialog, and a viewer gets no button at all', async () => {
    const first = await renderPage();
    await userEvent.click(section('Response').getByRole('button', { name: /^Reject ?: Isolate host on WS-FIN-0142$/ }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Reject action' }));
    await waitFor(() => expect(posts(first.calls)[0]).toMatchObject({ path: '/actions/00000000-0000-0000-0000-000048213001/reject' }));
    first.unmount();
    await renderPage({ role: 'viewer', id: 'u-viewer' });
    const response = section('Response');
    expect(response.queryByRole('button')).toBeNull();
    expect(response.getAllByText('Requires the analyst role.').length).toBeGreaterThan(0);
  });

  it('merges the case and its alerts into one timeline, each line with its alert and the person', async () => {
    const { container } = await renderPage();
    const timeline = section('Timeline');
    const lines = [...container.querySelectorAll('li[data-actor]')];
    expect(lines).toHaveLength(OPEN_CASE.timeline.length);
    expect(timeline.getByText('The case was opened for a person\'s decision.')).toBeInTheDocument();
    expect(timeline.getByText('An analyst claimed the case.').parentElement).toHaveTextContent('by you');
    const linked = timeline.getAllByText('The safety net linked this alert to the case. It stays closed.');
    expect(linked).toHaveLength(2);
    expect(within(linked[1].parentElement as HTMLElement).getByRole('link', { name: LINKED_TITLE })).toHaveAttribute('href', '/alerts/alr-48212');
    // No engine node name, and none of the workflow's inner steps.
    expect(screen.getByRole('region', { name: 'Timeline' })).not.toHaveTextContent(/node\.completed|plan_response|First assessment|Deeper analysis/);
    expect(screen.queryByText(/Older entries are left out/)).toBeNull();
  });

  it('says what the case touches, most shared first, and what was closed without a person', async () => {
    const { container } = await renderPage();
    const touches = section('What the case touches');
    const entities = within(touches.getByRole('list', { name: 'Entities of the case' })).getAllByRole('listitem');
    expect(entities[0]).toHaveTextContent('HostWS-FIN-0142: alerts whose title names it8 of the 9 alerts');
    expect(touches.getByRole('link', { name: /^m\.keller/ })).toHaveAttribute('href', '/alerts?view=all&q=m.keller');
    const counts = [...container.querySelectorAll('[data-closed-count]')].map((r) => [r.getAttribute('data-closed-count'), r.querySelector('td')?.textContent]);
    expect(counts).toEqual([
      ['ai_audit', '2'],
      ['suppression_rule', '1'],
      ['cached_verdict', '1'],
    ]);
  });

  it('says what is not yet available in the read model’s own words, and nothing else', async () => {
    const { container } = await renderPage();
    const pending = container.querySelector('[data-not-available]') as HTMLElement;
    expect(pending).toHaveTextContent(`Not yet available on this page (${OPEN_CASE.not_available.length})`);
    expect(within(pending).getAllByRole('listitem').map((li) => li.textContent)).toEqual(OPEN_CASE.not_available.map((n) => n.reason));
    // No control whose backend does not exist: nothing reopens or flags an alert here.
    expect(screen.queryByRole('button', { name: /reopen|flag/i })).toBeNull();
  });
});

describe('case page: the decision', () => {
  it('records the decision with the bar of the investigation view and opens the next case', async () => {
    const { calls } = await renderPage({ next: [escalation({ id: 'esc-next', alert_id: 'alert-next' })] });
    await dockReady();
    await userEvent.keyboard('t');
    expect(dock().getByRole('button', { name: /True positive/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('decision-effect')).toHaveTextContent('Marks it malicious and plans the response. A note is required.');
    await userEvent.type(dock().getByLabelText('What did you check'), 'Dump confirmed in the process tree.');
    await userEvent.click(dock().getByRole('button', { name: /Record and open next/ }));
    await waitFor(() =>
      expect(posts(calls)[0]).toMatchObject({
        path: `/escalations/${CASE_ID}/decision`,
        body: { decision: 'true_positive', version: 3, notes: 'Dump confirmed in the process tree.', approved_actions: [] },
      }),
    );
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/cases/esc-next'));
  });

  it('says when no other case waits, and when the next one cannot be looked up', async () => {
    const none = await renderPage();
    await dockReady();
    await userEvent.click(dock().getByRole('button', { name: /False positive/ }));
    await userEvent.click(dock().getByRole('button', { name: /Record and open next/ }));
    expect(await screen.findByText('No other escalation is waiting for you.')).toBeInTheDocument();
    none.unmount();
    await renderPage({
      handler: (m, path) => {
        if (m === 'GET' && path === '/escalations') throw apiError(503, 'unavailable', 'The service is not ready.');
        return undefined;
      },
    });
    await dockReady();
    await userEvent.click(dock().getByRole('button', { name: /False positive/ }));
    await userEvent.click(dock().getByRole('button', { name: /Record and open next/ }));
    expect(await screen.findByText(/Could not open the next escalation/)).toBeInTheDocument();
  });

  it('an unclaimed case is claimed first, and a viewer reads without deciding', async () => {
    const unclaimed = await renderPage({ model: { ...OPEN_CASE, status: 'open', owner: null }, esc: escalation({ status: 'open', assigned_to: null, assigned_to_email: null }) });
    expect(screen.getByText('Unassigned')).toBeInTheDocument();
    await userEvent.click((await dockReady()).getByRole('button', { name: 'Claim to decide' }));
    await waitFor(() => expect(posts(unclaimed.calls)[0]).toMatchObject({ path: `/escalations/${CASE_ID}/claim`, body: { version: 3 } }));
    unclaimed.unmount();
    await renderPage({ role: 'viewer', id: 'u-viewer' });
    expect((await dockReady()).getByRole('button', { name: /True positive/ })).toBeDisabled();
    expect(screen.getByTestId('decision-effect')).toHaveTextContent('Requires the analyst role.');
    expect(screen.getByText('Owner', { selector: 'span' })).toHaveTextContent('Ownerines.moreau@brightwater.example');
  });

  it('J and K move through the alerts and Enter opens one; the single-key switch turns them off', async () => {
    await renderPage();
    const links = OPEN_CASE.alerts.map((a) => section('Alerts in this case').getByRole('link', { name: a.title }));
    fireEvent.keyDown(document, { key: 'j' });
    expect(links[0]).toHaveFocus();
    fireEvent.keyDown(document, { key: 'J' });
    expect(links[1]).toHaveFocus();
    fireEvent.keyDown(document, { key: 'k' });
    fireEvent.keyDown(document, { key: 'k' });
    expect(links[0]).toHaveFocus();
    links[0].blur();
    fireEvent.keyDown(document, { key: 'k' });
    expect(links[links.length - 1]).toHaveFocus();
    fireEvent.keyDown(document, { key: 'j' });
    expect(links[links.length - 1]).toHaveFocus();
    // Not with a modifier, and not while typing the note.
    fireEvent.keyDown(document, { key: 'k', ctrlKey: true });
    expect(links[links.length - 1]).toHaveFocus();
    const note = (await dockReady()).getByLabelText('What did you check');
    note.focus();
    fireEvent.keyDown(note, { key: 'j' });
    expect(note).toHaveFocus();
    // The switch in the bar is the console's one preference: off, J no longer moves.
    await userEvent.click(dock().getByRole('button', { name: 'Single-key shortcuts: on' }));
    note.blur();
    fireEvent.keyDown(document, { key: 'j' });
    expect(links.some((l) => l === document.activeElement)).toBe(false);
    // Enter on the focused alert is the link itself.
    await userEvent.click(links[2]);
    expect(await screen.findByText('investigation view')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/alerts/alr-48212');
  });
});

describe('case page: a decided case', () => {
  it('shows the decision on record, what the confirmation reopened, and no decision bar', async () => {
    const { container, calls } = await renderPage({ model: DECIDED_CASE });
    expect(container.querySelector('[data-case]')).toHaveAttribute('data-case', 'decided');
    expect(screen.getByText('Decided: true positive')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Your decision' })).toBeNull();
    expect(screen.getByText('Why it was with a person')).toBeInTheDocument();
    expect(screen.queryByText('Deadline')).toBeNull();
    // The escalation is not read: the read model has all a decided case shows.
    expect(calls.some((c) => c.path === `/escalations/${CASE_ID}`)).toBe(false);
    const decision = section('Decision');
    expect(decision.getByText('True positive')).toBeInTheDocument();
    expect(decision.getByText('by you')).toBeInTheDocument();
    expect(decision.getByText('The dump is visible in the process tree. Isolating the host.')).toBeInTheDocument();
    // The linked alerts were reopened by the person's confirmation: a new run reviews each.
    const reopened = [...container.querySelectorAll('[data-reopened-alert]')];
    expect(reopened.map((li) => li.getAttribute('data-reopened-alert'))).toEqual(['alr-48190', 'alr-48212']);
    expect(reopened[0]).toHaveTextContent('confirmed by you');
    expect(reopened[0]).toHaveTextContent(/^Reopened.*A person confirmed a related threat.*A new run reviews it on its own\.$/);
    expect(container.querySelector('[data-linked]')).toBeNull();
    expect(screen.queryByText(/linked here and stay/)).toBeNull();
    // The alert the case was opened for was closed by the analyst, with the note.
    expect(row(container, DECIDED_CASE.alert_id).querySelector('q')).toHaveTextContent('The dump is visible in the process tree.');
  });

  it('a case that ended without a decision says so, and names a deciding colleague by e-mail', async () => {
    const first = await renderPage({ model: { ...DECIDED_CASE, status: 'cancelled', decision: null } });
    expect(section('Decision').getByText('This case is cancelled: no decision is recorded on it.')).toBeInTheDocument();
    expect(screen.getByText('Cancelled', { selector: 'span' })).toBeInTheDocument();
    first.unmount();
    await renderPage({ model: DECIDED_CASE, id: 'u-colleague' });
    expect(section('Decision').getByText('by ines.moreau@brightwater.example')).toBeInTheDocument();
  });
});

describe('case page: edges', () => {
  it('an alert that waits for its blind-audit label shows nothing of the AI’s side', async () => {
    const hidden = withAlert(OPEN_CASE, 'alr-48212', {
      role: 'withheld',
      hidden_for_blind_audit: true,
      closed_by: null,
      category: null,
      disposition: null,
      link: null,
      blind_audit: { state: 'pending', label: null, agrees: null, labelled_at: null },
    });
    const { container } = await renderPage({ model: { ...hidden, counts: { ...hidden.counts, linked: 1, withheld: 1, closed_by: { ...hidden.counts.closed_by, ai_audit: 1 } } } });
    const withheld = row(container, 'alr-48212');
    expect(withheld).toHaveTextContent('Withheld for the blind audit');
    expect(withheld).toHaveTextContent('This alert waits for its blind-audit label.');
    expect(withheld).not.toHaveTextContent(/Linked|model's word|Closure tier/);
    expect(container.querySelectorAll('[data-linked-alert]')).toHaveLength(1);
    expect(screen.getByText('1 alert closed by the AI is linked here and stays closed')).toBeInTheDocument();
    expect(section('What the case touches').getByText('1 alert waits for a blind-audit label and is not counted here.')).toBeInTheDocument();
  });

  it('a case of one alert with nothing recorded says so in each section', async () => {
    const threat = OPEN_CASE.alerts.find((a) => a.id === OPEN_CASE.alert_id) as CaseAlertOut;
    const alone: CaseOut = {
      ...OPEN_CASE,
      category: null,
      reason: null,
      sla_deadline: null,
      alerts: [{ ...threat, entities: [] }],
      actions: [],
      entities: [],
      timeline: OPEN_CASE.timeline.slice(-2),
      timeline_truncated: true,
      alerts_truncated: true,
      not_available: [],
      counts: { ...OPEN_CASE.counts, alerts: 240, open: 1, processing: 0, closed: 0, linked: 0, actions_awaiting_approval: 0, closed_by: { ai_evidence: 0, ai_audit: 0, suppression_rule: 0, cached_verdict: 0, analyst: 0 } },
    };
    const { container } = await renderPage({ model: alone });
    expect(screen.getByText('Open', { selector: 'span' })).toBeInTheDocument();
    expect(screen.queryByText('Why it is with a person')).toBeNull();
    expect(screen.getByText('No action is recorded')).toBeInTheDocument();
    expect(section('Alerts in this case').getByText(/The case has 240: the newest 0 that joined are listed/)).toBeInTheDocument();
    expect(row(container, threat.id)).not.toHaveTextContent('The case was opened for this alert.');
    expect(screen.queryByRole('region', { name: 'Linked by the safety net' })).toBeNull();
    expect(section('Response').getByText('No response action is recorded for the alerts of this case.')).toBeInTheDocument();
    expect(section('Timeline').getByText('Older entries are left out: the newest 2 are shown.')).toBeInTheDocument();
    expect(section('What the case touches').getByText('The alerts of this case name no host, user or other entity.')).toBeInTheDocument();
    expect(section('What the case touches').getByText('No alert of this case was closed without a person.')).toBeInTheDocument();
    expect(container.querySelector('[data-not-available]')).toBeNull();
  });

  it('actions that all ran: the fact links to them and says none waits; a link to another threat names it', async () => {
    const done: CaseOut = {
      ...withAlert(OPEN_CASE, 'alr-48212', { link: { ...(OPEN_CASE.alerts[2].link as NonNullable<CaseAlertOut['link']>), threat_alert_id: 'alr-40000', at: null } }),
      actions: OPEN_CASE.actions.slice(5),
      counts: { ...OPEN_CASE.counts, actions_awaiting_approval: 0 },
    };
    const { container } = await renderPage({ model: done });
    expect(screen.getByRole('link', { name: '2 actions, none waits' })).toHaveAttribute('href', '#case-response');
    const other = container.querySelector('[data-linked-alert="alr-48212"]') as HTMLElement;
    expect(within(other).getByRole('link', { name: 'alr-40000' })).toHaveAttribute('href', '/alerts/alr-40000');
    expect(other).toHaveTextContent(/linked to the threat/);
  });

  it('says when the case does not exist, and offers a retry when it cannot be read', async () => {
    const missing = await renderPage({ model: null });
    expect(screen.getByRole('heading', { level: 1, name: 'Case not found' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    expect(screen.getByRole('link', { name: 'Back to the queue' })).toHaveAttribute('href', '/queue');
    missing.unmount();
    let fail = true;
    await renderPage({
      handler: (m, path) => {
        if (m === 'GET' && path === `/cases/${CASE_ID}` && fail) throw apiError(503, 'unavailable', 'The service is not ready.');
        return undefined;
      },
    });
    expect(screen.getByRole('heading', { level: 1, name: 'Case' })).toBeInTheDocument();
    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('heading', { level: 1, name: TITLE })).toBeInTheDocument();
  });
});

describe('case page: pure parts', () => {
  it('states the counts of a case in one sentence', () => {
    expect(statement({ alerts: 9, open: 3, processing: 1, closed: 5 })).toBe('9 alerts: 3 with a person, 1 being investigated, 5 closed.');
    expect(statement({ alerts: 1, open: 1, processing: 0, closed: 0 })).toBe('1 alert: 1 with a person.');
    expect(statement({ alerts: 2, open: 0, processing: 0, closed: 0 })).toBe('2 alerts.');
  });

  it('names a person as "you", by e-mail, else by a short id', () => {
    expect(personLabel(null, 'u-1')).toBeNull();
    expect(personLabel({ user_id: 'u-1', email: 'a@acme.test' }, 'u-1')).toBe('you');
    expect(personLabel({ user_id: 'u-2', email: 'b@acme.test' }, 'u-1')).toBe('b@acme.test');
    expect(personLabel({ user_id: '5b0c7a52-6f0e-4c58-9d0e', email: null }, null)).toBe('5b0c7a52...');
  });
});
