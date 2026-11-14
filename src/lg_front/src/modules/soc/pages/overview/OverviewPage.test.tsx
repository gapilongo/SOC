import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { BlindAuditEstimate, BlindAuditReportOut, DashboardOut, EscalationOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { auditFigure, claimMean, closeMean, dayRange, handledSplit, handledStatement, windowPhrase } from './figures';
import { HandledBar } from './HandledBar';
import { workQueueHref } from './links';
import OverviewPage from './OverviewPage';
import { Verification } from './Verification';

const minutesFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

function summary(overrides: Partial<DashboardOut> = {}): DashboardOut {
  return {
    window_hours: 24,
    since: '2026-11-05T12:00:00Z',
    generated_at: new Date().toISOString(),
    alerts_total: 1284,
    by_status: { waiting_human: 24, waiting_approval: 4, closed: 1252, failed: 1, odd_state: 3 },
    by_severity: { high: 34, medium: 36, low: 35 },
    by_disposition: { benign: 1 },
    mtta_s: 840,
    mttr_s: 600,
    acknowledged: 125,
    resolved: 1252,
    open_escalations: 28,
    runs_by_status: { queued: 2 },
    queue_depth: 2,
    llm_cost_usd: 1.5,
    llm_tokens: 42000,
    llm_model: 'deep-model-test',
    handled_without_human: 1131,
    needed_human: 153,
    handled_without_human_rate: 1131 / 1284,
    analyst_hours_saved: 282.75,
    minutes_per_alert: 15,
    unassigned_escalations: 22,
    unassigned_breaching: 2,
    overdue_escalations: 3,
    next_sla_deadline: minutesFromNow(250),
    open_escalations_by_severity: { high: 40, medium: 63 },
    pending_approvals_total: 13,
    pending_approvals_by_risk: { medium: 6, high: 4, low: 3 },
    pending_approvals: 9,
    my_claimed: 3,
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

const OVERDUE = escalation('e-1', {
  summary: { title: 'Unusual sign-in pattern' },
  alert_severity: 'high',
  sla_deadline: minutesFromNow(-134),
  entities_preview: { items: [{ kind: 'user', value: 'j.moreau@acme.example' }], counts: { user: 1 } },
  routing: null,
  ai_reason_source: null,
});
const MINE = escalation('e-2', { rule: 'Phishing link clicked', sla_deadline: minutesFromNow(30), assigned_to: 'u-1', status: 'claimed' });
const THEIRS = escalation('e-3', { summary: { title: 'Impossible travel', severity: 'medium' }, sla_deadline: minutesFromNow(700), assigned_to: 'u-9', assigned_to_email: 'n.haddad@acme.example' });

function estimate(overrides: Partial<BlindAuditEstimate> = {}): BlindAuditEstimate {
  return {
    status: 'ok',
    complete: true,
    summary: '0.6% (stratified over 4 run(s); n=180; 95% CI 0.0% to 3.1%)',
    method: 'stratified',
    frame_size: 9870,
    estimated_frame: 9870,
    effective_n: 180,
    sampled: 180,
    labelled: 180,
    pending: 0,
    malicious: 1,
    benign: 179,
    unsure: 0,
    min_samples: 30,
    false_negative_rate: { rate: 0.0056, n: 180, ci_low: 0.0001, ci_high: 0.031 },
    agreement_rate: { rate: 0.994, n: 180, ci_low: 0.969, ci_high: 0.999 },
    estimated_missed: 55,
    estimated_missed_low: 1,
    estimated_missed_high: 306,
    worst_case_rate: 0.0056,
    worst_case_rate_high: 0.031,
    worst_case_missed: 55,
    worst_case_missed_high: 306,
    ...overrides,
  };
}

function auditReport(overrides: Partial<BlindAuditEstimate> = {}): BlindAuditReportOut {
  return { from: '2026-10-16', to: '2026-11-14', generated_at: '2026-11-14T10:04:00Z', estimate: estimate(overrides), strata: [], runs: [], uncovered: [], labels_by_organisation: [], notes: [] };
}

interface World {
  dash?: () => DashboardOut;
  audit?: () => BlindAuditReportOut;
  /** The blind queue's first page. */
  pending?: () => { items: Array<{ id: string }>; next_cursor: string | null };
  escalations?: (query: Record<string, unknown>) => EscalationOut[];
}

/** The API of the Overview: the dashboard, the three escalation lists, the blind queue and the blind-audit report. */
function world({ dash = () => summary(), audit = () => auditReport(), pending = () => ({ items: [{ id: 'b-1' }, { id: 'b-2' }], next_cursor: null }), escalations }: World = {}) {
  const fake = fakeApi((method, path) => {
    const query = (fake.calls.at(-1)?.query ?? {}) as Record<string, unknown>;
    if (method === 'GET' && path === '/dashboard/summary') return { ...dash(), window_hours: Number(query.window_hours) };
    if (method === 'GET' && path === '/escalations') {
      if (escalations) return { items: escalations(query), next_cursor: null };
      if (query.assigned_to === 'me') return { items: [MINE], next_cursor: null };
      if (query.assigned_to === 'none') return { items: [OVERDUE], next_cursor: null };
      return { items: [OVERDUE, MINE, THEIRS], next_cursor: null };
    }
    if (method === 'GET' && path === '/blind-audit/items') return pending();
    if (method === 'GET' && path === '/reports/blind-audit') return audit();
    if (method === 'GET' && path === '/onboarding/status') return { dismissed: true, complete: false, steps: [] };
    throw new Error(`unexpected ${method} ${path}`);
  });
  return fake;
}

async function open(w: ReturnType<typeof world>, role: 'viewer' | 'analyst' | 'admin') {
  const session = await signedInSession(w.api, { role });
  renderWithSession(<OverviewPage />, session);
  expect(await screen.findByRole('heading', { name: 'Overview', level: 1 })).toBeInTheDocument();
}

const row = (region: HTMLElement, title: RegExp) => within(region).getByText(title).closest('li') as HTMLElement;

describe('OverviewPage: needs you now', () => {
  it("puts the analyst's own work first, each line with its count, what it counts and one action", async () => {
    const w = world();
    await open(w, 'analyst');
    const now = await screen.findByRole('region', { name: 'Needs you now' });

    const mine = row(now, /items you own are waiting/);
    expect(mine).toHaveTextContent(/^3items you own are waiting/);
    expect(await within(mine).findByText(/The first deadline is in 30 minutes/)).toHaveTextContent('The first deadline is in 30 minutes: Phishing link clicked.');
    // The item opens its investigation view; the action opens the caller's queue.
    expect(within(mine).getByRole('link', { name: 'Phishing link clicked' })).toHaveAttribute('href', '/alerts/a-e-2');
    expect(within(mine).getByRole('link', { name: 'Open my queue' })).toHaveAttribute('href', '/queue?view=mine');

    const approvals = row(now, /response actions you can approve/);
    expect(approvals).toHaveTextContent(/^9response actions you can approve/);
    expect(approvals).toHaveTextContent('13 wait for approval; 4 of them need an admin. By risk: 4 high, 6 medium, 3 low.');
    expect(within(approvals).getByRole('link', { name: 'Open approvals' })).toHaveAttribute('href', '/approvals');

    const unclaimed = row(now, /items nobody has claimed/);
    expect(unclaimed).toHaveTextContent(/^22items nobody has claimed/);
    expect(await within(unclaimed).findByText(/Most overdue/)).toHaveTextContent('Most overdue: Unusual sign-in pattern, 2h 14m past its deadline.');
    expect(unclaimed).toHaveTextContent('2 of them are past their deadline.');
    expect(within(unclaimed).getByRole('link', { name: 'Unusual sign-in pattern' })).toHaveAttribute('href', '/alerts/a-e-1');
    expect(within(unclaimed).getByRole('link', { name: 'Open the queue' })).toHaveAttribute('href', '/queue?view=unassigned');

    const audit = row(now, /wait for a blind-audit label/);
    await waitFor(() => expect(audit).toHaveTextContent(/^2sampled AI closes wait for a blind-audit label/));
    expect(audit).toHaveTextContent("You label from the evidence; the AI's verdict stays hidden until you have chosen.");
    expect(within(audit).getByRole('link', { name: 'Label them' })).toHaveAttribute('href', '/blind-audit');

    // One primary action: the first line with something to do.
    expect(within(now).getByRole('link', { name: 'Open my queue' }).className).toContain('bg-accent');
    for (const name of ['Open approvals', 'Open the queue', 'Label them']) expect(within(now).getByRole('link', { name }).className).not.toContain('bg-accent');

    const queries = w.calls.filter((c) => c.path === '/escalations').map((c) => c.query);
    expect(queries).toContainEqual({ status: ['open', 'claimed'], assigned_to: 'me', order: 'sla_deadline', cursor: undefined, limit: 1 });
    expect(queries).toContainEqual({ status: ['open', 'claimed'], assigned_to: 'none', overdue: true, order: 'sla_deadline', cursor: undefined, limit: 1 });
    expect(w.calls.find((c) => c.path === '/blind-audit/items')?.query).toMatchObject({ status: 'pending' });
  });

  it('says so when nothing waits, and makes the first line with work the primary action', async () => {
    const w = world({
      dash: () => summary({ my_claimed: 0, unassigned_escalations: 1, unassigned_breaching: 0, pending_approvals: 0, pending_approvals_total: 0, pending_approvals_by_risk: {} }),
      pending: () => ({ items: [], next_cursor: null }),
    });
    await open(w, 'analyst');
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(row(now, /items you own are waiting/)).toHaveTextContent('0items you own are waitingYou hold nothing. Claim an item from the queue to see it here.');
    expect(row(now, /response actions you can approve/)).toHaveTextContent('Nothing waits for approval.');
    expect(row(now, /item nobody has claimed/)).toHaveTextContent('1item nobody has claimedNone of them is past its deadline.');
    await waitFor(() => expect(row(now, /wait for a blind-audit label/)).toHaveTextContent('No sample waits for a label.'));
    expect(within(now).getByRole('link', { name: 'Open the queue' }).className).toContain('bg-accent');
    expect(within(now).getByRole('link', { name: 'Open my queue' }).className).not.toContain('bg-accent');
    // Nothing is held or overdue: neither short list is asked for.
    expect(w.calls.filter((c) => c.path === '/escalations').every((c) => (c.query as { limit: number }).limit === 5)).toBe(true);
  });

  it('uses the singular, and counts a full first page of the blind queue as "at least"', async () => {
    const w = world({
      dash: () => summary({ my_claimed: 1, unassigned_escalations: 0, unassigned_breaching: 0, pending_approvals: 1, pending_approvals_total: 1, pending_approvals_by_risk: { low: 1, unheard_of: 0 } }),
      pending: () => ({ items: Array.from({ length: 50 }, (_, i) => ({ id: `b-${i}` })), next_cursor: 'next' }),
      escalations: (query) => (query.assigned_to === 'me' ? [escalation('e-9', { summary: { title: 'No deadline set' }, assigned_to: 'u-1' })] : []),
    });
    await open(w, 'admin');
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(await within(now).findByText(/First in your queue/)).toHaveTextContent('First in your queue: No deadline set.');
    expect(row(now, /item you own is waiting/)).toHaveTextContent(/^1item you own is waiting/);
    expect(row(now, /response action you can approve/)).toHaveTextContent('1 waits for approval. By risk: 1 low.');
    expect(row(now, /items nobody has claimed/)).toHaveTextContent('Every item that needs a person has an owner.');
    await waitFor(() => expect(row(now, /wait for a blind-audit label/)).toHaveTextContent(/^50\+sampled AI closes wait/));
  });

  it('tells an analyst how the first deadline stands once it has passed, and one sample from several', async () => {
    const w = world({
      dash: () => summary({ unassigned_breaching: 1, pending_approvals_by_risk: { critical: 1, odd: 2 }, pending_approvals_total: 3, pending_approvals: 2 }),
      pending: () => ({ items: [{ id: 'b-1' }], next_cursor: null }),
      escalations: () => [OVERDUE],
    });
    await open(w, 'analyst');
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(await within(now).findByText(/The first deadline passed/)).toHaveTextContent('The first deadline passed 2 hours ago: Unusual sign-in pattern.');
    expect(row(now, /nobody has claimed/)).toHaveTextContent('1 of them is past its deadline.');
    expect(row(now, /response actions you can approve/)).toHaveTextContent('3 wait for approval; 1 of them needs an admin. By risk: 1 critical, 2 odd.');
    await waitFor(() => expect(row(now, /blind-audit label/)).toHaveTextContent(/^1sampled AI close waits for a blind-audit label/));
  });

  it('gives a viewer the unclaimed items only, and asks for nothing a viewer may not read', async () => {
    const w = world();
    await open(w, 'viewer');
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(within(now).getAllByRole('listitem')).toHaveLength(1);
    expect(within(now).getByRole('link', { name: 'Open the queue' })).toBeInTheDocument();
    expect(within(now).queryByText(/you own/)).not.toBeInTheDocument();
    expect(within(now).queryByText(/you can approve/)).not.toBeInTheDocument();
    expect(within(now).queryByText(/blind-audit label/)).not.toBeInTheDocument();
    expect(w.calls.some((c) => c.path === '/blind-audit/items')).toBe(false);
    expect(w.calls.some((c) => c.path === '/onboarding/status')).toBe(false);
    // A viewer still reads how the closes are verified.
    expect(await screen.findByText(/labelled malicious by an analyst/)).toBeInTheDocument();
  });

  it('shows an admin every pending approval as theirs', async () => {
    await open(world({ dash: () => summary({ pending_approvals: 13 }) }), 'admin');
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    expect(row(now, /response actions you can approve/)).toHaveTextContent('13 wait for approval. By risk: 4 high, 6 medium, 3 low.');
    expect(within(now).queryByText(/need an admin/)).not.toBeInTheDocument();
  });

  it('keeps a failed list inside its own line', async () => {
    const fake = fakeApi((_m, path) => {
      if (path === '/dashboard/summary') return summary();
      if (path === '/reports/blind-audit') return auditReport();
      throw apiError(500, 'internal', 'List failed.');
    });
    const session = await signedInSession(fake.api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);
    const now = await screen.findByRole('region', { name: 'Needs you now' });
    // Mine, the most overdue, the blind queue; and the deadlines table below.
    await waitFor(() => expect(within(now).getAllByText('List failed.')).toHaveLength(3));
    expect(row(now, /wait for a blind-audit label/)).toHaveTextContent(/^–sampled AI closes/);
    expect(within(screen.getByRole('region', { name: 'Next deadlines' })).getByText('List failed.')).toBeInTheDocument();
    expect(within(now).getAllByRole('button', { name: 'Retry' })).toHaveLength(3);
    // The counts of the dashboard still stand.
    expect(row(now, /items you own are waiting/)).toHaveTextContent(/^3items/);
  });
});

describe('HandledBar', () => {
  const phrase = 'the last 24 hours';

  it('says what was closed without a person, draws it, and names what each row counts', () => {
    render(<HandledBar d={summary()} phrase={phrase} isAdmin={false} />);
    const block = screen.getByRole('region', { name: 'Closed without a person' });
    expect(within(block).getByText('1,131 of 1,284 finished alerts were closed without a person. 153 reached one.')).toBeInTheDocument();
    expect(within(block).getByTestId('overview-alerts-received').parentElement).toHaveTextContent('1,284 alerts received in the last 24 hours');
    const bar = within(block).getByRole('img', { name: '1,284 finished alerts: 1,131 closed without a person, 153 reached a person' });
    expect([...bar.children].map((s) => [s.getAttribute('data-segment'), (s as HTMLElement).style.flexGrow])).toEqual([
      ['handled', '1131'],
      ['needed', '153'],
    ]);
    const rows = within(within(block).getByRole('table', { name: 'Closed without a person' })).getAllByRole('row');
    expect(rows[1]).toHaveTextContent(/^Closed without a personAlerts1,131Share88%Checked byNo analyst decided it/);
    // The split of the closes is not in the API: said, not worked out.
    expect(rows[2]).toHaveTextContent("By AI on evidence, AI on the model's word, a suppression rule, an earlier analyst verdictAlertsnot measured yet");
    expect(rows[3]).toHaveTextContent(/^Reached a personAlerts153Share12%Checked by/);
    expect(rows[3]).toHaveTextContent('28 items wait right now. Claimed in a mean of 14m 00s, over 125 claimed in the last 24 hours.');
    expect(within(block).getByText(/Mean time from arrival to close/)).toHaveTextContent('Mean time from arrival to close: 10m 00s, over 1,252 alerts closed in the last 24 hours.');
    expect(within(block).queryByText(/too few/)).not.toBeInTheDocument();
  });

  it('withholds a share and a mean over a small sample', () => {
    render(<HandledBar d={summary({ alerts_total: 9, handled_without_human: 1, needed_human: 2, handled_without_human_rate: 1 / 3, acknowledged: 1, resolved: 4, open_escalations: 1 })} phrase={phrase} isAdmin={false} />);
    const block = screen.getByRole('region', { name: 'Closed without a person' });
    expect(within(block).getByText('1 of 3 finished alerts were closed without a person. 2 reached one.')).toBeInTheDocument();
    const rows = within(block).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('Alerts1Sharetoo few for a share');
    expect(rows[3]).toHaveTextContent('Alerts2Sharetoo few for a share');
    expect(rows[3]).toHaveTextContent('1 item waits right now. Mean time to claim: too few for a mean (n=1; at least 5 needed).');
    expect(within(block).getByText(/Shares need at least 5 finished alerts/)).toHaveTextContent('Mean time from arrival to close: too few for a mean (n=4; at least 5 needed).');
    expect(within(block).queryByText(/%/)).not.toBeInTheDocument();
  });

  it('draws a single segment when every finished alert is of one kind', () => {
    render(<HandledBar d={summary({ alerts_total: 40, handled_without_human: 40, needed_human: 0, handled_without_human_rate: 1 })} phrase={phrase} isAdmin={false} />);
    expect(screen.getByText('40 of 40 finished alerts were closed without a person. None reached one.')).toBeInTheDocument();
    const bar = screen.getByRole('img', { name: '40 finished alerts: 40 closed without a person, 0 reached a person' });
    expect([...bar.children].map((s) => s.getAttribute('data-segment'))).toEqual(['handled']);
    expect(screen.getAllByRole('row')[3]).toHaveTextContent('Alerts0Share0%');
  });

  it('has no bar and no table while nothing is finished, or without an alert', () => {
    const { unmount } = render(<HandledBar d={summary({ alerts_total: 1, handled_without_human: 0, needed_human: 0, handled_without_human_rate: null })} phrase={phrase} isAdmin={false} />);
    expect(screen.getByText('None of the 1 alert received in the last 24 hours is finished yet.')).toBeInTheDocument();
    expect(screen.getByTestId('overview-alerts-received').parentElement).toHaveTextContent('1 alert received in the last 24 hours');
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    unmount();

    const empty = summary({ alerts_total: 0, handled_without_human: 0, needed_human: 0, handled_without_human_rate: null });
    const admin = render(<HandledBar d={empty} phrase={phrase} isAdmin />);
    expect(screen.getByText('No alert was received in the last 24 hours.')).toBeInTheDocument();
    expect(screen.getByText('Connect a source under Sources or send alerts to the ingest API.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    admin.unmount();
    render(<HandledBar d={empty} phrase={phrase} isAdmin={false} />);
    expect(screen.getByText('Figures appear as alerts arrive.')).toBeInTheDocument();
  });

  it('gives the count alone on an API without the split', () => {
    const older = summary();
    delete older.handled_without_human;
    delete older.needed_human;
    render(<HandledBar d={older} phrase={phrase} isAdmin={false} />);
    expect(screen.getByText('1,284 alerts were received in the last 24 hours.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
});

describe('Verification', () => {
  async function show(report: () => BlindAuditReportOut, role: 'viewer' | 'admin' = 'viewer') {
    const fake = fakeApi((_m, path) => {
      if (path === '/reports/blind-audit') return report();
      throw new Error(`unexpected ${path}`);
    });
    const session = await signedInSession(fake.api, { role });
    renderWithSession(<Verification />, session);
    return { ...fake, block: screen.getByRole('region', { name: "How the AI's closes are verified" }) };
  }
  const figure = (block: HTMLElement, label: string) => within(block).getByRole('heading', { name: label, level: 3 }).parentElement as HTMLElement;
  /** The blind-audit figure once its report has arrived, found by its headline. */
  const shown = async (block: HTMLElement, big: string) => (await within(block).findByText(big)).parentElement as HTMLElement;

  it('gives the blind audit with its populations, its window and the rate the sample carries', async () => {
    const { block, calls } = await show(() => auditReport());
    const audit = await shown(block, '1 of 180');
    expect(audit).toHaveAttribute('data-figure', 'rate');
    expect(audit).toHaveTextContent("sampled AI closes were labelled malicious by an analyst who could not see the AI's verdict.");
    expect(audit).toHaveTextContent('Missed-threat rate 0.6%, 95% interval 0.0% to 3.1%.');
    expect(audit).toHaveTextContent('9,870 closes without a person eligible, 180 sampled, 180 labelled, 0 waiting for a label. Runs of');
    expect(audit).toHaveTextContent(/Runs of .*16.* to .*14.* \(UTC\)\./);
    expect(audit).not.toHaveTextContent('Counting unsure');
    expect(within(audit).getByRole('link', { name: 'Full estimate in Reports' })).toHaveAttribute('href', '/reports');
    // The report's own default window: the 30 days ending today, whatever the page's window.
    const query = calls.find((c) => c.path === '/reports/blind-audit')?.query as { from: string; to: string };
    expect((Date.parse(query.to) - Date.parse(query.from)) / 86_400_000).toBe(29);
  });

  it('adds the worst case while samples are unsure or still wait', async () => {
    const { block } = await show(() => auditReport({ status: 'incomplete', complete: false, sampled: 200, labelled: 188, pending: 12, unsure: 8, worst_case_rate: 0.105 }));
    const audit = await shown(block, '1 of 180');
    expect(audit).toHaveTextContent('Missed-threat rate 0.6%, 95% interval 0.0% to 3.1%. Counting unsure and waiting samples as malicious: 10.5%.');
    expect(audit).toHaveTextContent('200 sampled, 188 labelled (8 unsure), 12 waiting for a label');
  });

  it('refuses a rate on a small sample', async () => {
    const { block } = await show(() =>
      auditReport({ status: 'insufficient_data', frame_size: 1, sampled: 12, labelled: 4, pending: 8, malicious: 1, benign: 3, false_negative_rate: { rate: 0.25, n: 4, ci_low: 0.05, ci_high: 0.7 } }),
    );
    const audit = await shown(block, '1 of 4');
    expect(audit).toHaveAttribute('data-figure', 'few');
    expect(audit).toHaveTextContent('too few for a rate (n=4; at least 30 needed).');
    expect(audit).toHaveTextContent('1 close without a person eligible');
    expect(audit).not.toHaveTextContent('%');
  });

  it('says a single labelled close in the singular', async () => {
    const { block } = await show(() => auditReport({ status: 'insufficient_data', sampled: 5, labelled: 1, pending: 4, malicious: 0, benign: 1 }));
    expect(await within(block).findByText('0 of 1')).toBeInTheDocument();
    expect(block).toHaveTextContent('sampled AI close was labelled malicious');
  });

  it('says when samples wait for their first label', async () => {
    const { block } = await show(() => auditReport({ status: 'insufficient_data', sampled: 12, labelled: 2, pending: 10, malicious: 0, benign: 0, unsure: 2 }));
    const audit = await shown(block, 'None labelled yet');
    expect(audit).toHaveTextContent('12 AI closes were sampled; no analyst has labelled one malicious or benign yet.');
    expect(audit).toHaveTextContent('12 sampled, 2 labelled (2 unsure), 10 waiting for a label');
  });

  it('claims nothing when no sample was drawn, and tells an admin where to draw one', async () => {
    const none = { status: 'insufficient_data', frame_size: 0, sampled: 0, labelled: 0, pending: 0, malicious: 0, benign: 0 } as const;
    const viewer = await show(() => auditReport(none));
    expect(await within(viewer.block).findByText('No sample drawn')).toBeInTheDocument();
    expect(viewer.block).toHaveTextContent('No AI close was sampled for a blind audit in this period, so nothing is claimed about missed threats.');
    expect(viewer.block).toHaveTextContent('An admin draws a sample, or turns on the weekly one in the tenant settings.');
    expect(within(viewer.block).queryByRole('link', { name: 'Blind audit page' })).not.toBeInTheDocument();
  });

  it('gives an admin the link to draw a sample', async () => {
    const { block } = await show(() => auditReport({ status: 'insufficient_data', frame_size: 0, sampled: 0, labelled: 0, pending: 0, malicious: 0, benign: 0 }), 'admin');
    expect(await within(block).findByRole('link', { name: 'Blind audit page' })).toHaveAttribute('href', '/blind-audit');
  });

  it('shows what the API does not report as not measured yet, never as a figure', async () => {
    const { block } = await show(() => auditReport());
    for (const [label, counts] of [
      ['Planted attacks', 'Attack alerts planted in live traffic, and how many of them the AI closed.'],
      ['Safety net', 'AI closes reopened because a person confirmed a related threat, and closes linked to an open case and left closed.'],
    ]) {
      const f = figure(block, label);
      expect(f).toHaveAttribute('data-figure', 'not-measured');
      expect(f).toHaveTextContent('Not measured yet');
      expect(f).toHaveTextContent(counts);
      expect(f).not.toHaveTextContent(/\d/);
    }
  });

  it('keeps a failed report inside its block, with a retry', async () => {
    let fail = true;
    const { block } = await show(() => {
      if (fail) throw apiError(503, 'unavailable', 'A backend service is unavailable.');
      return auditReport();
    });
    expect(within(block).getByText('Loading the blind audit')).toBeInTheDocument();
    expect(await within(block).findByText('A backend service is unavailable.')).toBeInTheDocument();
    expect(figure(block, 'Planted attacks')).toHaveTextContent('Not measured yet');
    fail = false;
    await userEvent.click(within(block).getByRole('button', { name: 'Retry' }));
    expect(await within(block).findByText('1 of 180')).toBeInTheDocument();
  });
});

describe('OverviewPage: deadlines, platform health and the page', () => {
  it('lists the next deadlines, each item opening its investigation view', async () => {
    const w = world();
    await open(w, 'analyst');
    const block = await screen.findByRole('region', { name: 'Next deadlines' });
    expect(block).toHaveTextContent('Items that need a person, soonest deadline first, right now · the next deadline still ahead is in 4 hours · 3 are past their deadline');
    expect(within(block).getByRole('link', { name: 'Open the whole queue' })).toHaveAttribute('href', '/queue');
    const rows = within(await within(block).findByRole('table', { name: 'Next deadlines' })).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('2h 14m over · breaching');
    expect(rows[1]).toHaveTextContent('Unusual sign-in pattern · j.moreau@acme.example');
    expect(rows[1]).toHaveTextContent('Unassigned');
    expect(rows[2]).toHaveTextContent('at risk');
    expect(rows[2]).toHaveTextContent('You');
    expect(rows[3]).toHaveTextContent('n.haddad@acme.example');
    expect(rows[3]).toHaveTextContent('medium');
    expect(within(rows[1]).getByRole('link', { name: 'Unusual sign-in pattern' })).toHaveAttribute('href', '/alerts/a-e-1');
    expect(w.calls.filter((c) => c.path === '/escalations').map((c) => c.query)).toContainEqual({ status: ['open', 'claimed'], order: 'sla_deadline', cursor: undefined, limit: 5 });
  });

  it('says when the queue is clear', async () => {
    await open(world({ dash: () => summary({ my_claimed: 0, unassigned_escalations: 0, unassigned_breaching: 0, next_sla_deadline: null, overdue_escalations: 1 }), escalations: () => [] }), 'analyst');
    const block = await screen.findByRole('region', { name: 'Next deadlines' });
    expect(await within(block).findByText('Nothing waits for a person. The queue is clear.')).toBeInTheDocument();
    expect(block).toHaveTextContent('no deadline ahead · 1 is past its deadline');
  });

  it('shows platform health to an admin, with what each figure counts', async () => {
    const w = world();
    await open(w, 'admin');
    const admin = await screen.findByRole('region', { name: 'Platform health' });
    expect(admin).toHaveTextContent('Shown to admins only.');
    const figure = (label: string) => within(admin).getByRole('heading', { name: label, level: 3 }).parentElement as HTMLElement;
    expect(figure('Queue depth, right now')).toHaveTextContent('2workflow runs wait to start.');
    expect(figure('LLM cost, last 24 hours')).toHaveTextContent('for 42,000 tokens. Model: deep-model-test.');
    expect(within(admin).getByRole('link', { name: 'LLM usage by day and model' })).toHaveAttribute('href', '/usage');
    expect(figure('Analyst hours saved, last 24 hours')).toHaveTextContent('An estimate over 1,284 finished alerts: 15 minutes for each alert closed without a person.');
    expect(within(admin).getByRole('table', { name: /Worker health/ })).toHaveTextContent('Queued');
    const status = within(admin).getByRole('table', { name: /Alerts by status/ });
    expect(within(status).getAllByRole('rowheader').map((h) => h.textContent)).toEqual(['Waiting for an analyst', 'Waiting for approval', 'Closed', 'Failed', 'Odd state']);
    expect(within(status).getByRole('link', { name: 'Failed' })).toHaveAttribute('href', '/alerts?status=failed&from=2026-11-05T12%3A00%3A00Z');
    expect(within(admin).getByRole('link', { name: 'Benign' })).toHaveAttribute('href', '/alerts?disposition=benign&from=2026-11-05T12%3A00%3A00Z');
    await waitFor(() => expect(w.calls.some((c) => c.path === '/onboarding/status')).toBe(true));
  });

  it('says when LLM use is off and when nothing runs', async () => {
    await open(world({ dash: () => summary({ llm_model: null, runs_by_status: {}, by_disposition: {}, by_status: {} }) }), 'admin');
    const admin = await screen.findByRole('region', { name: 'Platform health' });
    expect(admin).toHaveTextContent('for 42,000 tokens. LLM use is off.');
    expect(admin).toHaveTextContent('No workflow run is waiting or running.');
    expect(admin).toHaveTextContent('No alert in this window.');
    expect(admin).toHaveTextContent('No disposition recorded in this window.');
  });

  it('hides platform health from everyone else, and keeps the order of the page', async () => {
    await open(world(), 'analyst');
    await screen.findByRole('region', { name: 'Needs you now' });
    expect(screen.queryByRole('region', { name: 'Platform health' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual(['Needs you now', 'Closed without a person', "How the AI's closes are verified", 'Next deadlines']);
  });

  it('asks the dashboard again for another window, and names that window', async () => {
    const w = world();
    await open(w, 'analyst');
    await screen.findByRole('region', { name: 'Closed without a person' });
    await userEvent.click(screen.getByRole('radio', { name: 'Last 7 days' }));
    await waitFor(() => expect(w.calls.filter((c) => c.path === '/dashboard/summary').at(-1)?.query).toEqual({ window_hours: 168 }));
    expect(await screen.findByText(/alerts received in the last 7 days/)).toBeInTheDocument();
    // The blind audit keeps its own 30 days.
    expect(w.calls.filter((c) => c.path === '/reports/blind-audit')).toHaveLength(1);
  });

  it('omits the queue blocks on an API without the queue figures', async () => {
    const older = summary({ alerts_total: 0, handled_without_human: 0, needed_human: 0, handled_without_human_rate: null });
    for (const k of ['unassigned_escalations', 'unassigned_breaching', 'pending_approvals_total', 'pending_approvals', 'my_claimed'] as const) delete older[k];
    const w = world({ dash: () => older });
    await open(w, 'viewer');
    expect(await screen.findByText('No alert was received in the last 24 hours.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Needs you now' })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Next deadlines' })).not.toBeInTheDocument();
    expect(w.calls.some((c) => c.path === '/escalations')).toBe(false);
  });

  it('shows a failed dashboard with a retry', async () => {
    const fake = fakeApi(() => {
      throw apiError(503, 'unavailable', 'A backend service is unavailable.');
    });
    const session = await signedInSession(fake.api, { role: 'analyst' });
    renderWithSession(<OverviewPage />, session);
    expect(await screen.findByText('A backend service is unavailable.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Closed without a person' })).not.toBeInTheDocument();
  });
});

describe('figures', () => {
  it('names the window and where the work queue is', () => {
    expect(windowPhrase(168)).toBe('the last 7 days');
    expect(windowPhrase(5)).toBe('the last 5 hours');
    expect(workQueueHref('mine')).toBe('/queue?view=mine');
    expect(workQueueHref('unassigned')).toBe('/queue?view=unassigned');
    expect(workQueueHref('all')).toBe('/queue');
    expect(dayRange('2026-10-16', '2026-11-14')).toMatch(/16.*14/);
    expect(dayRange('soon', '2026-11-14')).toMatch(/^soon to /);
  });

  it('gives a share only over enough finished alerts and only when the API sent the rate', () => {
    expect(handledSplit(summary({ handled_without_human: 71, needed_human: 34, handled_without_human_rate: 0.676 }))).toEqual({ handled: 71, needed: 34, finished: 105, handledShare: 0.676, neededShare: 1 - 0.676 });
    expect(handledSplit(summary({ handled_without_human: 3, needed_human: 1, handled_without_human_rate: 0.75 }))).toMatchObject({ finished: 4, handledShare: null, neededShare: null });
    expect(handledSplit(summary({ handled_without_human: 9, needed_human: 1, handled_without_human_rate: null }))).toMatchObject({ finished: 10, handledShare: null });
    expect(handledSplit(summary({ handled_without_human: -1 }))).toBeNull();
    expect(handledStatement(summary({ alerts_total: 1 }), null, 'x')).toBe('1 alert was received in x.');
    expect(handledStatement(summary(), { handled: 1, needed: 0, finished: 1, handledShare: null, neededShare: null }, 'x')).toBe('1 of 1 finished alert was closed without a person. None reached one.');
  });

  it('gives a mean only over enough observations', () => {
    expect(claimMean(summary({ acknowledged: 9, mtta_s: 420 }))).toEqual({ value: '7m 00s', n: 9 });
    expect(claimMean(summary({ acknowledged: 4, mtta_s: 420 }))).toEqual({ value: null, n: 4 });
    expect(claimMean(summary({ acknowledged: 9, mtta_s: null }))).toEqual({ value: null, n: 9 });
    expect(closeMean(summary({ resolved: 4 }))).toEqual({ value: null, n: 4 });
    expect(closeMean(summary({ resolved: 12, mttr_s: 600 }))).toEqual({ value: '10m 00s', n: 12 });
  });

  it('reads the blind-audit estimate into one of four states', () => {
    expect(auditFigure(estimate())).toEqual({ state: 'rate', decided: 180, rate: '0.6%', interval: '0.0% to 3.1%', worstCase: null });
    expect(auditFigure(estimate({ false_negative_rate: { rate: 0.0056, n: 180, ci_low: null, ci_high: null }, unsure: 2, worst_case_rate: null }))).toMatchObject({ state: 'rate', interval: null, worstCase: null });
    expect(auditFigure(estimate({ sampled: 0 })).state).toBe('none');
    expect(auditFigure(estimate({ malicious: 0, benign: 0 })).state).toBe('unlabelled');
    expect(auditFigure(estimate({ malicious: 1, benign: 3 })).state).toBe('few');
    expect(auditFigure(estimate({ status: 'insufficient_data' })).state).toBe('few');
    expect(auditFigure(estimate({ false_negative_rate: { rate: null, n: 0, ci_low: null, ci_high: null } })).state).toBe('few');
  });
});
