import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { AlertDetailOut, EscalationOut } from '../../api/types';
import { escalationHref } from '../../lib/links';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import { AlertDrawer } from './AlertDrawer';
import { AlertSidePanel } from './AlertPanel';

const minutesFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

const ALERT: AlertDetailOut = {
  id: 'a-1',
  tenant_id: 'acme',
  source_id: 'entra',
  source_alert_id: 'src-1',
  fingerprint: 'fp-1',
  title: 'Unusual sign-in pattern',
  severity: 'high',
  status: 'waiting_human',
  confidence: 42,
  threat_score: 55,
  occurred_at: minutesFromNow(-3),
  ingested_at: minutesFromNow(-2),
  updated_at: minutesFromNow(-1),
  source_name: 'Entra ID sign-ins',
  summary: {
    escalation_id: 'e-1',
    llm_budget_exceeded: true,
    triage: { confidence: 42, priority: 2, rule_tp: ['tor_exit'] },
    correlation: { related: 1 },
    response: { auto: 0, evidence: 'rules' },
    analysis: {
      verdict: 'inconclusive',
      threat_score: 55,
      certainty: 40,
      llm_used: true,
      conclusion: 'Sign-in from a TOR exit node nine minutes after a sign-in from Lyon.',
      reasoning: ['The source address is a TOR exit node.'],
      recommended_actions: ['revoke sessions', 'reset MFA'],
      tools: [{ kind: 'ip', target: '185.220.101.4', simulated: true, results: [{ source: 'abuseipdb' }] }],
    },
  },
  normalized: {
    rule_name: 'Risky sign-in',
    description: 'A sign-in from an anonymizing network.',
    flags: ['missing_host'],
    entities: { users: ['j.moreau@acme.example'], ips: ['185.220.101.4'] },
    mitre: { tactics: ['Initial Access'], techniques: ['T1078'] },
  },
  findings: [
    { origin: 'threat_intel', kind: 'ip', target: '185.220.101.4', source: 'abuseipdb', status: 'ok', verdict: 'malicious', checked_at: '2026-11-07T10:02:13Z', cached: false, data: { simulated: true } },
    { origin: 'threat_intel', kind: 'ip', target: '185.220.101.4', source: 'virustotal', status: 'error', verdict: 'unknown', checked_at: null, cached: true, data: {} },
    { origin: 'history', kind: 'user', target: 'j.moreau@acme.example', source: 'history', status: 'ok', verdict: 'benign', checked_at: '2026-11-07T10:02:14Z' },
  ],
};

function escalation(overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id: 'e-1',
    tenant_id: 'acme',
    alert_id: 'a-1',
    level: 'L1',
    status: 'open',
    reason: 'Low confidence',
    priority: 1,
    version: 3,
    sla_deadline: minutesFromNow(-134),
    created_at: minutesFromNow(-164),
    updated_at: minutesFromNow(-10),
    ...overrides,
  };
}

function handler(alert: AlertDetailOut, esc: () => EscalationOut | Error = () => escalation()) {
  return (method: string, path: string) => {
    if (method === 'GET' && path === `/alerts/${alert.id}`) return alert;
    if (method === 'GET' && path === `/alerts/${alert.id}/events`) {
      return { items: [{ id: 1, alert_id: alert.id, ts: '2026-11-07T10:02:11Z', event_type: 'ingested', actor_type: 'system', data: {} }], next_cursor: null };
    }
    if (method === 'GET' && path === '/actions') return { items: [], next_cursor: null };
    if (method === 'GET' && path === '/tickets') return [];
    if (method === 'GET' && path === '/escalations/e-1') {
      const e = esc();
      if (e instanceof Error) throw e;
      return e;
    }
    if (method === 'POST' && path === '/escalations/e-1/claim') return escalation({ status: 'claimed', assigned_to: 'u-1', version: 4 });
    throw new Error(`unexpected ${method} ${path}`);
  };
}

async function renderPanel(alert: AlertDetailOut = ALERT, opts: { role?: string; esc?: () => EscalationOut | Error } = {}) {
  const { api, calls } = fakeApi(handler(alert, opts.esc));
  renderWithSession(<AlertSidePanel alertId={alert.id} onClose={() => undefined} />, await signedInSession(api, { role: opts.role ?? 'analyst' }));
  const panel = await screen.findByRole('complementary', { name: alert.title });
  await within(panel).findByText('Alert details');
  return { panel, calls };
}

describe('alert panel sections', () => {
  it('says when the verdict is hidden for a blind audit', async () => {
    const hidden: AlertDetailOut = {
      ...ALERT,
      status: 'closed',
      disposition: null,
      confidence: null,
      threat_score: null,
      summary: { hidden_for_blind_audit: true },
      hidden_for_blind_audit: true,
    };
    const { panel } = await renderPanel(hidden);
    expect(within(panel).getByRole('status')).toHaveTextContent('Verdict hidden for a blind audit');
  });

  it('keeps every section of the old drawer', async () => {
    const { panel } = await renderPanel();
    for (const name of ['Automated triage', 'Entities', 'Timeline', 'Response actions', 'Tickets', 'Notes', 'Evidence and reporting', 'Alert details']) {
      expect(within(panel).getByRole('heading', { name })).toBeInTheDocument();
    }
    expect(within(panel).getByText('Normalized record')).toBeInTheDocument();
    expect(within(panel).getByText('Scores, rules and response plan')).toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Draft NIS2 report' })).toBeInTheDocument();
    // Header: severity, status, short id, source name.
    expect(within(panel).getByText('Waiting for an analyst')).toBeInTheDocument();
    expect(panel).toHaveTextContent('a-1 · Entra ID sign-ins · 2 minutes ago');
    // Details, entities and MITRE, the triage narrative.
    expect(within(panel).getByText('Risky sign-in')).toBeInTheDocument();
    expect(within(panel).getByText('A sign-in from an anonymizing network.')).toBeInTheDocument();
    expect(within(panel).getByText('Data quality flags: missing_host')).toBeInTheDocument();
    expect(within(panel).getByText('IP addresses')).toBeInTheDocument();
    expect(within(panel).getByText('Initial Access, T1078')).toBeInTheDocument();
    expect(within(panel).getByText(/Triage confidence 42%\. Threat score 55\./)).toBeInTheDocument();
    expect(within(panel).getByText(/TOR exit node nine minutes/)).toBeInTheDocument();
    expect(within(panel).getByRole('list', { name: 'Reasoning steps' })).toHaveTextContent('The source address is a TOR exit node.');
    expect(within(panel).getByText('Agent suggests: revoke sessions, reset MFA. Nothing runs until an analyst decides.')).toBeInTheDocument();
    expect(within(panel).getByText(/daily LLM token budget was exhausted/)).toBeInTheDocument();
    const basis = within(panel).getByRole('list', { name: 'Basis of this verdict' });
    expect(basis).toHaveTextContent('Written by the model');
    expect(basis).toHaveTextContent('Evidence: partly simulated');
    expect(basis).toHaveTextContent('LLM budget exhausted');
    // The timeline loaded its event (and "Ingested" is also a detail row).
    await waitFor(() => expect(within(panel).getAllByText('Ingested')).toHaveLength(2));
    // A viewer-level action is never offered to an analyst: no reprocess.
    expect(within(panel).queryByRole('button', { name: 'Reprocess' })).not.toBeInTheDocument();
  });

  it('lists what the AI verdict is based on: origin, source, verdict, check time and the cached marker', async () => {
    const { panel } = await renderPanel();
    const findings = within(panel).getByRole('list', { name: 'What the AI verdict is based on' });
    const items = within(findings).getAllByRole('listitem');
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent('Threat intel');
    expect(items[0]).toHaveTextContent('abuseipdb');
    expect(items[0]).toHaveTextContent('Malicious');
    expect(items[0]).toHaveTextContent('simulated');
    expect(items[0]).toHaveTextContent('IP 185.220.101.4');
    expect(within(items[0]).getByText(/Checked/).querySelector('time')).toHaveAttribute('dateTime', '2026-11-07T10:02:13Z');
    expect(items[0]).not.toHaveTextContent('cached');
    expect(items[1]).toHaveTextContent('virustotal');
    expect(items[1]).toHaveTextContent('Unknown (error)');
    expect(items[1]).toHaveTextContent('cached');
    expect(items[1]).toHaveTextContent('Check time not recorded');
    expect(items[2]).toHaveTextContent('Your history');
    expect(items[2]).toHaveTextContent('User j.moreau@acme.example');
  });

  it('warns in red when evidence was simulated, naming the provider', async () => {
    const { panel } = await renderPanel();
    const warning = within(panel).getAllByRole('alert').find((el) => el.textContent?.includes('Some evidence was simulated.'));
    expect(warning).toBeDefined();
    expect(warning).toHaveAttribute('data-tone', 'warning');
    expect(warning).toHaveTextContent('Results from abuseipdb came from a test fixture, not a live lookup. Verify before acting.');
  });

  it('warns about a dry-run response, and says nothing when the evidence was live', async () => {
    const closed: AlertDetailOut = {
      ...ALERT,
      status: 'closed',
      summary: { verdict: 'malicious', dry_run: true, simulated_evidence: false },
      findings: [],
    };
    const { panel } = await renderPanel(closed);
    expect(within(panel).getByRole('alert')).toHaveTextContent('The response ran as a dry run.');
    expect(within(panel).queryByText('Some evidence was simulated.')).not.toBeInTheDocument();
    expect(within(panel).queryByText(/Nothing runs until an analyst decides/)).not.toBeInTheDocument();
    // No escalation id: no escalation box.
    expect(within(panel).queryByTestId('escalation-box')).not.toBeInTheDocument();

    const live: AlertDetailOut = { ...ALERT, title: 'Live evidence only', summary: { analysis: { verdict: 'benign', llm_used: false } }, findings: [] };
    const second = await renderPanel(live);
    expect(within(second.panel).queryByRole('alert')).not.toBeInTheDocument();
    expect(within(second.panel).getByRole('list', { name: 'Basis of this verdict' })).toHaveTextContent('Rules onlyEvidence: no lookups');
    expect(within(second.panel).getByText('No threat-intel or history lookup was recorded for this analysis.')).toBeInTheDocument();
  });

  it('says when the workflow has not produced a verdict', async () => {
    const { panel } = await renderPanel({ ...ALERT, status: 'queued', summary: {}, findings: undefined });
    expect(within(panel).getByText('The workflow has not produced a verdict yet.')).toBeInTheDocument();
  });
});

describe('alert panel escalation', () => {
  it('shows the SLA and owner, and claims only when Claim is pressed', async () => {
    const { panel, calls } = await renderPanel();
    const box = await within(panel).findByTestId('escalation-box');
    expect(box).toHaveTextContent('Escalation e-1 · L1');
    expect(box).toHaveTextContent(/2h 1[34]m over · breaching/);
    expect(box).toHaveTextContent('Owner: Unassigned');
    expect(within(box).getByRole('link', { name: 'Open escalation' })).toHaveAttribute('href', escalationHref(escalation()));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await userEvent.click(within(box).getByRole('button', { name: 'Claim' }));
    await waitFor(() => expect(calls.find((c) => c.method === 'POST')).toMatchObject({ path: '/escalations/e-1/claim', body: { version: 3 } }));
    expect(await screen.findByText('Escalation claimed.')).toBeInTheDocument();
  });

  it('offers no claim to a viewer, nor on an escalation another analyst holds; an admin may take it over', async () => {
    const viewer = await renderPanel(ALERT, { role: 'viewer' });
    const box = await within(viewer.panel).findByTestId('escalation-box');
    expect(within(box).queryByRole('button', { name: 'Claim' })).not.toBeInTheDocument();
    expect(within(viewer.panel).queryByRole('heading', { name: 'Notes' })).not.toBeInTheDocument();
    expect(within(viewer.panel).queryByRole('button', { name: 'Draft NIS2 report' })).not.toBeInTheDocument();
  });

  it('lets an admin take over a claimed escalation and reprocess the alert', async () => {
    const held = () => escalation({ status: 'claimed', assigned_to: 'u-9', assigned_to_email: 'n.haddad@acme.example', claimed_at: minutesFromNow(-4) });
    const { panel } = await renderPanel(ALERT, { role: 'admin', esc: held });
    const box = await within(panel).findByTestId('escalation-box');
    expect(box).toHaveTextContent(/Owner: n\.haddad@acme\.example, claimed 4 minutes ago/);
    expect(within(box).getByRole('button', { name: 'Take over' })).toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Reprocess' })).toBeInTheDocument();
  });

  it('shows a decided escalation without a claim, and a failed escalation load with a retry', async () => {
    const decided = () => escalation({ status: 'decided', decision: 'false_positive', decided_by: 'u-1', decided_at: minutesFromNow(-30) });
    const { panel } = await renderPanel(ALERT, { esc: decided });
    const box = await within(panel).findByTestId('escalation-box');
    expect(box).toHaveTextContent('Decided');
    expect(box).toHaveTextContent('Decided false positive by You');
    expect(within(box).queryByRole('button', { name: /Claim|Take over/ })).not.toBeInTheDocument();

    const failing = await renderPanel({ ...ALERT, title: 'Escalation fails to load' }, { esc: () => apiError(500, 'internal') });
    expect(await within(failing.panel).findByRole('button', { name: /retry/i })).toBeInTheDocument();
  });

  it('reports a claim conflict', async () => {
    const { api } = fakeApi((method, path) => {
      if (method === 'POST') throw apiError(409, 'conflict');
      return handler(ALERT)(method, path);
    });
    renderWithSession(<AlertSidePanel alertId="a-1" onClose={() => undefined} />, await signedInSession(api, { role: 'analyst' }));
    const box = await screen.findByTestId('escalation-box');
    await userEvent.click(within(box).getByRole('button', { name: 'Claim' }));
    expect(await screen.findByText(/Someone else changed this escalation first/)).toBeInTheDocument();
  });
});

describe('AlertDrawer', () => {
  it('shows the same sections in a modal drawer for the other pages', async () => {
    const { api } = fakeApi(handler(ALERT));
    renderWithSession(<AlertDrawer alertId="a-1" onClose={() => undefined} />, await signedInSession(api, { role: 'admin' }));
    const dialog = await screen.findByRole('dialog', { name: 'Unusual sign-in pattern' });
    expect(within(dialog).getByRole('heading', { name: 'Automated triage' })).toBeInTheDocument();
    expect(within(dialog).getByText('Some evidence was simulated.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Reprocess' })).toBeInTheDocument();
  });
});
