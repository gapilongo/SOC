import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { BlindAuditItemOut, BlindAuditLabelOut, BlindAuditReportOut, BlindAuditRunSummary } from '../../../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import ReportsPage from '../ReportsPage';
import BlindAuditPage from './BlindAuditPage';
import { missedText } from './BlindAuditReport';
import { agreementText, isTypingTarget, labelForKey, normalizedFacts } from './labels';
import { parseSize } from './SampleCard';

function item(id: string, overrides: Partial<BlindAuditItemOut> = {}): BlindAuditItemOut {
  return {
    id,
    run_id: 'run-1',
    sample_rank: 1,
    label: null,
    notes: null,
    labelled_at: null,
    labelled_by: null,
    escalation_id: null,
    created_at: '2026-10-12T00:00:00Z',
    alert: {
      title: `Logon from new device ${id}`,
      severity: 'high',
      source_id: 'splunk',
      source_name: 'Splunk',
      category: 'identity',
      occurred_at: '2026-10-06T09:00:00Z',
      ingested_at: '2026-10-06T09:00:05Z',
      entities_preview: { items: [{ kind: 'user', value: 'j.doe' }], counts: { user: 1 } },
      raw: { event: 'logon' },
      normalized: { title: 'Logon', rule_name: 'New device logon', entities: { users: ['j.doe'] } },
    },
    reveal: null,
    ...overrides,
  };
}

const RUN: BlindAuditRunSummary = {
  id: 'run-1',
  window_start: '2026-10-05T00:00:00Z',
  window_end: '2026-10-12T00:00:00Z',
  seed: 42,
  seed_source: 'server',
  sample_rate: 0.02,
  min_sample: 5,
  fixed_size: null,
  frame_size: 300,
  sample_size: 6,
  trigger: 'schedule',
  created_by: 'scheduler',
  created_at: '2026-10-12T00:00:01Z',
  sampled: 6,
  malicious: 1,
  benign: 3,
  unsure: 0,
  agreed: 3,
};

function labelled(id: string, label: 'malicious' | 'benign' | 'unsure'): BlindAuditLabelOut {
  return {
    item: {
      ...item(id),
      label,
      labelled_at: '2026-10-12T10:00:00Z',
      reveal: {
        ai_class: 'benign',
        agreement: label === 'unsure' ? null : label === 'benign',
        disposition: 'benign',
        confidence: 87.5,
        threat_score: 12,
        close_reason: 'triage:false_positive',
        routing_code: 'grey_zone',
        conclusion: 'Routine logon from a managed device.',
      },
    },
    escalation_id: label === 'malicious' ? 'esc-9' : null,
    escalation_created: label === 'malicious',
  };
}

function queueHandler(pending: BlindAuditItemOut[]) {
  return (method: string, path: string, body?: unknown) => {
    if (method === 'GET' && path === '/blind-audit/items') return { items: pending, next_cursor: null };
    if (method === 'GET' && path.startsWith('/blind-audit/items/')) {
      const found = pending.find((i) => path === `/blind-audit/items/${i.id}`);
      if (!found) throw new Error(`unknown ${path}`);
      return found;
    }
    if (method === 'POST' && path.endsWith('/label')) {
      const id = path.split('/')[3];
      pending.splice(
        pending.findIndex((i) => i.id === id),
        1,
      );
      return labelled(id, (body as { label: 'malicious' | 'benign' | 'unsure' }).label);
    }
    if (method === 'GET' && path === '/blind-audit/runs') return { items: [RUN], next_cursor: null };
    if (method === 'POST' && path === '/blind-audit/runs') return { ...RUN, id: 'run-2', sample_size: 3, frame_size: 40 };
    throw new Error(`unexpected ${method} ${path}`);
  };
}

async function renderQueue(role: string, pending: BlindAuditItemOut[]) {
  const fake = fakeApi(queueHandler(pending));
  const session = await signedInSession(fake.api, { role });
  renderWithSession(<BlindAuditPage />, session, { route: '/blind-audit' });
  return fake;
}

describe('BlindAuditPage', () => {
  it('shows the evidence without any AI verdict, then reveals it after the label', async () => {
    const fake = await renderQueue('analyst', [item('i1'), item('i2', { sample_rank: 2 })]);
    expect(await screen.findByRole('heading', { name: 'Logon from new device i1' })).toBeInTheDocument();
    expect(screen.getByText('j.doe')).toBeInTheDocument();
    expect(screen.getByText('New device logon')).toBeInTheDocument();
    // Nothing of the AI's side before the label.
    expect(screen.queryByText(/87/)).toBeNull();
    expect(screen.queryByText(/Routine logon/)).toBeNull();
    expect(screen.queryByText(/AI verdict/)).toBeNull();

    await userEvent.type(screen.getByLabelText('Notes (optional)'), 'normal travel');
    await userEvent.click(screen.getByRole('button', { name: /^Benign/ }));

    expect(await screen.findByText('You and the AI agree.')).toBeInTheDocument();
    expect(screen.getByText('Routine logon from a managed device.')).toBeInTheDocument();
    expect(screen.getByText('88%')).toBeInTheDocument();
    const call = fake.calls.find((c) => c.method === 'POST');
    expect(call?.path).toBe('/blind-audit/items/i1/label');
    expect(call?.body).toEqual({ label: 'benign', notes: 'normal travel' });

    await userEvent.click(screen.getByRole('button', { name: /Next sample/ }));
    expect(await screen.findByRole('heading', { name: 'Logon from new device i2' })).toBeInTheDocument();
  });

  it('labels with the keyboard and links the escalation a malicious label opens', async () => {
    const fake = await renderQueue('analyst', [item('i1')]);
    await screen.findByRole('heading', { name: 'Logon from new device i1' });
    await userEvent.keyboard('m');
    expect(await screen.findByText('You disagree with the AI.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'open the escalation' })).toHaveAttribute('href', '/escalations/esc-9');
    expect(fake.calls.find((c) => c.method === 'POST')?.body).toEqual({ label: 'malicious', notes: null });
    await userEvent.keyboard('n');
    expect(await screen.findByText('Nothing to label')).toBeInTheDocument();
  });

  it('lets an admin draw a sample and see the runs', async () => {
    const fake = await renderQueue('admin', []);
    expect(await screen.findByText('Nothing to label')).toBeInTheDocument();
    expect(await screen.findByText(/6 of 300 sampled \(schedule, seed 42\)/)).toBeInTheDocument();
    const form = screen.getByRole('form', { name: 'Draw a sample' });
    await userEvent.type(within(form).getByLabelText(/Sample size/), '3');
    await userEvent.click(within(form).getByRole('button', { name: 'Draw a sample now' }));
    await screen.findByText('Sampled 3 of 40 auto-closed alerts.');
    expect(fake.calls.find((c) => c.method === 'POST')?.body).toEqual({ size: 3 });
  });

  it('hides sampling from analysts', async () => {
    await renderQueue('analyst', []);
    expect(await screen.findByText('Nothing to label')).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Draw a sample' })).toBeNull();
  });
});

describe('blind audit helpers', () => {
  it('maps keys, typing targets, facts and sizes', () => {
    expect(labelForKey('M')).toBe('malicious');
    expect(labelForKey('x')).toBeNull();
    expect(isTypingTarget(document.createElement('textarea'))).toBe(true);
    expect(isTypingTarget(document.body)).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
    expect(normalizedFacts({ title: 'T', entities: {}, nested: { a: 1 }, n: null, count: 3 })).toEqual([
      ['Title', 'T'],
      ['Count', '3'],
    ]);
    expect(normalizedFacts(null)).toEqual([]);
    expect(parseSize('')).toBeNull();
    expect(parseSize('12')).toBe(12);
    expect(parseSize('0')).toBe('invalid');
    expect(parseSize('2.5')).toBe('invalid');
    expect(agreementText({ ...labelled('a', 'unsure').item.reveal! })).toMatch(/not compared/);
  });
});

const REPORT: BlindAuditReportOut = {
  from: '2026-10-01',
  to: '2026-10-31',
  generated_at: '2026-10-31T00:00:00Z',
  estimate: {
    status: 'ok',
    complete: true,
    summary: '6.7% (stratified over 1 run(s); n=30; 95% CI 1.8% to 21.3%)',
    method: 'stratified',
    frame_size: 3000,
    estimated_frame: 3000,
    effective_n: 30,
    sampled: 32,
    labelled: 31,
    pending: 1,
    malicious: 2,
    benign: 28,
    unsure: 1,
    min_samples: 30,
    false_negative_rate: { rate: 2 / 30, n: 30, ci_low: 0.018477, ci_high: 0.213235 },
    agreement_rate: { rate: 28 / 30, n: 30, ci_low: 0.786, ci_high: 0.982 },
    estimated_missed: 200,
    estimated_missed_low: 55.43,
    estimated_missed_high: 639.7,
    worst_case_rate: 0.09375,
    worst_case_rate_high: 0.24,
    worst_case_missed: 281.25,
    worst_case_missed_high: 720,
  },
  strata: [
    {
      run_id: 'run-1',
      window_start: RUN.window_start,
      window_end: RUN.window_end,
      frame_size: 3000,
      sampled: 32,
      labelled: 31,
      pending: 1,
      malicious: 2,
      benign: 28,
      unsure: 1,
      complete: false,
      false_negative_rate: { rate: 2 / 30, n: 30, ci_low: 0.018477, ci_high: 0.213235 },
    },
  ],
  uncovered: [{ from: '2026-10-12T00:00:00Z', to: '2026-10-31T00:00:00Z' }],
  labels_by_organisation: [{ organisation: 'mssp-org', labelled: 31, malicious: 2, benign: 28, unsure: 1 }],
  runs: [RUN],
  notes: ['Analysts label each sample without seeing the AI verdict.'],
};

describe('Reports page, blind audit tab', () => {
  async function renderTab(report: BlindAuditReportOut) {
    const fake = fakeApi((method, path) => {
      if (path === '/reports/blind-audit') return report;
      if (path === '/reports/value') return new Promise(() => undefined);
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(fake.api, { role: 'viewer' });
    renderWithSession(<ReportsPage />, session, { route: '/reports' });
    await userEvent.click(screen.getByRole('tab', { name: 'Blind audit' }));
  }

  it('shows the false-negative estimate with n, its interval and the frame scaling', async () => {
    await renderTab(REPORT);
    expect(await screen.findByText('6.7%')).toBeInTheDocument();
    expect(screen.getByText(/2 malicious of 30 labelled samples \(n\)\. 95% CI 1\.8% to 21\.3%/)).toBeInTheDocument();
    expect(screen.getByText('about 200 (55 to 640)')).toBeInTheDocument();
    expect(screen.getByText(/3,000 of 3,000 eligible auto-closed alerts/)).toBeInTheDocument();
    expect(screen.getByText('9.4%')).toBeInTheDocument();
    expect(screen.getByText('6.7% (2 of 30; 95% CI 1.8% to 21.3%)')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Uncovered time' })).toBeInTheDocument();
    expect(screen.getByText(/MSSP mssp-org: 31 labels/)).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Blind audit sampling runs' })).toBeInTheDocument();
    expect(screen.queryByText(/Not enough data/)).toBeNull();
  });

  it('uses the small-sample wording', async () => {
    const e = { ...REPORT.estimate, status: 'insufficient_data' as const, summary: 'Not enough data (n=4; at least 30 needed)' };
    await renderTab({ ...REPORT, estimate: e, runs: [], strata: [], uncovered: [], labels_by_organisation: [] });
    expect(await screen.findByText(/Not enough data \(n=4; at least 30 needed\)/)).toBeInTheDocument();
    expect(screen.getByText('No sampling run in this range')).toBeInTheDocument();
    expect(missedText({ ...e, estimated_missed: null })).toBe('-');
  });
});

describe('Reports page, blind audit tab, incomplete', () => {
  it('says the estimate is incomplete while samples wait', async () => {
    const fake = fakeApi((method, path) => {
      if (path === '/reports/blind-audit') return { ...REPORT, estimate: { ...REPORT.estimate, status: 'incomplete', complete: false, pending: 1 } };
      if (path === '/reports/value') return new Promise(() => undefined);
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(fake.api, { role: 'viewer' });
    renderWithSession(<ReportsPage />, session, { route: '/reports' });
    await userEvent.click(screen.getByRole('tab', { name: 'Blind audit' }));
    expect(await screen.findByText(/Incomplete: 1 sample\(s\) still wait for a label/)).toBeInTheDocument();
  });
});
