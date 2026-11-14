import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { AccuracyBlock, AccuracyReportOut, DetectionOut, DetectionsReportOut, ValueMetrics, ValueReportOut } from '../../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../test/helpers';
import ReportsPage from './ReportsPage';

function metrics(overrides: Partial<ValueMetrics> = {}): ValueMetrics {
  return {
    alerts_ingested: 10,
    handled_without_human: 5,
    needed_human: 4,
    in_progress: 1,
    handled_without_human_rate: 5 / 9,
    analyst_hours_saved: 1.25,
    auto_closed_benign: 3,
    auto_contained: 1,
    auto_contained_dry_run: 1,
    escalated: 3,
    human_decided: 2,
    suppressed_by_rule: 1,
    verdict_cache_hits: 1,
    grouped_into_escalation: 1,
    mean_time_to_verdict_s: 20,
    verdicts: 9,
    mtta_s: 600,
    escalations_created: 2,
    acknowledged: 1,
    mttr_s: 1449,
    mttr_auto_s: 59,
    mttr_human_s: 5400,
    resolved: 8,
    sla_breaches: 2,
    llm_cost_usd: 0.75,
    llm_cost_per_alert_usd: 0.075,
    ...overrides,
  };
}

const VALUE: ValueReportOut = {
  from: '2026-09-01',
  to: '2026-09-02',
  generated_at: '2026-09-30T00:00:00Z',
  minutes_per_alert: 15,
  totals: metrics(),
  escalations_breached: 1,
  days: [
    { day: '2026-09-01', ...metrics({ alerts_ingested: 4, handled_without_human: 4, needed_human: 0 }) },
    { day: '2026-09-02', ...metrics({ alerts_ingested: 6, handled_without_human: 1, needed_human: 4 }) },
  ],
  notes: ['Analyst hours saved is an estimate.'],
};

function block(overrides: Partial<AccuracyBlock> = {}): AccuracyBlock {
  return {
    samples: 6,
    status: 'insufficient_data',
    confusion_matrix: { malicious: { malicious: 1, benign: 2, inconclusive: 0 }, benign: { malicious: 1, benign: 1, inconclusive: 1 } },
    agreement: 2,
    agreement_rate: 2 / 6,
    agreement_ci95: [0.1, 0.7],
    analyst_malicious: 3,
    false_negatives: 2,
    false_negative_rate: 2 / 3,
    false_negative_ci95: [0.2, 0.94],
    analyst_benign: 3,
    false_positives: 1,
    false_positive_rate: 1 / 3,
    ai_inconclusive: 1,
    ai_inconclusive_rate: 1 / 6,
    agreement_rate_ci: { rate: 2 / 6, n: 6, ci_low: 0.0968, ci_high: 0.7004 },
    false_negative_rate_ci: { rate: 2 / 3, n: 3, ci_low: 0.2077, ci_high: 0.9384 },
    false_positive_rate_ci: { rate: 1 / 3, n: 3, ci_low: 0.0616, ci_high: 0.7923 },
    ai_inconclusive_rate_ci: { rate: 1 / 6, n: 6, ci_low: 0.0301, ci_high: 0.5636 },
    ...overrides,
  };
}

const ACCURACY: AccuracyReportOut = {
  from: '2026-09-01',
  to: '2026-09-02',
  generated_at: '2026-09-30T00:00:00Z',
  min_samples: 30,
  low_score_below: 30,
  high_score_from: 80,
  overall: block(),
  by_model: [{ model: 'anthropic/claude-x', accuracy: block({ samples: 2, agreement_rate_ci: undefined, false_negative_rate_ci: undefined }) }],
  feedback: {
    total: 8,
    by_decision: {},
    triage_correct: { rate: 2 / 3, samples: 3, status: 'insufficient_data', n: 3, ci_low: 0.2077, ci_high: 0.9384 },
    analysis_accurate: { rate: 0.5, samples: 2, status: 'insufficient_data' },
    correlation_helpful: { rate: null, samples: 0, status: 'insufficient_data', n: 0, ci_low: null, ci_high: null },
    avg_review_duration_s: null,
  },
  notes: [],
};

function detection(overrides: Partial<DetectionOut> = {}): DetectionOut {
  return {
    source_id: 'splunk',
    rule_field: 'rule_name',
    rule: 'Noisy rule',
    volume: 12,
    decided: 12,
    benign: 12,
    benign_rate: 1,
    benign_rate_ci: { rate: 1, n: 12, ci_low: 0.7576, ci_high: 1 },
    malicious: 0,
    auto_closed: 8,
    analyst_false_positive: 4,
    analyst_benign_positive: 0,
    analyst_true_positive: 0,
    median_severity: 'low',
    max_severity: 'medium',
    max_confirmed_benign_severity: 'medium',
    suggestion: 'candidate_suppression',
    reason: 'All decided alerts were benign.',
    can_propose_suppression: true,
    ...overrides,
  };
}

const DETECTIONS: DetectionsReportOut = {
  from: '2026-09-01',
  to: '2026-09-02',
  generated_at: '2026-09-30T00:00:00Z',
  detections: [detection(), detection({ rule: 'Mixed rule', suggestion: 'tune_rule', can_propose_suppression: false, reason: 'Some were malicious.' })],
  truncated: false,
  limit: 200,
  notes: [],
};

function handler(method: string, path: string) {
  if (method === 'POST' && path === '/reports/detections/propose-suppression') return { id: 'rule-1', enabled: false };
  if (path === '/reports/value') return VALUE;
  if (path === '/reports/accuracy') return ACCURACY;
  if (path === '/reports/detections') return DETECTIONS;
  throw new Error(`unexpected ${method} ${path}`);
}

async function renderPage(role: string) {
  const fake = fakeApi(handler);
  const session = await signedInSession(fake.api, { role });
  renderWithSession(<ReportsPage />, session, { route: '/reports' });
  return fake;
}

describe('ReportsPage', () => {
  it('shows the value figures and links the monthly report', async () => {
    await renderPage('viewer');
    expect(await screen.findByText('55.6%')).toBeInTheDocument();
    expect(screen.getAllByText('Handled without a human').length).toBeGreaterThan(0);
    expect(screen.getByRole('img', { name: /per day, 2 days/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open monthly report/ })).toHaveAttribute('href', expect.stringMatching(/^\/reports\/monthly\/\d{4}-\d{2}$/));
    expect(screen.getByRole('table', { name: 'Value report by day' })).toBeInTheDocument();
  });

  it('flags insufficient accuracy data and shows the confusion matrix', async () => {
    await renderPage('viewer');
    await userEvent.click(screen.getByRole('tab', { name: 'Accuracy' }));
    expect(await screen.findByText(/Not enough data \(n=6; at least 30 needed\)/)).toBeInTheDocument();
    // Every rate shows n and its 95% Wilson interval; a model block without one (older API) shows the bare rate.
    expect(screen.getByText(/2 of 3 alerts an analyst confirmed malicious\. 95% CI 20\.8% to 93\.8%/)).toBeInTheDocument();
    expect(screen.getByText(/2 of 6 decisions\. 95% CI 9\.7% to 70\.0%/)).toBeInTheDocument();
    expect(screen.getByText(/Inconclusive on 16\.7% \(1 of 6; 95% CI 3\.0% to 56\.4%\) of all/)).toBeInTheDocument();
    expect(screen.getByText('2 of 3; 95% CI 20.8% to 93.8%')).toBeInTheDocument();
    expect(screen.getByText('Not enough data (n=2; at least 30 needed)')).toBeInTheDocument();
    expect(screen.getByText('Not enough data (n=0)')).toBeInTheDocument();
    expect(screen.getAllByText('66.7%').length).toBeGreaterThan(0);
    expect(screen.getByText('anthropic/claude-x')).toBeInTheDocument();
    expect(screen.getByText(/false negatives/)).toBeInTheDocument();
  });

  it('lets an analyst propose a suppression for a candidate detection', async () => {
    const fake = await renderPage('analyst');
    await userEvent.click(screen.getByRole('tab', { name: 'Detections' }));
    const row = (await screen.findByText('Noisy rule')).closest('tr') as HTMLElement;
    expect(within(screen.getByText('Mixed rule').closest('tr') as HTMLElement).queryByRole('button')).toBeNull();
    await userEvent.click(within(row).getByRole('button', { name: 'Propose suppression' }));
    expect(await within(row).findByRole('link', { name: /review under Suppressions/ })).toBeInTheDocument();
    const call = fake.calls.find((c) => c.method === 'POST');
    expect(call?.body).toMatchObject({ source_id: 'splunk', rule_field: 'rule_name', rule: 'Noisy rule' });
  });

  it('hides the proposal from viewers', async () => {
    await renderPage('viewer');
    await userEvent.click(screen.getByRole('tab', { name: 'Detections' }));
    await screen.findByText('Noisy rule');
    expect(screen.queryByRole('button', { name: 'Propose suppression' })).toBeNull();
    expect(screen.getAllByText('12 of 12; 95% CI 75.8% to 100.0%')).toHaveLength(2);
  });
});
