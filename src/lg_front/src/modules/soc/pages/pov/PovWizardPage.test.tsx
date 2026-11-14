import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { PovRunIn, PovRunOut } from '../../api/types';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import ReportsPage from '../ReportsPage';
import { backtestStatus, backtestSummary, parseDays, runStatus, shadowRange, shadowStatus, BACKTEST_DAYS, SHADOW_DAYS } from './pov';
import PovPage from './PovPage';
import PovWizardPage from './PovWizardPage';

function run(overrides: Partial<PovRunOut> = {}): PovRunOut {
  return {
    id: 'run-1',
    name: 'Acme November',
    status: 'backtest',
    backtest: {
      window_start: '2026-08-16T10:00:00Z',
      window_end: '2026-11-14T10:00:00Z',
      status: 'pending',
      started_at: null,
      finished_at: null,
      error: null,
      result: null,
    },
    shadow: {
      window_start: '2026-11-14T10:00:00Z',
      window_end: '2026-11-28T10:00:00Z',
      status: 'running',
      reports: { value: '/reports/value?from=2026-11-14&to=2026-11-28' },
    },
    created_at: '2026-11-14T10:00:00Z',
    created_by: 'u-1',
    cancelled_at: null,
    cancelled_by: null,
    ...overrides,
  };
}

const RESULT = {
  metrics: {
    items: 120,
    errors: 2,
    malicious_items: 18,
    malicious_false_negatives: 1,
    intervals: { malicious_false_negative_rate: { rate: 1 / 18, n: 18, ci_low: 0.0099, ci_high: 0.2576 } },
  },
};

/** The API as the wizard and the page drive it: the runs, one run, start and stop. */
function povApi(initial: PovRunOut[] = [], create?: (body: PovRunIn) => PovRunOut) {
  let runs = initial;
  return fakeApi((method, path, body) => {
    if (path === '/pov/runs' && method === 'POST') {
      const b = body as PovRunIn;
      const made = create ? create(b) : run({ id: 'run-new', name: b.name });
      runs = [made, ...runs];
      return made;
    }
    if (path === '/pov/runs') return { items: runs.map((r) => ({ ...r, backtest: { ...r.backtest, result: null } })), next_cursor: null };
    const id = path.split('/')[3];
    if (path.endsWith('/cancel')) {
      runs = runs.map((r) => (r.id === id ? { ...r, status: 'cancelled', cancelled_at: '2026-11-15T08:00:00Z' } : r));
      return runs.find((r) => r.id === id);
    }
    if (path.startsWith('/pov/runs/')) return runs.find((r) => r.id === id);
    if (path.startsWith('/reports/')) return new Promise(() => undefined);
    throw new Error(`unexpected ${method} ${path}`);
  });
}

function App() {
  return (
    <Routes>
      <Route path="/pov/new" element={<PovWizardPage />} />
      <Route path="/pov" element={<PovPage />} />
      <Route path="/reports" element={<ReportsPage />} />
    </Routes>
  );
}

describe('proof-of-value wizard', () => {
  it('walks through the window, the shadow period and the review, then starts the run through the API', async () => {
    const user = userEvent.setup();
    const { api, calls } = povApi();
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov/new' });

    // 1. The history window: a name and a number of days, checked like the API does.
    expect(await screen.findByRole('heading', { name: 'New proof of value', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Step 1 of 3: History window' })).toBeInTheDocument();
    const steps = screen.getByRole('list', { name: 'Proof-of-value steps' });
    expect(within(steps).getByText('History window').closest('li')).toHaveAttribute('aria-current', 'step');
    const proceed = screen.getByRole('button', { name: 'Continue' });
    expect(proceed).toBeDisabled();
    await user.type(screen.getByLabelText('Name'), '  Acme November ');
    const history = screen.getByLabelText('Days of history to replay');
    expect(history).toHaveValue('90');
    await user.clear(history);
    await user.type(history, '400');
    expect(screen.getByText('A whole number from 1 to 366.')).toBeInTheDocument();
    expect(proceed).toBeDisabled();
    await user.clear(history);
    await user.type(history, '30');
    await user.click(proceed);

    // 2. The shadow period.
    const step2 = await screen.findByRole('heading', { name: 'Step 2 of 3: Shadow period' });
    expect(step2).toHaveFocus();
    const shadow = screen.getByLabelText('Days of shadow period');
    expect(shadow).toHaveValue('14');
    await user.clear(shadow);
    await user.type(shadow, '0');
    expect(screen.getByText('A whole number from 1 to 90.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByLabelText('Name')).toHaveValue('  Acme November ');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.clear(screen.getByLabelText('Days of shadow period'));
    await user.type(screen.getByLabelText('Days of shadow period'), '21');
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    // 3. Review: what was chosen, and that the run only reads.
    await screen.findByRole('heading', { name: 'Step 3 of 3: Review and start' });
    expect(screen.getByText('Acme November')).toBeInTheDocument();
    expect(screen.getByText(/^30 days: /)).toBeInTheDocument();
    expect(screen.getByText(/^21 days: /)).toBeInTheDocument();
    expect(screen.getByText(/no alert is updated, no response action is planned and nobody is notified/)).toBeInTheDocument();
    // Nothing was sent before the last step.
    expect(calls.filter((c) => c.method === 'POST')).toEqual([]);
    await user.click(screen.getByRole('button', { name: 'Start proof of value' }));

    // One request, then the run's page: its backtest is waiting for the server, no command to run.
    expect(await screen.findByRole('heading', { name: 'Proof of value', level: 1 })).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST')).toEqual([
      { method: 'POST', path: '/pov/runs', body: { name: 'Acme November', backtest_days: 30, shadow_days: 21 }, query: undefined },
    ]);
    expect(await screen.findByRole('heading', { name: 'Acme November' })).toBeInTheDocument();
    expect(screen.getByText('Proof of value "Acme November" started.')).toBeInTheDocument();
    expect(screen.getByText('Waiting to start')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'New proof of value' })).not.toBeInTheDocument();
  });

  it('shows why a run was refused and keeps the choices', async () => {
    const user = userEvent.setup();
    const { api } = povApi([], () => {
      throw apiError(429, 'too_many_pov_runs', 'at most 3 proof-of-value runs can be created in 24 hours');
    });
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov/new' });
    await user.type(await screen.findByLabelText('Name'), 'Acme');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(await screen.findByRole('button', { name: 'Continue' }));
    await user.click(await screen.findByRole('button', { name: 'Start proof of value' }));
    expect(await screen.findByText(/at most 3 proof-of-value runs can be created in 24 hours/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Step 3 of 3: Review and start' })).toBeInTheDocument();
    expect(screen.getByText(/^90 days: /)).toBeInTheDocument();
  });

  it('says so when a run is already in progress and does not start another', async () => {
    const user = userEvent.setup();
    const { api, calls } = povApi([run({ status: 'shadow' })]);
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov/new' });
    expect(await screen.findByText('A proof of value is already in progress')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open it' })).toHaveAttribute('href', '/pov');
    await user.type(screen.getByLabelText('Name'), 'Second');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(await screen.findByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('button', { name: 'Start proof of value' })).toBeDisabled();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});

describe('proof-of-value page', () => {
  it('invites to start one when there is none', async () => {
    const { api } = povApi();
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov' });
    expect(await screen.findByText('No proof of value yet')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'New proof of value' })).toHaveAttribute('href', '/pov/new');
  });

  it('shows the backtest result with its sample size and links the reports of the shadow period', async () => {
    const user = userEvent.setup();
    const done = run({ status: 'shadow', backtest: { ...run().backtest, status: 'completed', result: RESULT } });
    const { api } = povApi([done, run({ id: 'run-0', name: 'October trial', status: 'cancelled' })]);
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov' });

    const backtest = await screen.findByRole('region', { name: '1. Backtest over history' });
    expect(await within(backtest).findByText('120')).toBeInTheDocument();
    expect(within(backtest).getByText('1 of 18')).toBeInTheDocument();
    // Every rate carries its n and its interval.
    expect(within(backtest).getByText('5.6% (1 of 18; 95% CI 1.0% to 25.8%)')).toBeInTheDocument();
    expect(within(backtest).getByText('Completed')).toBeInTheDocument();
    const shadow = screen.getByRole('region', { name: '2. Shadow period' });
    expect(within(shadow).getByText('Observing')).toBeInTheDocument();
    expect(within(screen.getByRole('list', { name: 'Earlier runs' })).getByText('Stopped')).toBeInTheDocument();

    // The reports open on the shadow period's window.
    await user.click(within(shadow).getByRole('link', { name: 'Open the reports for this period' }));
    expect(await screen.findByRole('heading', { name: 'Reports', level: 1 })).toBeInTheDocument();
    expect(screen.getByLabelText('From')).toHaveValue('2026-11-14');
    expect(screen.getByLabelText('To')).toHaveValue('2026-11-28');
  });

  it('stops a run in progress after a confirmation', async () => {
    const user = userEvent.setup();
    const { api, calls } = povApi([run()]);
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov' });
    await user.click(await screen.findByRole('button', { name: 'Stop this run' }));
    const dialog = await screen.findByRole('dialog', { name: 'Stop this proof of value?' });
    await user.click(within(dialog).getByRole('button', { name: 'Stop run' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/pov/runs/run-1/cancel')).toBe(true));
    expect(await screen.findByText('Stopped "Acme November".')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'New proof of value' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Stop this run' })).not.toBeInTheDocument();
  });

  it.each([
    ['running', null, /Replaying the alerts/],
    ['no_data', null, /nothing to replay/],
    ['failed', 'model endpoint unreachable', /did not finish: model endpoint unreachable/],
    ['failed', null, /did not finish: no reason was recorded/],
    ['completed', null, /The backtest is complete/],
  ])('explains a backtest that is %s', async (status, error, text) => {
    const { api } = povApi([run({ status: 'shadow', backtest: { ...run().backtest, status, error } })]);
    renderWithSession(<App />, await signedInSession(api, { role: 'admin' }), { route: '/pov' });
    expect(await screen.findByText(text)).toBeInTheDocument();
  });
});

describe('proof-of-value helpers', () => {
  it('accepts whole days within the limits only', () => {
    expect(parseDays(' 30 ', BACKTEST_DAYS)).toBe(30);
    expect(parseDays('366', BACKTEST_DAYS)).toBe(366);
    for (const bad of ['', '0', '367', '1.5', '-3', 'ten', '1e2']) expect(parseDays(bad, BACKTEST_DAYS)).toBeNull();
    expect(parseDays('91', SHADOW_DAYS)).toBeNull();
  });

  it('words every status and shows an unknown one as it is', () => {
    expect(runStatus('backtest')).toEqual({ label: 'Backtest in progress', tone: 'processing' });
    expect(runStatus('completed').tone).toBe('ok');
    expect(backtestStatus('failed')).toEqual({ label: 'Failed', tone: 'bad' });
    expect(shadowStatus('scheduled').label).toBe('Not started');
    expect(shadowStatus('paused_by_a_newer_api')).toEqual({ label: 'Paused by a newer api', tone: 'neutral' });
  });

  it('turns the shadow period into whole report days', () => {
    expect(shadowRange(run())).toEqual({ from: '2026-11-14', to: '2026-11-28' });
    const midnight = run({ shadow: { ...run().shadow, window_start: '2026-11-14T00:00:00Z', window_end: '2026-11-15T00:00:00Z' } });
    expect(shadowRange(midnight)).toEqual({ from: '2026-11-14', to: '2026-11-14' });
  });

  it('reads the headline figures and tolerates a report without them', () => {
    expect(backtestSummary(RESULT)).toEqual({
      items: 120,
      errors: 2,
      threats: 18,
      missed: 1,
      missedRate: { rate: 1 / 18, n: 18, ci_low: 0.0099, ci_high: 0.2576 },
    });
    expect(backtestSummary({ metrics: { items: 'many', intervals: { malicious_false_negative_rate: { n: 0 } } } })).toEqual({
      items: 0,
      errors: 0,
      threats: 0,
      missed: 0,
      missedRate: { rate: null, n: 0, ci_low: null, ci_high: null },
    });
    expect(backtestSummary({ metrics: { intervals: [] } })?.missedRate).toBeNull();
    expect(backtestSummary({})).toBeNull();
    expect(backtestSummary(null)).toBeNull();
  });
});
