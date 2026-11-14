import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { UsageOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../../test/helpers';
import UsagePage, { dailyTotals } from './UsagePage';

const USAGE: UsageOut = {
  start: '2026-09-01',
  end: '2026-09-30',
  days: [
    {
      day: '2026-09-01',
      model: 'model-a',
      agent: 'triage',
      calls: 3,
      input_tokens: 1200,
      output_tokens: 300,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
      cost_usd: '0.42',
      refusals: 0,
      errors: 0,
    },
  ],
  total_calls: 3,
  total_input_tokens: 1200,
  total_output_tokens: 300,
  total_cost_usd: '0.42',
};

async function renderPage() {
  const fake = fakeApi((method, path) => {
    if (method === 'GET' && path === '/usage/llm') return USAGE;
    throw new Error(`unexpected ${method} ${path}`);
  });
  const session = await signedInSession(fake.api, { role: 'admin' });
  renderWithSession(<UsagePage />, session, { route: '/usage' });
  return fake;
}

describe('UsagePage', () => {
  it('loads the default 30-day window', async () => {
    const fake = await renderPage();
    expect(await screen.findByRole('img', { name: /Daily LLM cost/ })).toBeInTheDocument();
    expect(fake.calls.filter((c) => c.path === '/usage/llm')).toHaveLength(1);
    expect(screen.queryByText(/at most 366 days|must not be before/)).not.toBeInTheDocument();
  });

  it('reports a window over 366 days before sending the request', async () => {
    const fake = await renderPage();
    await screen.findByRole('img', { name: /Daily LLM cost/ });
    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2020-01-01' } });
    expect(await screen.findByText('A report covers at most 366 days.')).toHaveAttribute('role', 'alert');
    expect(fake.calls.filter((c) => c.path === '/usage/llm')).toHaveLength(1);
    expect(screen.getByRole('button', { name: /Export CSV/ })).toBeDisabled();
  });

  it('reports an end date before the start date', async () => {
    const fake = await renderPage();
    await screen.findByRole('img', { name: /Daily LLM cost/ });
    // The default window ends today, so an end date in the past is before its start.
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2020-01-01' } });
    expect(await screen.findByText('The end date must not be before the start date.')).toHaveAttribute('role', 'alert');
    expect(fake.calls.filter((c) => c.path === '/usage/llm')).toHaveLength(1);
  });
});

describe('dailyTotals', () => {
  it('sums daily LLM cost across models and fills empty days', () => {
    const row = (day: string, cost: string, calls: number) => ({ day, model: 'm', agent: 'a', calls, input_tokens: 10, output_tokens: 5, cache_read_tokens: 0, cache_write_tokens: 0, cost_usd: cost, refusals: 0, errors: 0 });
    const days = dailyTotals([row('2026-09-01', '0.10', 2), row('2026-09-01', '0.05', 1), row('2026-09-03', '1.00', 4)], '2026-09-01', '2026-09-03');
    expect(days.map((d) => [d.day, Number(d.cost.toFixed(2)), d.calls])).toEqual([
      ['2026-09-01', 0.15, 3],
      ['2026-09-02', 0, 0],
      ['2026-09-03', 1, 4],
    ]);
  });
});
