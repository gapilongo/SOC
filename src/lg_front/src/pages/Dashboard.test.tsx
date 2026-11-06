import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { DashboardOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import DashboardPage from './Dashboard';

function summary(overrides: Partial<DashboardOut> = {}): DashboardOut {
  return {
    window_hours: 24,
    since: '2026-10-01T00:00:00Z',
    generated_at: '2026-10-02T00:00:00Z',
    alerts_total: 1234,
    by_status: { queued: 4, closed: 1230 },
    by_severity: { high: 34, low: 1200 },
    by_disposition: { benign: 1100 },
    mtta_s: 90,
    mttr_s: 600,
    acknowledged: 10,
    resolved: 9,
    open_escalations: 7,
    runs_by_status: { running: 2 },
    queue_depth: 3,
    llm_cost_usd: 1.5,
    llm_tokens: 42000,
    handled_without_human: 900,
    needed_human: 100,
    handled_without_human_rate: 0.9,
    analyst_hours_saved: 225,
    minutes_per_alert: 15,
    ...overrides,
  };
}

describe('DashboardPage', () => {
  it('renders the summary tiles and breakdowns and re-reads them for another window', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/dashboard/summary') return summary();
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<DashboardPage />, session);

    expect(await screen.findByRole('link', { name: /Alerts\s*1,234/ })).toHaveAttribute('href', '/alerts');
    expect(screen.getByRole('link', { name: /Open escalations\s*7/ })).toHaveAttribute('href', '/escalations');
    expect(screen.getByText('Handled without human')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'By severity' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'high' })).toHaveAttribute('href', '/alerts?severity=high');
    expect(screen.queryByText(/No alerts were ingested/)).not.toBeInTheDocument();
    // Analysts do not see the admin onboarding banner (it would query /onboarding/status).
    expect(calls.map((c) => c.path)).toEqual(['/dashboard/summary']);
    expect(calls[0].query).toEqual({ window_hours: 24 });

    await userEvent.selectOptions(screen.getByLabelText('Window'), '168');
    await waitFor(() => expect(calls.at(-1)?.query).toEqual({ window_hours: 168 }));
  });

  it('explains an empty window', async () => {
    const { api } = fakeApi(() => summary({ alerts_total: 0, by_status: {}, by_severity: {}, by_disposition: {} }));
    const session = await signedInSession(api, { role: 'viewer' });
    renderWithSession(<DashboardPage />, session);
    expect(await screen.findByText(/No alerts were ingested in this window/)).toBeInTheDocument();
  });
});
