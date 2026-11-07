import { fireEvent, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { OnboardingStatusOut } from '../api/types';
import { OnboardingBanner } from './onboarding/Onboarding';
import { fakeApi, renderWithSession, signedInSession } from '../test/helpers';
import GettingStartedPage from './GettingStartedPage';
import { retentionPatch } from './settings/ReviewSections';

function status(overrides: Partial<OnboardingStatusOut> = {}): OnboardingStatusOut {
  return {
    tenant_id: 'acme',
    steps: [
      { id: 'source_connected', done: true, available: true },
      { id: 'notifications_configured', done: false, available: false },
      { id: 'teammate_invited', done: false, available: true },
      { id: 'autonomy_reviewed', done: false, available: true },
      { id: 'first_alert_triaged', done: false, available: true },
    ],
    completed: 1,
    total: 4,
    complete: false,
    dismissed: false,
    samples_sent: false,
    first_verdict: false,
    ...overrides,
  };
}

describe('getting started', () => {
  it('lists the available steps with links and sends the sample alerts', async () => {
    const { api, calls } = fakeApi((_method, path) => {
      if (path === '/onboarding/sample-alerts') return { source_id: 'demo:samples', received: 5, inserted: 5, duplicates: 0, enqueued: 5, alert_ids: [] };
      if (path === '/onboarding/autonomy-reviewed') return status({ completed: 2 });
      return status();
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<GettingStartedPage />, session);

    expect(await screen.findByText('Checklist: 1 of 4 done')).toBeInTheDocument();
    expect(screen.getByText('Connect an alert source')).toHaveTextContent('(done)');
    expect(screen.queryByText('Configure notifications')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open users' })).toHaveAttribute('href', '/users');
    expect(screen.getByRole('link', { name: 'Open settings' })).toHaveAttribute('href', '/settings');

    fireEvent.click(screen.getByRole('button', { name: 'Mark reviewed' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/onboarding/autonomy-reviewed')).toBe(true));
    fireEvent.click(screen.getByRole('button', { name: 'Send sample alerts' }));
    await waitFor(() => expect(calls.filter((c) => c.method === 'POST' && c.path === '/onboarding/sample-alerts')).toHaveLength(1));
    expect(await screen.findByText(/5 sample alerts sent/)).toBeInTheDocument();
  });

  it('shows the dashboard banner until it is dismissed', async () => {
    let current = status({ steps: [...status().steps.slice(0, 1), { id: 'notifications_configured', done: false, available: true }, ...status().steps.slice(2)], total: 5 });
    const { api, calls } = fakeApi((_m, path) => {
      if (path === '/onboarding/dismiss') current = { ...current, dismissed: true };
      return current;
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<OnboardingBanner />, session);
    expect(await screen.findByText('Getting started: 1 of 5 done')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Configure notifications' })).toHaveAttribute('href', '/integrations');
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss the getting started banner' }));
    await waitFor(() => expect(screen.queryByText(/Getting started:/)).not.toBeInTheDocument());
    expect(calls.some((c) => c.path === '/onboarding/dismiss')).toBe(true);
  });

  it('builds the retention patch within the install bounds', () => {
    const limits = { min_days: 7, max_days: 730 };
    expect(retentionPatch('30', '', limits)).toEqual({ retention: { alerts_days: 30, indicators_days: null } });
    expect(retentionPatch('3', '', limits)).toBeInstanceOf(Error);
    expect(retentionPatch('30', '731', limits)).toBeInstanceOf(Error);
    expect(retentionPatch('', '', limits)).toEqual({ retention: { alerts_days: null, indicators_days: null } });
  });
});
