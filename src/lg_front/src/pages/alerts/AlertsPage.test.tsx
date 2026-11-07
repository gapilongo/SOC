import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { createApiClient } from '../../api/client';
import { endpoints } from '../../api/endpoints';
import type { AlertDetailOut, AlertOut, LiveEvent } from '../../api/types';
import { writePref } from '../../lib/prefs';
import { LiveContext, type LiveListener } from '../../live/LiveProvider';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import AlertsPage, { filtersFromParams } from './AlertsPage';
import { startOfToday } from './views';

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

export function alertRow(id: string, overrides: Partial<AlertOut> = {}): AlertOut {
  return {
    id,
    tenant_id: 'acme',
    source_id: 'entra',
    source_alert_id: `src-${id}`,
    fingerprint: `fp-${id}`,
    title: `Alert ${id}`,
    severity: 'high',
    status: 'waiting_human',
    occurred_at: minutesAgo(10),
    ingested_at: minutesAgo(9),
    updated_at: minutesAgo(9),
    summary: {},
    ...overrides,
  };
}

const ROWS: AlertOut[] = [
  alertRow('a-1', {
    title: 'Unusual sign-in pattern',
    source_name: 'Entra ID',
    confidence: 42,
    summary: { analysis: { verdict: 'inconclusive' } },
    entities_preview: { items: [{ kind: 'user', value: 'j.moreau@acme.example' }, { kind: 'ip', value: '185.220.101.4' }], counts: { user: 1, ip: 3 } },
  }),
  alertRow('a-2', { title: 'Phishing link clicked', severity: 'medium', source_id: 'm365', source_name: null }),
  alertRow('a-3', { title: 'Impossible travel', severity: 'low', status: 'closed', disposition: 'benign' }),
];

function detailOf(row: AlertOut, extra: Partial<AlertDetailOut> = {}): AlertDetailOut {
  return { ...row, normalized: {}, findings: [], ...extra };
}

function handler(rows: AlertOut[] = ROWS) {
  return (method: string, path: string) => {
    if (method === 'GET' && path === '/alerts/counts') {
      return { by_status: { waiting_human: 103, waiting_approval: 1, queued: 2, processing: 1, failed: 0, closed: 4 }, closed_from: startOfToday(), generated_at: minutesAgo(0) };
    }
    if (method === 'GET' && path === '/alerts') return { items: rows, next_cursor: null };
    const detail = rows.find((r) => path === `/alerts/${r.id}`);
    if (method === 'GET' && detail) return detailOf(detail);
    if (method === 'GET' && /^\/alerts\/[^/]+\/events$/.test(path)) return { items: [], next_cursor: null };
    if (method === 'GET' && path === '/actions') return { items: [], next_cursor: null };
    if (method === 'GET' && path === '/tickets') return [];
    if (method === 'GET' && path === '/sources') return [{ id: 'splunk', name: 'Splunk prod' }];
    throw new Error(`unexpected ${method} ${path}`);
  };
}

/** Shows the router location, so tests can read the URL the page wrote. */
function Location() {
  const loc = useLocation();
  return <output data-testid="location">{loc.search}</output>;
}
const search = () => new URLSearchParams(screen.getByTestId('location').textContent ?? '');

type Calls = ReturnType<typeof fakeApi>['calls'];
const listCalls = (calls: Calls) => calls.filter((c) => c.path === '/alerts');
const lastListQuery = (calls: Calls) => listCalls(calls).at(-1)?.query as Record<string, unknown> | undefined;

async function renderPage(route = '/alerts', opts: { rows?: AlertOut[]; role?: string; wrap?: (ui: ReactNode) => ReactNode } = {}) {
  const fake = fakeApi(handler(opts.rows));
  const session = await signedInSession(fake.api, { role: opts.role ?? 'analyst' });
  const ui = (
    <>
      <AlertsPage />
      <Location />
    </>
  );
  const utils = renderWithSession(<>{opts.wrap ? opts.wrap(ui) : ui}</>, session, { route });
  return { ...utils, calls: fake.calls };
}

function grid() {
  return screen.getByRole('grid', { name: 'Alerts' });
}

async function rows() {
  await screen.findByRole('row', { name: /Unusual sign-in pattern/ });
  return within(grid()).getAllByRole('row').slice(1);
}

afterEach(() => writePref('density', 'compact'));

// jsdom lays nothing out: give elements a size so the virtualized grid renders its rows.
const sizes = ['offsetHeight', 'offsetWidth'] as const;
const saved = sizes.map((k) => Object.getOwnPropertyDescriptor(HTMLElement.prototype, k));
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, get: () => 600 });
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, get: () => 1024 });
});
afterAll(() => {
  sizes.forEach((k, i) => {
    const d = saved[i];
    if (d) Object.defineProperty(HTMLElement.prototype, k, d);
  });
});

describe('AlertsPage view tabs', () => {
  it('opens Needs analyst with every tab counted from one counts request', async () => {
    const { calls } = await renderPage();
    const nav = screen.getByRole('navigation', { name: 'Alert views' });
    const needs = await within(nav).findByRole('link', { name: 'Needs analyst 103 alerts' });
    expect(needs).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'Awaiting approval 1 alert' })).not.toHaveAttribute('aria-current');
    expect(within(nav).getByRole('link', { name: 'Processing 3 alerts' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Failed 0 alerts' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Closed today 4 alerts' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'All' })).toBeInTheDocument();
    expect(calls.filter((c) => c.path === '/alerts/counts')).toHaveLength(1);
    expect(calls.find((c) => c.path === '/alerts/counts')?.query).toEqual({ closed_from: startOfToday() });
    await waitFor(() => expect(lastListQuery(calls)).toMatchObject({ status: ['waiting_human'] }));
  });

  it('lists the closed-today window on Closed today, and every status on All, without another counts request', async () => {
    const { calls } = await renderPage();
    const nav = screen.getByRole('navigation', { name: 'Alert views' });
    await userEvent.click(await within(nav).findByRole('link', { name: /^Closed today/ }));
    await waitFor(() => expect(lastListQuery(calls)).toMatchObject({ status: ['closed'], closed_from: startOfToday() }));
    expect(search().get('view')).toBe('closed');
    expect(within(nav).getByRole('link', { name: /^Closed today/ })).toHaveAttribute('aria-current', 'page');

    await userEvent.click(within(nav).getByRole('link', { name: 'All' }));
    await waitFor(() => expect(lastListQuery(calls)?.status).toBeUndefined());
    expect(calls.filter((c) => c.path === '/alerts/counts')).toHaveLength(1);
    // The status filter is a chip of the All view only.
    expect(screen.getByRole('button', { name: /^Status:/ })).toBeInTheDocument();
  });

  it('opens an overview link (filters, no view) on All with its filters', async () => {
    const { calls } = await renderPage('/alerts?status=waiting_approval&severity=high');
    const nav = screen.getByRole('navigation', { name: 'Alert views' });
    expect(within(nav).getByRole('link', { name: 'All' })).toHaveAttribute('aria-current', 'page');
    await waitFor(() => expect(lastListQuery(calls)).toMatchObject({ status: ['waiting_approval'], severity: ['high'] }));
    expect(screen.getByRole('button', { name: /^Status:/ })).toHaveTextContent('Waiting for approval');
    expect(screen.getByRole('button', { name: /^Severity:/ })).toHaveTextContent('High');
  });

  it('labels a custom closing window "Closed"', async () => {
    const { calls } = await renderPage('/alerts?view=closed&closed_from=2026-11-01T00:00:00.000Z');
    expect(await screen.findByRole('link', { name: /^Closed \d/ })).toHaveAttribute('aria-current', 'page');
    await waitFor(() => expect(lastListQuery(calls)).toMatchObject({ closed_from: '2026-11-01T00:00:00.000Z' }));
    expect(calls.find((c) => c.path === '/alerts/counts')?.query).toEqual({ closed_from: '2026-11-01T00:00:00.000Z' });
  });
});

describe('AlertsPage rows and filters', () => {
  it('shows severity, title, entities, source, AI verdict, status and age on each row', async () => {
    await renderPage();
    const [first, second] = await rows();
    expect(first).toHaveAccessibleName('high alert: Unusual sign-in pattern, status waiting human');
    expect(within(first).getByText('Unusual sign-in pattern')).toBeInTheDocument();
    expect(within(first).getByText('j.moreau@acme.example · 185.220.101.4 · +2 more')).toBeInTheDocument();
    expect(within(first).getByText('Entra ID')).toBeInTheDocument();
    expect(within(first).getByText('Inconclusive')).toBeInTheDocument();
    expect(within(first).getByText('42%')).toBeInTheDocument();
    expect(within(first).getByText('Needs analyst')).toBeInTheDocument();
    expect(within(first).getByText('9 min ago')).toBeInTheDocument();
    // No source name: the id; no verdict: a dash.
    expect(within(second).getByText('m365')).toBeInTheDocument();
    expect(within(second).getByText('-')).toBeInTheDocument();
  });

  it('follows the density preference: comfortable rows are taller and put the entities under the title', async () => {
    writePref('density', 'comfortable');
    await renderPage();
    const [first] = await rows();
    expect(first.style.height).toBe('56px');
    const entities = within(first).getByText(/j\.moreau@acme\.example/);
    expect(entities.tagName).toBe('DIV');
  });

  it('moves the selection with the arrow keys and opens the focused row with Enter', async () => {
    await renderPage();
    const [first, second] = await rows();
    first.focus();
    await userEvent.keyboard('{ArrowDown}');
    await waitFor(() => expect(second).toHaveFocus());
    await userEvent.keyboard('{ArrowUp}');
    await waitFor(() => expect(first).toHaveFocus());
    await userEvent.keyboard('{ArrowDown}');
    await waitFor(() => expect(second).toHaveFocus());
    await userEvent.keyboard('{Enter}');
    expect(await screen.findByRole('complementary', { name: 'Phishing link clicked' })).toBeInTheDocument();
    expect(search().get('alert')).toBe('a-2');
    expect(within(grid()).getByRole('row', { name: /Phishing link clicked/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('writes the filter chips and the search to the URL, pinning the view', async () => {
    const { calls } = await renderPage();
    await rows();
    await userEvent.click(screen.getByRole('button', { name: /^Severity:/ }));
    await userEvent.click(screen.getByRole('option', { name: 'High' }));
    await userEvent.keyboard('{Escape}');
    expect(search().getAll('severity')).toEqual(['high']);
    expect(search().get('view')).toBe('needs_analyst');
    await waitFor(() => expect(lastListQuery(calls)).toMatchObject({ status: ['waiting_human'], severity: ['high'] }));

    await userEvent.click(screen.getByRole('button', { name: /^Verdict:/ }));
    await userEvent.click(screen.getByRole('option', { name: 'Malicious' }));
    await userEvent.keyboard('{Escape}');
    expect(search().getAll('disposition')).toEqual(['malicious']);

    // Sources come from the loaded rows for an analyst (the sources API is admin-only).
    await userEvent.click(screen.getByRole('button', { name: /^Source:/ }));
    expect(screen.getByRole('option', { name: 'Entra ID' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('option', { name: 'm365' }));
    expect(search().get('source_id')).toBe('m365');
    expect(calls.some((c) => c.path === '/sources')).toBe(false);

    await userEvent.type(screen.getByRole('searchbox', { name: 'Search titles' }), 'sign-in{Enter}');
    expect(search().get('q')).toBe('sign-in');

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-11-01T08:00' } });
    expect(search().get('from')).toBe(new Date('2026-11-01T08:00').toISOString());

    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    for (const k of ['severity', 'disposition', 'source_id', 'q', 'from']) expect(search().has(k)).toBe(false);
    expect(screen.getByRole('searchbox', { name: 'Search titles' })).toHaveValue('');
  });

  it('offers an admin every source', async () => {
    await renderPage('/alerts', { role: 'admin' });
    await rows();
    await userEvent.click(screen.getByRole('button', { name: /^Source:/ }));
    expect(await screen.findByRole('option', { name: 'Splunk prod' })).toBeInTheDocument();
  });

  it('says when a view is empty', async () => {
    await renderPage('/alerts', { rows: [] });
    expect(await screen.findByText('No alerts in Needs analyst')).toBeInTheDocument();
  });
});

describe('AlertsPage side panel', () => {
  it('keeps the /alerts?alert=<id> deep link: the panel opens on that alert', async () => {
    const { calls } = await renderPage('/alerts?alert=a-3');
    const panel = await screen.findByRole('complementary', { name: 'Impossible travel' });
    expect(within(panel).getByText('Benign')).toBeInTheDocument();
    expect(calls.some((c) => c.path === '/alerts/a-3')).toBe(true);
    // The deep link does not change the view.
    expect(screen.getByRole('link', { name: /^Needs analyst/ })).toHaveAttribute('aria-current', 'page');
  });

  it('closes with the close button or Escape, and returns focus to the row', async () => {
    await renderPage('/alerts?alert=a-1');
    const panel = await screen.findByRole('complementary', { name: 'Unusual sign-in pattern' });
    await userEvent.click(within(panel).getByRole('button', { name: 'Close alert details' }));
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(search().has('alert')).toBe(false);
    expect(within(grid()).getByRole('row', { name: /Unusual sign-in pattern/ })).toHaveFocus();

    await userEvent.click(within(grid()).getByRole('row', { name: /Phishing link clicked/ }));
    const next = await screen.findByRole('complementary', { name: 'Phishing link clicked' });
    within(next).getByRole('heading', { name: 'Phishing link clicked' }).focus();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });

  it('does not claim on open: there is no claim request until Claim is pressed', async () => {
    const { calls } = await renderPage('/alerts?alert=a-1');
    await screen.findByRole('complementary', { name: 'Unusual sign-in pattern' });
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});

describe('AlertsPage new alerts pill', () => {
  function bus() {
    const listeners = new Set<LiveListener>();
    return {
      value: { status: 'open' as const, subscribe: (l: LiveListener) => (listeners.add(l), () => void listeners.delete(l)) },
      emit: (event: Partial<LiveEvent>) =>
        act(() => {
          for (const l of listeners) l({ type: 'alert.created', tenant_id: 'acme', alert_id: 'x', data: {}, ts: minutesAgo(0), ...event } as LiveEvent);
        }),
    };
  }

  it('counts alert.created events since the list loaded and reloads the list on click', async () => {
    const live = bus();
    const { calls } = await renderPage('/alerts?view=all&severity=high', {
      wrap: (ui) => <LiveContext.Provider value={live.value}>{ui}</LiveContext.Provider>,
    });
    await rows();
    expect(screen.queryByRole('button', { name: /new alert/ })).not.toBeInTheDocument();
    live.emit({ data: { severity: 'high' } });
    expect(screen.getByRole('button', { name: '1 new alert: reload the list' })).toBeInTheDocument();
    live.emit({ data: { severity: 'high' } });
    // Other event types and alerts outside the severity filter do not count.
    live.emit({ type: 'alert.updated', data: { severity: 'high' } });
    live.emit({ data: { severity: 'low' } });
    const pill = screen.getByRole('button', { name: '2 new alerts: reload the list' });
    const before = listCalls(calls).length;
    await userEvent.click(pill);
    await waitFor(() => expect(listCalls(calls).length).toBe(before + 1));
    await waitFor(() => expect(screen.queryByRole('button', { name: /new alert/ })).not.toBeInTheDocument());
  });
});

describe('alert filters in the URL', () => {
  it('reads alert filters from the URL, keeping multi-valued parameters', () => {
    const f = filtersFromParams(new URLSearchParams('status=queued&status=failed&severity=high&q=mimikatz&from=2026-09-01T00:00:00.000Z'));
    expect(f).toEqual({ status: ['queued', 'failed'], severity: ['high'], q: 'mimikatz', from: '2026-09-01T00:00:00.000Z' });
  });
  it('sends at most one source_id, as the API filters on a single source', () => {
    const f = filtersFromParams(new URLSearchParams('source_id=splunk-prod&source_id=wazuh-dc'));
    expect(f.source_id).toBe('splunk-prod');
    expect(filtersFromParams(new URLSearchParams('source_id=%20')).source_id).toBeUndefined();
  });
  it('puts exactly one source_id in the alerts request', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ items: [], next_cursor: null }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const api = createApiClient({ baseUrl: '/api/v1', auth: { getToken: () => 't', refresh: async () => null, actingTenant: () => null }, fetchImpl });
    await endpoints.alerts(api, filtersFromParams(new URLSearchParams('source_id=a&source_id=b&severity=high&severity=low')));
    const url = new URL(String((fetchImpl.mock.calls[0] as unknown[])[0]), 'https://soc.example');
    expect(url.searchParams.getAll('source_id')).toEqual(['a']);
    expect(url.searchParams.getAll('severity')).toEqual(['high', 'low']);
  });
});
