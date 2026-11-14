import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createRef } from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import type { BulkItemIn, EscalationOut } from '../../api/types';
import type { VirtualTableApi } from '../../components/VirtualTable';
import { readUserPref, writeUserPref } from '../../lib/prefs';
import { apiError, fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import QueuePage from './QueuePage';
import { QueueTable, type QueueSelection } from './QueueTable';

const inSeconds = (s: number) => new Date(Date.now() + s * 1000).toISOString();

function escalation(id: string, overrides: Partial<EscalationOut> = {}): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `alert-${id}`,
    level: 'L1',
    status: 'open',
    reason: 'assessment in the grey zone',
    priority: 50,
    summary: { title: `Item ${id}` },
    assigned_to: null,
    sla_deadline: inSeconds(3_600),
    version: 3,
    created_at: inSeconds(-600),
    updated_at: inSeconds(-600),
    alert_severity: 'medium',
    routing: { code: 'grey_zone', confidence: 42 },
    ...overrides,
  };
}

/** Five items in deadline order: one overdue, one inside ten minutes, one inside fifteen, two later. */
const items = () => [
  escalation('a', { sla_deadline: inSeconds(-252), alert_severity: 'critical', routing: { code: 'response_review' }, ai_reason: 'The dump was written from a PowerShell started by Word', ai_reason_source: 'model', assigned_to: 'u-1', status: 'claimed' }),
  escalation('b', { sla_deadline: inSeconds(310), alert_severity: 'high', entities_preview: { items: [{ kind: 'host', value: 'FS-02' }], counts: { host: 1 } } }),
  escalation('c', { sla_deadline: inSeconds(800), alert_severity: 'high', assigned_to: 'u-9', assigned_to_email: 't.brandt@acme.test', status: 'claimed' }),
  escalation('d', { sla_deadline: inSeconds(4_000), alert_severity: 'low' }),
  escalation('e', { sla_deadline: inSeconds(90_000), alert_severity: 'info', routing: null }),
];

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

type Handler = (method: string, path: string, body: unknown, query: Record<string, unknown>) => unknown;

async function renderQueue(rows: EscalationOut[] = items(), { role = 'analyst', route = '/queue', handler }: { role?: string; route?: string; handler?: Handler } = {}) {
  const { api, calls } = fakeApi((method, path, body) => {
    const query = (calls[calls.length - 1]?.query ?? {}) as Record<string, unknown>;
    const answer = handler?.(method, path, body, query);
    if (answer !== undefined) return answer;
    if (method === 'GET' && path === '/escalations') {
      const mine = query.assigned_to === 'me' ? rows.filter((e) => e.assigned_to === 'u-1') : query.assigned_to === 'none' ? rows.filter((e) => !e.assigned_to) : rows;
      return { items: mine, next_cursor: null };
    }
    if (path === '/auth/me') return { tenant_id: 'acme', tenant_name: 'Acme Corp' };
    return {};
  });
  const session = await signedInSession(api, { role, id: 'u-1' });
  const view = renderWithSession(
    <>
      <Routes>
        <Route path="/queue" element={<QueuePage />} />
        <Route path="/escalations/:id" element={<p>decision page</p>} />
      </Routes>
      <LocationProbe />
    </>,
    session,
    { route },
  );
  return { ...view, calls };
}

const grid = () => screen.getByRole('grid', { name: /^Work queue/ });
const row = (title: string) => within(grid()).getByRole('row', { name: new RegExp(`^${title},`) });
async function rows() {
  await screen.findByRole('row', { name: /^Item a,/ });
  return within(grid()).getAllByRole('row').slice(1);
}
const preview = () => screen.getByRole('complementary', { name: 'Preview of the highlighted row' });
const tab = (name: RegExp | string) => screen.getByRole('tab', { name });
const listQueries = (calls: Array<{ method: string; path: string; query?: unknown }>) =>
  calls.filter((c) => c.method === 'GET' && c.path === '/escalations').map((c) => c.query as Record<string, unknown>);

// jsdom lays nothing out: give elements a size so the windowed table renders its rows.
const sizes = { offsetHeight: 600, offsetWidth: 1024, clientHeight: 600, clientWidth: 1024 } as const;
const original = Object.keys(sizes).map((k) => Object.getOwnPropertyDescriptor(HTMLElement.prototype, k));
beforeAll(() => {
  for (const [k, v] of Object.entries(sizes)) Object.defineProperty(HTMLElement.prototype, k, { configurable: true, get: () => v });
});
afterAll(() => {
  Object.keys(sizes).forEach((k, i) => {
    const d = original[i];
    if (d) Object.defineProperty(HTMLElement.prototype, k, d);
    else Reflect.deleteProperty(HTMLElement.prototype, k);
  });
});
afterEach(() => window.localStorage.clear());

describe('the queue: what needs a person', () => {
  it('lists the waiting escalations soonest deadline first, with the same request as the Escalations page', async () => {
    const { calls } = await renderQueue();
    const all = await rows();
    expect(all.map((r) => r.getAttribute('aria-label')?.split(',')[0])).toEqual(['Item a', 'Item b', 'Item c', 'Item d', 'Item e']);
    expect(listQueries(calls)[0]).toMatchObject({ status: ['open', 'claimed', 'expired'], order: 'sla_deadline', limit: 50 });
    expect(screen.getByRole('heading', { name: 'Queue', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('5 items need a person. 1 is past the deadline and 1 passes it in the next 10 minutes.')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Filters' })).getByRole('status')).toHaveTextContent('5 rows');
  });

  it('says what needs you and why, with severity as bars and a word and the outcome so far', async () => {
    await renderQueue();
    await rows();
    const first = row('Item a');
    expect(within(first).getByRole('link', { name: 'Item a' })).toHaveAttribute('href', '/escalations/a');
    expect(first).toHaveTextContent('The planned response did not complete; a person decides what happens next. The dump was written from a PowerShell started by Word.');
    expect(first.querySelector('[data-severity="critical"]')).toHaveTextContent('critical');
    expect(first.querySelector('[data-outcome="threat"]')).toHaveTextContent('Likely malicious');
    expect(row('Item b').querySelector('[data-outcome="review"]')).toHaveTextContent('Not proven either way');
    expect(row('Item b')).toHaveTextContent('FS-02');
    // Before routing was recorded there is no outcome to show.
    expect(row('Item e').querySelector('[data-outcome]')).toBeNull();
    expect(first).toHaveTextContent('You');
    expect(row('Item c')).toHaveTextContent('t.brandt@acme.test');
    expect(row('Item b')).toHaveTextContent('Unassigned');
  });

  it('leaves the tenant column out and names the acting tenant as the scope', async () => {
    await renderQueue();
    await rows();
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['', 'Due in ↑, soonest first', 'Severity', 'What needs you, and why', 'Entity', 'Outcome so far', 'Owner']);
    expect(await screen.findByText('Acme Corp')).toBeInTheDocument();
  });

  it('marks overdue and nearly due deadlines in words, not by colour alone', async () => {
    await renderQueue();
    await rows();
    const overdue = row('Item a').querySelector('[data-due]') as HTMLElement;
    expect(overdue).toHaveAttribute('data-due', 'overdue');
    expect(overdue).toHaveTextContent(/^04:1\d over$/);
    expect(overdue).toHaveAttribute('title', expect.stringMatching(/^Overdue by 4m 1\ds$/));
    const soon = row('Item b').querySelector('[data-due]') as HTMLElement;
    expect(soon).toHaveAttribute('data-due', 'soon');
    expect(soon).toHaveTextContent(/^05:\d\d ! due soon$/);
    expect(row('Item d').querySelector('[data-due]')).toHaveAttribute('data-due', 'ok');
    expect(row('Item a')).toHaveAccessibleName(/Overdue by 4m/);
  });

  it('shows skeleton rows while loading, then an empty view that says where the rest went', async () => {
    let release: (v: unknown) => void = () => undefined;
    const gate = new Promise((r) => (release = r));
    await renderQueue([], { handler: (m, path) => (m === 'GET' && path === '/escalations' ? gate.then(() => ({ items: [], next_cursor: null })) : undefined) });
    expect(screen.getByText('Loading the queue')).toBeInTheDocument();
    release(null);
    expect(await screen.findByText(/Nothing in this view needs a person in/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('href', '/');
    expect(screen.getByText('Nothing needs a person right now.')).toBeInTheDocument();
    expect(screen.queryByRole('grid')).not.toBeInTheDocument();
    expect(tab(/^Needs a person/)).toHaveTextContent('Needs a person0');
  });

  it('shows the error with a retry', async () => {
    let fail = true;
    await renderQueue(items(), {
      handler: (m, path) => {
        if (m === 'GET' && path === '/escalations' && fail) throw apiError(503, 'unavailable', 'The service is not ready.');
        return undefined;
      },
    });
    const alert = (await screen.findByText('The service is not ready.')).closest('[role="alert"]') as HTMLElement;
    expect(screen.getByText('The queue could not be loaded.')).toBeInTheDocument();
    fail = false;
    await userEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('row', { name: /^Item a,/ })).toBeInTheDocument();
  });
});

describe('the queue: densities', () => {
  it('has three row heights and remembers the choice per user', async () => {
    const user = userEvent.setup();
    const first = await renderQueue();
    expect((await rows())[0].style.height).toBe('28px');
    const density = screen.getByRole('group', { name: 'Row density' });
    expect(within(density).getByRole('button', { name: 'Compact' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(within(density).getByRole('button', { name: 'Dense' }));
    expect((await rows())[0].style.height).toBe('24px');
    await user.click(within(density).getByRole('button', { name: 'Two lines' }));
    expect((await rows())[0].style.height).toBe('44px');
    expect(within(density).getByRole('button', { name: 'Two lines' })).toHaveAttribute('aria-pressed', 'true');
    expect(readUserPref('queue-density', 'u-1')).toBe('relaxed');
    expect(readUserPref('queue-density', 'u-2')).toBeNull();
    first.unmount();
    await renderQueue();
    expect((await rows())[0].style.height).toBe('44px');
  });

  it('fits at least 20 compact rows in the list of a 1440 by 900 window', async () => {
    // The e2e suite (triage.spec.ts) measures this in the real shell, where the list is 617 px high at
    // 1440 by 900. Here the list is 600 px (this file's stub): count the rows that lie wholly inside it.
    await renderQueue(Array.from({ length: 40 }, (_, i) => escalation(`n${String(i).padStart(2, '0')}`, { sla_deadline: inSeconds(1_000 + i) })));
    await screen.findByRole('row', { name: /^Item n00,/ });
    const inside = () =>
      within(grid())
        .getAllByRole('row')
        .slice(1)
        .filter((r) => Number(/translateY\((\d+)px\)/.exec(r.style.transform)?.[1]) + parseInt(r.style.height, 10) <= 600).length;
    expect(inside()).toBe(21);
    await userEvent.click(within(screen.getByRole('group', { name: 'Row density' })).getByRole('button', { name: 'Dense' }));
    await waitFor(() => expect(inside()).toBe(25));
  });

  it('stacks each item into a record on a narrow screen, without the column headers', async () => {
    const selection: QueueSelection = { enabled: true, isSelected: () => false, toggle: vi.fn(), setAll: vi.fn() };
    render(
      <MemoryRouter>
        <QueueTable
          rows={items()}
          now={Date.now()}
          density="compact"
          width={358}
          userId="u-1"
          selection={selection}
          onOpen={vi.fn()}
          onActiveChange={vi.fn()}
          onRowKeyDown={() => false}
          apiRef={createRef<VirtualTableApi>() as React.MutableRefObject<VirtualTableApi | null>}
          maxHeight="600px"
          autoLoad={false}
          hasMore={false}
          loadingMore={false}
          onLoadMore={vi.fn()}
        />
      </MemoryRouter>,
    );
    expect(screen.getAllByRole('columnheader')).toHaveLength(2);
    const first = screen.getByRole('row', { name: /^Item a,/ });
    expect(first.style.height).toBe('92px');
    expect(first).toHaveTextContent('Item a');
    expect(first.querySelector('[data-due="overdue"]')).not.toBeNull();
    expect(first.querySelector('[data-severity="critical"]')).not.toBeNull();
    await userEvent.click(within(first).getByRole('checkbox', { name: 'Select Item a' }));
    expect(selection.toggle).toHaveBeenCalledWith(expect.objectContaining({ id: 'a' }));
  });
});

describe('the queue: preview', () => {
  it('shows the highlighted row beside the list and keeps the essential columns', async () => {
    await renderQueue();
    await rows();
    const pane = preview();
    expect(within(pane).getByRole('heading', { name: 'Item a', level: 2 })).toBeInTheDocument();
    expect(pane).toHaveTextContent('Needs your decision: likely malicious');
    expect(pane).toHaveTextContent('The dump was written from a PowerShell started by Word');
    expect(pane).toHaveTextContent('Written by the model.');
    expect(pane).toHaveTextContent('The planned response did not complete');
    expect(pane).toHaveTextContent(/Overdue by 4m/);
    expect(within(pane).getByRole('link', { name: 'Open Enter' })).toHaveAttribute('href', '/escalations/a');
    // Already yours: nothing to claim.
    expect(within(pane).queryByRole('button', { name: /Claim/ })).not.toBeInTheDocument();
  });

  it('hides with the Preview button and with Space, and comes back', async () => {
    const user = userEvent.setup();
    await renderQueue();
    await rows();
    const toggle = screen.getByRole('button', { name: 'Preview Space' });
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await user.click(toggle);
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    toggle.blur();
    await user.keyboard(' ');
    expect(preview()).toBeInTheDocument();
    await user.keyboard(' ');
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });

  it('is left out in a window too narrow for it', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({ matches: !/min-width: 1180px/.test(query), media: query, addEventListener: () => undefined, removeEventListener: () => undefined }));
    await renderQueue();
    await rows();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Preview Space' })).not.toBeInTheDocument();
    vi.unstubAllGlobals();
  });

  it('claims the highlighted row from the preview', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(items(), { handler: (m, path) => (m === 'POST' && path === '/escalations/b/claim' ? escalation('b', { assigned_to: 'u-1' }) : undefined) });
    await rows();
    await user.keyboard('j');
    await waitFor(() => expect(within(preview()).getByRole('heading', { level: 2 })).toHaveTextContent('Item b'));
    await user.click(within(preview()).getByRole('button', { name: 'Claim C' }));
    await waitFor(() => expect(calls.find((c) => c.method === 'POST')).toMatchObject({ path: '/escalations/b/claim', body: { version: 3 } }));
    expect(await screen.findByText('Claimed: Item b. It is in Mine.')).toBeInTheDocument();
  });
});

describe('the queue: keyboard', () => {
  it('J and K move the cursor, the preview follows, Enter opens the item', async () => {
    const user = userEvent.setup();
    await renderQueue();
    const [a, b, c] = await rows();
    expect(a).toHaveAttribute('tabindex', '0');
    // From anywhere on the page: nothing needs focus first.
    await user.keyboard('j');
    await waitFor(() => expect(b).toHaveFocus());
    expect(within(preview()).getByRole('heading', { level: 2 })).toHaveTextContent('Item b');
    await user.keyboard('J');
    await waitFor(() => expect(c).toHaveFocus());
    await user.keyboard('k');
    await waitFor(() => expect(b).toHaveFocus());
    await user.keyboard('{ArrowUp}');
    await waitFor(() => expect(a).toHaveFocus());
    await user.keyboard('k');
    await waitFor(() => expect(a).toHaveAttribute('tabindex', '0'));
    await user.keyboard('j{Enter}');
    expect(await screen.findByText('decision page')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations/b');
  });

  it('Enter opens the highlighted row even when no row has focus', async () => {
    const user = userEvent.setup();
    await renderQueue();
    await rows();
    await user.keyboard('{Enter}');
    expect(await screen.findByText('decision page')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations/a');
  });

  it('Space shows and hides the preview from a focused row, without opening it', async () => {
    const user = userEvent.setup();
    await renderQueue();
    const [a] = await rows();
    a.focus();
    await user.keyboard(' ');
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/queue');
    await user.keyboard(' ');
    expect(preview()).toBeInTheDocument();
  });

  it('X selects the highlighted row and the bulk bar replaces the filters', async () => {
    const user = userEvent.setup();
    await renderQueue();
    const [a, b] = await rows();
    await user.keyboard('x');
    expect(a).toHaveAttribute('aria-selected', 'true');
    const bar = screen.getByRole('region', { name: 'Bulk actions' });
    expect(bar).toHaveTextContent('1 selected');
    expect(bar).toHaveTextContent('Open the row to decide it.');
    expect(screen.queryByRole('region', { name: 'Filters' })).not.toBeInTheDocument();
    await user.keyboard('jx');
    await waitFor(() => expect(b).toHaveAttribute('aria-selected', 'true'));
    expect(bar).toHaveTextContent('2 selected');
    expect(bar).toHaveTextContent('Bulk decide is offered only for look-alikes. These rows differ, so each needs its own decision.');
    expect(within(bar).queryByRole('button', { name: /Decide all/ })).not.toBeInTheDocument();
    await user.keyboard('x');
    expect(b).toHaveAttribute('aria-selected', 'false');
    await user.click(within(bar).getByRole('button', { name: 'Clear' }));
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Filters' })).toBeInTheDocument();
  });

  it('leaves the letters alone while typing in a field', async () => {
    const user = userEvent.setup();
    await renderQueue();
    const [a] = await rows();
    await user.click(screen.getByRole('button', { name: '+ Save view' }));
    await user.type(screen.getByRole('textbox', { name: 'Name of the view' }), 'jkx ');
    expect(a).toHaveAttribute('tabindex', '0');
    expect(a).toHaveAttribute('aria-selected', 'false');
    expect(preview()).toBeInTheDocument();
  });

  it('acts on the cursor, not on the row that still has focus, when keys arrive within one frame', async () => {
    // Focus follows the cursor an animation frame later. Keys queued behind a busy page arrive back to back,
    // before that frame: each must still move, select and open from where the cursor is.
    const { calls } = await renderQueue(items(), { handler: (m, path) => (m === 'POST' && path === '/escalations/bulk/claim' ? { succeeded: 2, failed: 0, results: [] } : undefined) });
    const [a, b, c, d] = await rows();
    a.focus();
    for (const key of ['j', 'x', 'j', 'j', 'x']) fireEvent.keyDown(a, { key });
    expect(a).toHaveFocus();
    expect([a, b, c, d].map((r) => r.getAttribute('aria-selected'))).toEqual(['false', 'true', 'false', 'true']);
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('2 selected');
    expect(within(preview()).getByRole('heading', { level: 2 })).toHaveTextContent('Item d');
    // C right after the last X claims the two selected rows, not the cursor row alone.
    fireEvent.keyDown(a, { key: 'x' });
    fireEvent.keyDown(a, { key: 'x' });
    fireEvent.keyDown(a, { key: 'c' });
    await waitFor(() => expect(calls.find((call) => call.method === 'POST')).toMatchObject({ path: '/escalations/bulk/claim', body: { items: [{ escalation_id: 'b', version: 3 }, { escalation_id: 'd', version: 3 }] } }));
    await waitFor(() => expect(d).toHaveFocus());
    // Enter opens the cursor row as well.
    fireEvent.keyDown(d, { key: 'k' });
    fireEvent.keyDown(d, { key: 'Enter' });
    expect(await screen.findByText('decision page')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/escalations/c');
  });

  it('claims the selected rows in one request with C, and reports each result', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(items(), {
      handler: (m, path, body) => {
        if (m !== 'POST' || path !== '/escalations/bulk/claim') return undefined;
        const sent = (body as { items: BulkItemIn[] }).items;
        return { succeeded: 1, failed: 1, results: [{ escalation_id: sent[0].escalation_id, ok: true }, { escalation_id: sent[1].escalation_id, ok: false, error: { status: 409, code: 'conflict', message: 'Changed by someone else.' } }] };
      },
    });
    await rows();
    await user.keyboard('jxjjxc');
    await waitFor(() => expect(calls.find((c) => c.method === 'POST')).toMatchObject({ path: '/escalations/bulk/claim', body: { items: [{ escalation_id: 'b', version: 3 }, { escalation_id: 'd', version: 3 }] } }));
    const status = await screen.findByText('Claim: 1 succeeded, 1 failed');
    expect(status.closest('[role="status"]')).toHaveTextContent('Item d: Changed by someone else.');
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
  });

  it('gives a viewer the list and the preview but nothing to select or claim', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue(items(), { role: 'viewer' });
    const [a] = await rows();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    await user.keyboard('xc');
    expect(a).not.toHaveAttribute('aria-selected');
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST')).toEqual([]);
    expect(screen.getByRole('note', { name: 'Keyboard' })).not.toHaveTextContent('select');
    await user.keyboard('j');
    await waitFor(() => expect(within(preview()).getByRole('heading', { level: 2 })).toHaveTextContent('Item b'));
    expect(within(preview()).queryByRole('button', { name: /Claim/ })).not.toBeInTheDocument();
  });

  it('selects every row from the header checkbox', async () => {
    const user = userEvent.setup();
    await renderQueue();
    await rows();
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows' }));
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('5 selected');
    await user.click(screen.getByRole('checkbox', { name: 'Select Item a' }));
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('4 selected');
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows' }));
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows' }));
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
  });
});

describe('the queue: views', () => {
  it('counts each view and hides Look-alikes while the API sends no grouping', async () => {
    await renderQueue();
    await rows();
    const names = within(screen.getByRole('tablist', { name: 'Saved views' })).getAllByRole('tab').map((t) => t.textContent);
    expect(names).toEqual(['Needs a person5', 'Mine1', 'Unassigned3', 'Deadline under 15 min3', 'Likely malicious1']);
    expect(tab(/^Needs a person/)).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tabpanel')).toHaveAccessibleName(/^Needs a person/);
  });

  it('shows Look-alikes, the count on the row and bulk decide once rows carry a group', async () => {
    const user = userEvent.setup();
    const grouped = (id: string) => ({ ...escalation(id, { sla_deadline: inSeconds(2_000) }), group_id: 'g-1', group_size: 9 }) as EscalationOut;
    await renderQueue([...items(), grouped('g1'), grouped('g2')]);
    await rows();
    await user.click(tab(/^Look-alikes/));
    expect(tab(/^Look-alikes/)).toHaveTextContent('Look-alikes2');
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1)).toHaveLength(2));
    expect(row('Item g1')).toHaveTextContent('×9 look-alikes');
    expect(preview()).toHaveTextContent('9 alerts: same rule, same source, same finding');
    await user.keyboard('xjx');
    const bar = await screen.findByRole('region', { name: 'Bulk actions' });
    await waitFor(() => expect(bar).toHaveTextContent('2 selected'));
    expect(bar).toHaveTextContent('Look-alikes: same rule, same source, same finding.');
    await user.click(within(bar).getByRole('button', { name: 'Decide all 2…' }));
    expect(await screen.findByRole('dialog', { name: 'Close 2 escalations' })).toBeInTheDocument();
  });

  it('asks the API for Mine and Unassigned, and filters the loaded rows for the others', async () => {
    const user = userEvent.setup();
    const { calls } = await renderQueue();
    await rows();
    await user.click(tab(/^Mine/));
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1)).toHaveLength(1));
    expect(listQueries(calls).at(-1)).toMatchObject({ assigned_to: 'me', order: 'sla_deadline' });
    expect(screen.getByTestId('location')).toHaveTextContent('/queue?view=mine');
    await user.click(tab(/^Unassigned/));
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1)).toHaveLength(3));
    expect(listQueries(calls).at(-1)).toMatchObject({ assigned_to: 'none' });
    const before = listQueries(calls).length;
    await user.click(tab(/^Deadline under 15 min/));
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1).map((r) => r.getAttribute('aria-label')?.split(',')[0])).toEqual(['Item a', 'Item b', 'Item c']));
    await user.click(tab(/^Likely malicious/));
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1)).toHaveLength(1));
    expect(listQueries(calls)).toHaveLength(before);
    // Left and Right move between the tabs.
    await user.keyboard('{ArrowLeft}');
    expect(tab(/^Deadline under 15 min/)).toHaveAttribute('aria-selected', 'true');
    expect(tab(/^Deadline under 15 min/)).toHaveFocus();
  });

  it('filters by the severity and outcome chips, in the URL', async () => {
    const user = userEvent.setup();
    await renderQueue(items(), { route: '/queue?severity=high' });
    await screen.findByRole('row', { name: /^Item b,/ });
    expect(within(grid()).getAllByRole('row').slice(1)).toHaveLength(2);
    expect(within(screen.getByRole('region', { name: 'Filters' })).getByRole('status')).toHaveTextContent('2 rows');
    await user.click(screen.getByRole('button', { name: /^Outcome:/ }));
    await user.click(screen.getByRole('option', { name: 'Likely malicious' }));
    expect(screen.getByTestId('location')).toHaveTextContent('/queue?severity=high&outcome=threat');
    expect(await screen.findByText(/Nothing in this view needs a person in/)).toBeInTheDocument();
  });

  it('saves a view per user in the browser, opens it with its chips and density, and removes it', async () => {
    const user = userEvent.setup();
    const first = await renderQueue(items(), { route: '/queue?view=unassigned&severity=high' });
    await screen.findByRole('row', { name: /^Item b,/ });
    await user.click(within(screen.getByRole('group', { name: 'Row density' })).getByRole('button', { name: 'Dense' }));
    await user.click(screen.getByRole('button', { name: '+ Save view' }));
    await user.type(screen.getByRole('textbox', { name: 'Name of the view' }), 'High, unclaimed{Enter}');
    const saved = await screen.findByRole('tab', { name: 'High, unclaimed' });
    expect(saved).toHaveAttribute('aria-selected', 'true');
    expect(JSON.parse(readUserPref('queue-views', 'u-1') ?? '[]')).toEqual([expect.objectContaining({ name: 'High, unclaimed', base: 'unassigned', severity: ['high'], outcome: [], density: 'dense' })]);
    expect(readUserPref('queue-views', 'u-2')).toBeNull();
    first.unmount();

    // A later visit: the view is there, and opening it applies what was saved.
    writeUserPref('queue-density', 'u-1', 'compact');
    await renderQueue();
    await rows();
    await user.click(screen.getByRole('tab', { name: 'High, unclaimed' }));
    await waitFor(() => expect(within(grid()).getAllByRole('row').slice(1).map((r) => r.getAttribute('aria-label')?.split(',')[0])).toEqual(['Item b']));
    expect(within(grid()).getAllByRole('row')[1].style.height).toBe('24px');
    expect(screen.getByRole('button', { name: /^Severity:/ })).toHaveTextContent('High');
    await user.click(screen.getByRole('button', { name: 'Remove view' }));
    expect(screen.queryByRole('tab', { name: 'High, unclaimed' })).not.toBeInTheDocument();
    expect(readUserPref('queue-views', 'u-1')).toBe('[]');
    expect(tab(/^Needs a person/)).toHaveAttribute('aria-selected', 'true');
  });

  it('survives a browser that refuses storage', async () => {
    const user = userEvent.setup();
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    await renderQueue();
    await rows();
    await user.click(within(screen.getByRole('group', { name: 'Row density' })).getByRole('button', { name: 'Dense' }));
    expect((await rows())[0].style.height).toBe('24px');
    await user.click(screen.getByRole('button', { name: '+ Save view' }));
    await user.type(screen.getByRole('textbox', { name: 'Name of the view' }), 'Kept for now{Enter}');
    expect(await screen.findByRole('tab', { name: 'Kept for now' })).toBeInTheDocument();
    get.mockRestore();
    set.mockRestore();
  });

  it('says "at least" and offers more when the server holds more rows than are loaded', async () => {
    const user = userEvent.setup();
    const page1 = Array.from({ length: 50 }, (_, i) => escalation(`p${String(i).padStart(2, '0')}`, { sla_deadline: inSeconds(2_000 + i) }));
    const { calls } = await renderQueue(page1, {
      handler: (m, path, _b, query) => {
        if (m === 'GET' && path === '/escalations') return query.cursor ? { items: [escalation('last', { sla_deadline: inSeconds(9_000) })], next_cursor: null } : { items: page1, next_cursor: 'c2' };
        if (path.startsWith('/dashboard')) return { unassigned_escalations: 61, my_claimed: 4 };
        return undefined;
      },
    });
    await screen.findByRole('row', { name: /^Item p00,/ });
    expect(screen.getByText('More than 50 items need a person. No deadline in the next 10 minutes.')).toBeInTheDocument();
    expect(tab(/^Needs a person/)).toHaveTextContent('Needs a person50+');
    await waitFor(() => expect(tab(/^Unassigned/)).toHaveTextContent('Unassigned61'));
    expect(tab(/^Mine/)).toHaveTextContent('Mine4');
    expect(screen.getByText('The first 50 items by deadline are loaded.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(tab(/^Needs a person/)).toHaveTextContent('Needs a person51'));
    expect(listQueries(calls).at(-1)).toMatchObject({ cursor: 'c2' });
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });
});
