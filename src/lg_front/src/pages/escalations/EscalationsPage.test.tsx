import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { createApiClient } from '../../api/client';
import type { EscalationOut, Page, TicketOut } from '../../api/types';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import EscalationsPage from './EscalationsPage';

function escalation(id: string, status: string, assigned: string | null): EscalationOut {
  return {
    id,
    tenant_id: 'acme',
    alert_id: `alert-${id}`,
    level: 'L2',
    status,
    reason: `reason ${id}`,
    priority: 50,
    summary: { title: `Escalation ${id}` },
    assigned_to: assigned,
    sla_deadline: '2099-01-01T00:00:00Z',
    version: 3,
    created_at: '2026-09-29T10:00:00Z',
    updated_at: '2026-09-29T10:00:00Z',
  };
}

function card(title: string): HTMLElement {
  return screen.getByText(title).closest('li') as HTMLElement;
}

async function renderQueue(role: string, userId: string) {
  const page: Page<EscalationOut> = {
    items: [escalation('theirs', 'claimed', 'u-other'), escalation('late', 'expired', null), escalation('mine', 'claimed', userId)],
    next_cursor: null,
  };
  const { api } = fakeApi(() => page);
  const session = await signedInSession(api, { role, id: userId });
  renderWithSession(<EscalationsPage />, session);
  await screen.findByText('Escalation theirs');
}

describe('escalation queue gating mirrors the API', () => {
  it('stops an analyst deciding or claiming another analyst claim, but allows claiming an expired one', async () => {
    await renderQueue('analyst', 'u-1');
    const theirs = within(card('Escalation theirs'));
    expect(theirs.getByRole('button', { name: /Decide/ })).toBeDisabled();
    expect(theirs.getByText(/Claimed by another analyst/)).toBeInTheDocument();
    expect(theirs.queryByRole('button', { name: /Claim|Take over/ })).not.toBeInTheDocument();

    const late = within(card('Escalation late'));
    expect(late.getByRole('button', { name: 'Claim' })).toBeEnabled();
    expect(late.getByRole('button', { name: /Decide/ })).toBeEnabled();

    const mine = within(card('Escalation mine'));
    expect(mine.getByRole('button', { name: /Decide/ })).toBeEnabled();
    expect(mine.queryByRole('button', { name: /Claim|Take over/ })).not.toBeInTheDocument();
  });

  it('lets an admin take over and decide another analyst claim', async () => {
    await renderQueue('admin', 'u-9');
    const theirs = within(card('Escalation theirs'));
    expect(theirs.getByRole('button', { name: 'Take over' })).toBeEnabled();
    expect(theirs.getByRole('button', { name: /Decide/ })).toBeEnabled();
  });
});

describe('linked tickets of the escalation queue', () => {
  function ticket(escalationId: string, key: string): TicketOut {
    return {
      id: `t-${escalationId}`,
      integration_id: 'jira-1',
      system: 'jira',
      alert_id: `alert-${escalationId}`,
      escalation_id: escalationId,
      external_key: key,
      external_url: `https://jira.example/browse/${key}`,
      resolved: false,
      created_at: '2026-09-29T10:00:00Z',
    };
  }

  it('looks tickets up for 200 escalations in requests of at most about 4 KB each', async () => {
    const ids = Array.from({ length: 200 }, () => crypto.randomUUID());
    const urls: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'https://soc.example');
      urls.push(String(input));
      const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
      if (url.pathname === '/api/v1/escalations') {
        return json({ items: ids.map((id, i) => ({ ...escalation(id, 'open', null), summary: { title: `Escalation ${i}` } })), next_cursor: null });
      }
      if (url.pathname === '/api/v1/tickets') {
        const asked = url.searchParams.getAll('escalation_id');
        // A proxy refuses request lines over 8 KB (nginx large_client_header_buffers).
        if (String(input).length > 8_192) return new Response('URI Too Long', { status: 414 });
        return json(asked.filter((id) => id === ids[0] || id === ids[199]).map((id) => ticket(id, id === ids[0] ? 'SEC-1' : 'SEC-200')));
      }
      return json({});
    });
    const api = createApiClient({ baseUrl: '/api/v1', auth: { getToken: () => 't', refresh: async () => null, actingTenant: () => null }, fetchImpl });
    const session = await signedInSession(api, { role: 'analyst' });
    renderWithSession(<EscalationsPage />, session);

    // 200 cards: plain selectors, since role queries over this DOM are slow on a busy runner.
    const link = (key: string) => document.querySelector(`a[href="https://jira.example/browse/${key}"]`);
    await waitFor(() => expect(link('SEC-200')).toHaveTextContent('Jira SEC-200'), { timeout: 10_000 });
    expect(link('SEC-1')).toHaveTextContent('Jira SEC-1');
    const ticketUrls = urls.filter((u) => u.startsWith('/api/v1/tickets'));
    expect(ticketUrls.length).toBeGreaterThan(1);
    for (const u of ticketUrls) expect(u.length).toBeLessThanOrEqual(4_096);
    const asked = ticketUrls.flatMap((u) => new URL(u, 'https://soc.example').searchParams.getAll('escalation_id'));
    expect(new Set(asked)).toEqual(new Set(ids));
  });
});

