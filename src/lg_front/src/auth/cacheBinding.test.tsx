import { QueryClient } from '@tanstack/react-query';
import { act, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import type { AlertOut, Page } from '../api/types';
import AlertsPage from '../pages/alerts/AlertsPage';
import { apiError, fakeApi, fakeTransport, renderWithSession, token } from '../test/helpers';
import { bindQueryCacheToSession, identityKey } from './cacheBinding';
import { AuthStore } from './store';

function alert(id: string, title: string, tenant: string): AlertOut {
  return {
    id,
    tenant_id: tenant,
    source_id: 'splunk',
    source_alert_id: id,
    title,
    severity: 'high',
    status: 'queued',
    disposition: null,
    occurred_at: '2026-09-29T10:00:00Z',
    ingested_at: '2026-09-29T10:00:00Z',
  } as AlertOut;
}

function storeWith(logins: Array<ReturnType<typeof token>>) {
  const login = vi.fn();
  for (const t of logins) login.mockResolvedValueOnce(t);
  return new AuthStore({
    transport: fakeTransport({ login }),
    lock: (_n, fn) => fn(),
    setTimer: () => 0,
    clearTimer: () => undefined,
  });
}

describe('query cache bound to the session identity', () => {
  it('derives the identity from user, tenants and role only while authenticated', async () => {
    const store = storeWith([token('a', { id: 'u-a', tenant_id: 'acme' })]);
    expect(identityKey(store.getState())).toBeNull();
    await store.login('a@acme.test', 'pw', null);
    expect(identityKey(store.getState())).toContain('u-a');
  });

  it('clears the cache when the session expires or another user signs in, not on a plain token refresh', async () => {
    const store = storeWith([token('a', { id: 'u-a' }), token('b', { id: 'u-b', tenant_id: 'globex' })]);
    const client = new QueryClient();
    const stop = bindQueryCacheToSession(store, client);
    await store.login('a@acme.test', 'pw', null);
    client.setQueryData(['alerts', {}], 'data of A');

    store.expire();
    expect(client.getQueryData(['alerts', {}])).toBeUndefined();

    client.setQueryData(['alerts', {}], 'left over');
    await store.login('b@globex.test', 'pw', null);
    expect(client.getQueryData(['alerts', {}])).toBeUndefined();

    stop();
  });

  it('keeps the cache when the same identity is re-issued a token', async () => {
    const refresh = vi.fn(async () => token('a2', { id: 'u-a' }));
    const store = new AuthStore({
      transport: fakeTransport({ login: vi.fn(async () => token('a', { id: 'u-a' })), refresh }),
      lock: (_n, fn) => fn(),
      setTimer: () => 0,
      clearTimer: () => undefined,
    });
    const client = new QueryClient();
    bindQueryCacheToSession(store, client);
    await store.login('a@acme.test', 'pw', null);
    client.setQueryData(['dashboard', 24], 'kept');
    await store.refresh();
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(client.getQueryData(['dashboard', 24])).toBe('kept');
  });

  it('never renders the previous user rows after the session expires and user B signs in', async () => {
    const store = storeWith([token('a', { id: 'u-a', tenant_id: 'acme' }), token('b', { id: 'u-b', tenant_id: 'globex', role: 'viewer' })]);
    await store.login('a@acme.test', 'pw', null);
    let pageForB: Promise<Page<AlertOut>> = Promise.reject(apiError(403, 'forbidden', 'Not allowed'));
    pageForB.catch(() => undefined);
    const { api } = fakeApi((_m, path) => {
      if (path !== '/alerts') return {};
      const who = store.getState().principal?.userId;
      if (who === 'u-a') return { items: [alert('a-1', 'Secret alert of tenant acme', 'acme')], next_cursor: null };
      return pageForB;
    });
    const { client } = renderWithSession(<AlertsPage />, { auth: store, api });
    bindQueryCacheToSession(store, client);
    // The virtualized grid renders no row elements in jsdom; its row count and footer show what it holds.
    const grid = await screen.findByRole('grid', { name: 'Alerts' });
    expect(grid).toHaveAttribute('aria-rowcount', '2');
    expect(screen.getByText('1 row loaded')).toBeInTheDocument();

    await act(async () => store.expire());
    // React Query notifies observers on its next tick.
    await waitFor(() => expect(screen.queryByRole('grid', { name: 'Alerts' })).not.toBeInTheDocument());
    // B's first request fails: the stale rows of A must not be what remains on screen.
    pageForB = Promise.reject(apiError(403, 'forbidden', 'Not allowed'));
    pageForB.catch(() => undefined);
    await act(async () => store.login('b@globex.test', 'pw', null));

    expect(screen.queryByRole('grid', { name: 'Alerts' })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/Not allowed/)).toBeInTheDocument());
    expect(screen.queryByRole('grid', { name: 'Alerts' })).not.toBeInTheDocument();
    expect(screen.queryByText('1 row loaded')).not.toBeInTheDocument();
  });
});
