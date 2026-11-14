import { QueryClient, QueryClientProvider, type QueryKey } from '@tanstack/react-query';
import { act, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SessionProvider } from '../auth/AuthContext';
import type { Session } from '../auth/session';
import { fakeApi, signedInSession } from '../test/helpers';
import { LiveProvider, useLive, useLiveEvents } from './LiveProvider';

/** The browser's WebSocket, under the test's control. */
class FakeWebSocket {
  static sockets: FakeWebSocket[] = [];
  readyState = 0;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;
  constructor(public url: string) {
    FakeWebSocket.sockets.push(this);
  }
  close() {
    this.closed = true;
  }
  receive(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent);
  }
}

/** A module's live-event mapping, as the registry hands it to the provider. */
const KEYS: Record<string, QueryKey[]> = { 'thing.updated': [['m', 'things']] };
const keysFor = (type: string) => KEYS[type] ?? [];

function Probe({ heard }: { heard: (type: string) => void }) {
  const { status } = useLive();
  useLiveEvents((event) => heard(event.type));
  return <p>status: {status}</p>;
}

async function mount(session: Session, client: QueryClient, heard: (type: string) => void) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <SessionProvider session={session}>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </SessionProvider>
  );
  const utils = render(
    <LiveProvider keysFor={keysFor}>
      <Probe heard={heard} />
    </LiveProvider>,
    { wrapper },
  );
  // The socket opens after the token is read (a microtask).
  await act(async () => undefined);
  return utils;
}

describe('LiveProvider', () => {
  let session: Session;
  let client: QueryClient;

  beforeEach(async () => {
    FakeWebSocket.sockets = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);
    // A platform admin, so one test can act on another tenant.
    session = await signedInSession(fakeApi(() => ({})).api, { role: 'admin', is_platform_admin: true });
    client = new QueryClient({ defaultOptions: { queries: { gcTime: Infinity } } });
    client.setQueryData(['m', 'things', 1], 'cached');
    client.setQueryData(['other', 'rows'], 'cached');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    client.clear();
  });

  it('opens one socket with the token and reports its status', async () => {
    await mount(session, client, vi.fn());
    expect(FakeWebSocket.sockets).toHaveLength(1);
    expect(FakeWebSocket.sockets[0].url).toMatch(/\/ws\?token=t$/);
    expect(screen.getByText('status: connecting')).toBeInTheDocument();
    act(() => FakeWebSocket.sockets[0].receive({ type: 'hello' }));
    expect(screen.getByText('status: open')).toBeInTheDocument();
  });

  it('hands on the events a module listens to, and marks that module keys stale once per window', async () => {
    const heard = vi.fn();
    await mount(session, client, heard);
    vi.useFakeTimers();
    const spy = vi.spyOn(client, 'invalidateQueries');
    const socket = FakeWebSocket.sockets[0];
    act(() => {
      socket.receive({ type: 'hello' });
      socket.receive({ type: 'thing.updated', tenant_id: 'acme', alert_id: null, data: {}, ts: 'now' });
      socket.receive({ type: 'thing.updated', tenant_id: 'acme', alert_id: null, data: {}, ts: 'now' });
      // No module listens to this type: the socket drops it.
      socket.receive({ type: 'other.updated', tenant_id: 'acme', alert_id: null, data: {}, ts: 'now' });
    });
    expect(heard.mock.calls.map(([type]) => type)).toEqual(['thing.updated', 'thing.updated']);
    expect(spy).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    // Only the module's own prefix was refreshed, once.
    expect(spy.mock.calls.map(([filters]) => (filters as { queryKey: QueryKey }).queryKey)).toEqual([['m', 'things', 1]]);
    expect(client.getQueryState(['other', 'rows'])?.isInvalidated).toBe(false);
  });

  it('re-reads everything visible after a reconnect, and reconnects when the network returns', async () => {
    await mount(session, client, vi.fn());
    const spy = vi.spyOn(client, 'invalidateQueries');
    const first = FakeWebSocket.sockets[0];
    act(() => first.receive({ type: 'hello' }));
    // The connection drops; the browser says the network is back.
    act(() => first.onclose?.({ code: 1006 } as CloseEvent));
    await act(async () => {
      window.dispatchEvent(new Event('online'));
    });
    expect(FakeWebSocket.sockets).toHaveLength(2);
    act(() => FakeWebSocket.sockets[1].receive({ type: 'hello' }));
    expect(spy.mock.calls.map(([filters]) => (filters as { queryKey: QueryKey }).queryKey).sort()).toEqual([
      ['m', 'things', 1],
      ['other', 'rows'],
    ]);
  });

  it('closes the socket and goes idle while acting on another tenant, and on unmount', async () => {
    const { unmount } = await mount(session, client, vi.fn());
    const socket = FakeWebSocket.sockets[0];
    act(() => session.auth.setActingTenant('globex'));
    expect(socket.closed).toBe(true);
    expect(screen.getByText('status: idle')).toBeInTheDocument();
    await act(async () => session.auth.setActingTenant(null));
    expect(FakeWebSocket.sockets).toHaveLength(2);
    unmount();
    expect(FakeWebSocket.sockets[1].closed).toBe(true);
  });
});
