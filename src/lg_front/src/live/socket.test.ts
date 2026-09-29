import { describe, expect, it, vi } from 'vitest';

import type { LiveEvent } from '../api/types';
import { backoffDelay, LiveSocket, UNAVAILABLE_AFTER, type WebSocketLike } from './socket';

class FakeSocket implements WebSocketLike {
  readyState = 0;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;
  constructor(public url: string) {}
  close() {
    this.closed = true;
  }
  receive(data: unknown) {
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) } as MessageEvent);
  }
  drop(code = 1006) {
    this.onclose?.({ code } as CloseEvent);
  }
}

function harness(opts: { token?: string | null; refreshed?: string | null } = {}) {
  const sockets: FakeSocket[] = [];
  const timers: Array<{ fn: () => void; ms: number }> = [];
  const events: LiveEvent[] = [];
  const statuses: string[] = [];
  const onResync = vi.fn();
  const refreshToken = vi.fn(async () => (opts.refreshed === undefined ? 'fresh' : opts.refreshed));
  const socket = new LiveSocket({
    url: 'wss://soc.example/api/v1/ws',
    getToken: () => (opts.token === undefined ? 'tok' : opts.token),
    refreshToken,
    onEvent: (e) => events.push(e),
    onStatus: (s) => statuses.push(s),
    onResync,
    random: () => 0.5,
    backoff: { baseMs: 1_000, maxMs: 30_000 },
    setTimer: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    clearTimer: () => undefined,
    createSocket: (url) => {
      const s = new FakeSocket(url);
      sockets.push(s);
      return s;
    },
  });
  const flush = () => new Promise((r) => setTimeout(r, 0));
  return { socket, sockets, timers, events, statuses, onResync, refreshToken, flush };
}

describe('backoffDelay', () => {
  it('grows exponentially with jitter in [cap/2, cap] and is capped', () => {
    expect(backoffDelay(0, { baseMs: 1000, maxMs: 30000 }, () => 0)).toBe(500);
    expect(backoffDelay(0, { baseMs: 1000, maxMs: 30000 }, () => 1)).toBe(1000);
    expect(backoffDelay(3, { baseMs: 1000, maxMs: 30000 }, () => 0.5)).toBe(6000);
    expect(backoffDelay(20, { baseMs: 1000, maxMs: 30000 }, () => 1)).toBe(30000);
    for (let i = 0; i < 50; i++) {
      const d = backoffDelay(4, { baseMs: 1000, maxMs: 30000 });
      expect(d).toBeGreaterThanOrEqual(8000);
      expect(d).toBeLessThanOrEqual(16000);
    }
  });
});

describe('LiveSocket', () => {
  it('connects with the token in the query string and forwards events', async () => {
    const h = harness();
    h.socket.start();
    await h.flush();
    expect(h.sockets).toHaveLength(1);
    expect(h.sockets[0].url).toBe('wss://soc.example/api/v1/ws?token=tok');
    h.sockets[0].receive({ type: 'hello' });
    h.sockets[0].receive({ type: 'ping' });
    h.sockets[0].receive('not json');
    h.sockets[0].receive({ type: 'unknown.kind' });
    h.sockets[0].receive({ type: 'alert.created', tenant_id: 'acme', alert_id: 'a1', data: {}, ts: 'now' });
    expect(h.socket.status).toBe('open');
    expect(h.events.map((e) => e.type)).toEqual(['alert.created']);
    expect(h.onResync).not.toHaveBeenCalled();
  });

  it('reconnects with growing backoff, resets it after hello and resyncs', async () => {
    const h = harness();
    h.socket.start();
    await h.flush();
    h.sockets[0].receive({ type: 'hello' });
    h.sockets[0].drop();
    expect(h.socket.status).toBe('reconnecting');
    expect(h.timers.at(-1)!.ms).toBe(750); // attempt 0: cap 1000, jitter 0.5

    h.timers.at(-1)!.fn();
    await h.flush();
    h.sockets[1].drop(); // fails before hello
    expect(h.timers.at(-1)!.ms).toBe(1500); // attempt 1: cap 2000

    h.timers.at(-1)!.fn();
    await h.flush();
    h.sockets[2].drop(1013);
    expect(h.timers.at(-1)!.ms).toBe(3000); // attempt 2: cap 4000

    h.timers.at(-1)!.fn();
    await h.flush();
    h.sockets[3].receive({ type: 'hello' });
    expect(h.onResync).toHaveBeenCalledTimes(1);
    expect(h.socket.attempt).toBe(0);
    h.sockets[3].drop();
    expect(h.timers.at(-1)!.ms).toBe(750);
  });

  it('reports live updates unavailable after repeated handshake failures, and recovers on hello', async () => {
    const h = harness();
    h.socket.start();
    for (let i = 0; i < UNAVAILABLE_AFTER; i += 1) {
      await h.flush();
      h.sockets.at(-1)!.drop(1006); // e.g. Origin refused during the handshake
      if (i < UNAVAILABLE_AFTER - 1) expect(h.socket.status).toBe('reconnecting');
      h.timers.at(-1)!.fn();
    }
    await h.flush();
    expect(h.socket.status).toBe('unavailable');
    // Still retrying with backoff, without flapping back to "reconnecting".
    h.sockets.at(-1)!.drop(1006);
    expect(h.socket.status).toBe('unavailable');
    expect(h.statuses.filter((s) => s === 'unavailable')).toHaveLength(1);
    h.timers.at(-1)!.fn();
    await h.flush();
    h.sockets.at(-1)!.receive({ type: 'hello' });
    expect(h.socket.status).toBe('open');
  });

  it('gets a fresh token after the server closes with 4401', async () => {
    const h = harness();
    h.socket.start();
    await h.flush();
    h.sockets[0].receive({ type: 'hello' });
    h.sockets[0].drop(4401);
    h.timers.at(-1)!.fn();
    await h.flush();
    expect(h.refreshToken).toHaveBeenCalledTimes(1);
    expect(h.sockets[1].url).toContain('token=fresh');
  });

  it('waits and retries when no token is available', async () => {
    const h = harness({ token: null, refreshed: null });
    h.socket.start();
    await h.flush();
    expect(h.sockets).toHaveLength(0);
    expect(h.timers).toHaveLength(1);
    expect(h.socket.status).toBe('reconnecting');
  });

  it('stops for good when stopped', async () => {
    const h = harness();
    h.socket.start();
    await h.flush();
    h.socket.stop();
    expect(h.sockets[0].closed).toBe(true);
    h.sockets[0].drop();
    expect(h.timers).toHaveLength(0);
    expect(h.socket.status).toBe('closed');
  });
});
