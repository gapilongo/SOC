/**
 * Live event stream over `/ws?token=<access token>`.
 *
 * * Reconnects with exponential backoff and jitter
 *   (`delay = random in [cap/2, cap]`, `cap = min(max, base * 2^attempt)`),
 *   so a fleet of browsers does not reconnect in lockstep after an outage.
 * * Delivery is at-most-once: after every reconnect (not the first connect)
 *   `onResync` fires so the app re-reads state from the REST API.
 * * Close code 4401 (token expired) and 1008 (policy, e.g. a refused token)
 *   ask for a fresh token before reconnecting; 1013 (server busy / client
 *   too slow) uses the normal backoff.
 * * The attempt counter resets once the server's `hello` arrives, so a
 *   socket that opens and immediately closes keeps backing off.
 * * After `UNAVAILABLE_AFTER` consecutive failed attempts the status becomes
 *   `unavailable` (still retrying with backoff), so the UI can say live
 *   updates are down instead of showing "Reconnecting" forever. A browser
 *   cannot tell why a handshake failed (a refused Origin, an unreachable
 *   API and a proxy without WebSocket support all look like close 1006).
 */

import type { LiveEvent } from '../modules/soc/api/types';

export type LiveStatus = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'unavailable' | 'closed';

/** Consecutive failed attempts after which the stream is reported unavailable. */
export const UNAVAILABLE_AFTER = 5;

export interface BackoffOptions {
  baseMs: number;
  maxMs: number;
}

export const DEFAULT_BACKOFF: BackoffOptions = { baseMs: 1_000, maxMs: 30_000 };

/** Backoff delay for the given attempt (0-based), with jitter in [cap/2, cap]. */
export function backoffDelay(attempt: number, options: BackoffOptions = DEFAULT_BACKOFF, random: () => number = Math.random): number {
  const cap = Math.min(options.maxMs, options.baseMs * 2 ** Math.max(0, attempt));
  return Math.round(cap / 2 + random() * (cap / 2));
}

export interface WebSocketLike {
  readonly readyState: number;
  onopen: ((ev: Event) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  onclose: ((ev: CloseEvent) => void) | null;
  onerror: ((ev: Event) => void) | null;
  close(code?: number, reason?: string): void;
}

export interface LiveSocketOptions {
  url: string;
  /** Current access token; may refresh. Null means "not signed in": do not connect. */
  getToken: () => string | null;
  /** Force a new token (after 4401/1008). */
  refreshToken: () => Promise<string | null>;
  /** Which message types are events to hand to `onEvent` (the types the registered modules listen to). */
  isEvent: (type: string) => boolean;
  onEvent: (event: LiveEvent) => void;
  onStatus?: (status: LiveStatus) => void;
  /** Called after a reconnect once the server said hello: re-read state. */
  onResync?: () => void;
  backoff?: BackoffOptions;
  random?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  createSocket?: (url: string) => WebSocketLike;
}

const CLOSE_TOKEN_EXPIRED = 4401;
const CLOSE_POLICY = 1008;

export class LiveSocket {
  #opts: Required<Omit<LiveSocketOptions, 'onStatus' | 'onResync'>> & Pick<LiveSocketOptions, 'onStatus' | 'onResync'>;
  #socket: WebSocketLike | null = null;
  #timer: unknown = null;
  #attempt = 0;
  #everConnected = false;
  #stopped = true;
  #status: LiveStatus = 'idle';
  #needsFreshToken = false;

  constructor(options: LiveSocketOptions) {
    this.#opts = {
      backoff: DEFAULT_BACKOFF,
      random: Math.random,
      setTimer: (fn, ms) => setTimeout(fn, ms),
      clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
      createSocket: (url) => new WebSocket(url),
      ...options,
    };
  }

  get status(): LiveStatus {
    return this.#status;
  }

  /** Number of consecutive failed attempts (for tests and diagnostics). */
  get attempt(): number {
    return this.#attempt;
  }

  start(): void {
    if (!this.#stopped) return;
    this.#stopped = false;
    void this.#connect();
  }

  stop(): void {
    this.#stopped = true;
    this.#clearTimer();
    const socket = this.#socket;
    this.#socket = null;
    if (socket) {
      socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
      try {
        socket.close(1000, 'client closing');
      } catch {
        // already closed
      }
    }
    this.#setStatus('closed');
  }

  /** Reconnect now (e.g. the network came back), resetting the backoff. */
  reconnectNow(): void {
    if (this.#stopped) return;
    this.#attempt = 0;
    this.#clearTimer();
    if (!this.#socket) void this.#connect();
  }

  #setStatus(status: LiveStatus): void {
    if (this.#status === status) return;
    this.#status = status;
    this.#opts.onStatus?.(status);
  }

  #clearTimer(): void {
    if (this.#timer !== null) {
      this.#opts.clearTimer(this.#timer);
      this.#timer = null;
    }
  }

  async #connect(): Promise<void> {
    if (this.#stopped) return;
    this.#setStatus(this.#failingStatus() ?? (this.#everConnected ? 'reconnecting' : 'connecting'));
    let token = this.#opts.getToken();
    if (!token || this.#needsFreshToken) {
      this.#needsFreshToken = false;
      try {
        token = await this.#opts.refreshToken();
      } catch {
        token = null;
      }
    }
    if (this.#stopped) return;
    if (!token) {
      this.#scheduleReconnect();
      return;
    }
    const sep = this.#opts.url.includes('?') ? '&' : '?';
    let socket: WebSocketLike;
    try {
      socket = this.#opts.createSocket(`${this.#opts.url}${sep}token=${encodeURIComponent(token)}`);
    } catch {
      this.#scheduleReconnect();
      return;
    }
    this.#socket = socket;
    let greeted = false;
    socket.onmessage = (ev) => {
      let msg: unknown;
      try {
        msg = JSON.parse(typeof ev.data === 'string' ? ev.data : '');
      } catch {
        return;
      }
      if (!msg || typeof msg !== 'object') return;
      const type = (msg as { type?: unknown }).type;
      if (type === 'hello') {
        greeted = true;
        const isReconnect = this.#everConnected;
        this.#everConnected = true;
        this.#attempt = 0;
        this.#setStatus('open');
        if (isReconnect) this.#opts.onResync?.();
        return;
      }
      if (type === 'ping') return;
      if (typeof type === 'string' && this.#opts.isEvent(type)) this.#opts.onEvent(msg as LiveEvent);
    };
    socket.onerror = () => {
      // onclose follows and handles the reconnect.
    };
    socket.onclose = (ev) => {
      if (this.#socket !== socket) return;
      this.#socket = null;
      if (this.#stopped) return;
      if (ev.code === CLOSE_TOKEN_EXPIRED || ev.code === CLOSE_POLICY) this.#needsFreshToken = true;
      if (ev.code === CLOSE_TOKEN_EXPIRED && greeted) {
        // Normal end of a token's life: reconnect promptly with a new token.
        this.#attempt = 0;
      }
      this.#scheduleReconnect();
    };
  }

  #failingStatus(): LiveStatus | null {
    return this.#attempt >= UNAVAILABLE_AFTER ? 'unavailable' : null;
  }

  #scheduleReconnect(): void {
    if (this.#stopped) return;
    const delay = backoffDelay(this.#attempt, this.#opts.backoff, this.#opts.random);
    this.#attempt += 1;
    this.#setStatus(this.#failingStatus() ?? 'reconnecting');
    this.#clearTimer();
    this.#timer = this.#opts.setTimer(() => {
      this.#timer = null;
      void this.#connect();
    }, delay);
  }
}
