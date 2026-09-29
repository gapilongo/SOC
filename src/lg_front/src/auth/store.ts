/**
 * Session state for the web app.
 *
 * Security properties:
 *
 * * The access token lives in a private field of this object only: it is
 *   never written to localStorage, sessionStorage or cookies. The one URL
 *   it appears in is the WebSocket handshake (`/api/v1/ws?token=...`,
 *   browsers cannot send headers there); see README "Security model".
 *   A page reload therefore starts signed out and restores the session
 *   through `POST /auth/refresh`, which uses the HttpOnly refresh cookie the
 *   API set at login.
 * * Refreshes are single-flight: concurrent callers (a burst of 401s, the
 *   expiry timer, the WebSocket) share one request. Across tabs a Web Lock
 *   serialises refreshes, because the API treats a rotated refresh token
 *   presented twice as theft and revokes every session of the user.
 * * The token is refreshed shortly before it expires, again when the tab
 *   becomes visible (timers are throttled in background tabs), and on a 401.
 * * A refresh the API refuses (401) ends the session with status `expired`;
 *   transient failures (network, 5xx, 429) keep the session and retry.
 */

import { ApiError } from '../api/client';
import type { MeOut, TokenOut, UserOut } from '../api/types';

export type AuthStatus = 'initializing' | 'anonymous' | 'authenticated' | 'expired';
export type AuthMethod = 'password' | 'oidc';

export interface Principal {
  userId: string | null;
  email: string | null;
  role: string | null;
  tenantId: string;
  homeTenantId: string;
  isPlatformAdmin: boolean;
  method: AuthMethod;
}

export interface AuthState {
  status: AuthStatus;
  principal: Principal | null;
  /** Tenant a platform admin currently acts on (sent as X-Tenant-ID), null for the home tenant. */
  actingTenant: string | null;
}

/** Token material obtained from the API or the identity provider. */
export interface IssuedToken {
  token: string;
  expiresIn: number;
  user?: UserOut;
}

export interface AuthTransport {
  login(email: string, password: string, tenant: string | null): Promise<TokenOut>;
  /** POST /auth/refresh with the cookie. Throws ApiError. */
  refresh(): Promise<TokenOut>;
  logout(token: string | null): Promise<void>;
  me(token: string): Promise<MeOut>;
}

/** Refreshes an OIDC session (refresh_token grant); null when it cannot. */
export interface OidcRefresher {
  refresh(refreshToken: string): Promise<{ token: string; expiresIn: number; refreshToken: string | null } | null>;
}

export type LockFn = <T>(name: string, fn: () => Promise<T>) => Promise<T>;

export interface AuthStoreDeps {
  transport: AuthTransport;
  oidc?: OidcRefresher | null;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  lock?: LockFn;
}

const MIN_REFRESH_DELAY_MS = 5_000;
const EARLY_REFRESH_MS = 60_000;
const RETRY_DELAY_MS = 15_000;
export const REFRESH_LOCK = 'lg-sotf-auth-refresh';

/** Web Locks when available (serialises refresh across tabs), otherwise run directly. */
export const browserLock: LockFn = async (name, fn) => {
  const locks = typeof navigator !== 'undefined' ? (navigator as Navigator & { locks?: LockManager }).locks : undefined;
  if (locks && typeof locks.request === 'function') {
    return locks.request(name, () => fn()) as ReturnType<typeof fn>;
  }
  return fn();
};

function principalFromUser(user: UserOut, method: AuthMethod): Principal {
  return {
    userId: user.id,
    email: user.email,
    role: user.role,
    tenantId: user.tenant_id,
    homeTenantId: user.tenant_id,
    isPlatformAdmin: Boolean(user.is_platform_admin),
    method,
  };
}

function principalFromMe(me: MeOut, method: AuthMethod): Principal {
  return {
    userId: me.user_id ?? null,
    email: me.email ?? null,
    role: me.role ?? null,
    tenantId: me.tenant_id,
    homeTenantId: me.home_tenant_id,
    isPlatformAdmin: Boolean(me.is_platform_admin),
    method,
  };
}

/** A refresh failure that means the session is gone (not a transient outage). */
export function isSessionRejected(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.status === 403);
}

export class AuthStore {
  // Memory only. Never persisted.
  #token: string | null = null;
  #expiresAt = 0;
  #oidcRefreshToken: string | null = null;
  #inflight: Promise<string | null> | null = null;
  #timer: unknown = null;
  #state: AuthState = { status: 'initializing', principal: null, actingTenant: null };
  #listeners = new Set<() => void>();
  // Bumped whenever a session starts or ends, so a refresh that started
  // before a login (or logout) cannot overwrite the newer outcome.
  #generation = 0;
  readonly #deps: Required<Omit<AuthStoreDeps, 'oidc'>> & { oidc: OidcRefresher | null };

  constructor(deps: AuthStoreDeps) {
    this.#deps = {
      transport: deps.transport,
      oidc: deps.oidc ?? null,
      now: deps.now ?? (() => Date.now()),
      setTimer: deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms)),
      clearTimer: deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>)),
      lock: deps.lock ?? browserLock,
    };
  }

  // -- observable state ---------------------------------------------------------

  getState = (): AuthState => this.#state;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  #set(patch: Partial<AuthState>): void {
    this.#state = { ...this.#state, ...patch };
    for (const l of [...this.#listeners]) l();
  }

  /** The access token while it is valid, else null. */
  getToken = (): string | null => {
    if (!this.#token) return null;
    if (this.#deps.now() >= this.#expiresAt) return null;
    return this.#token;
  };

  /** Seconds until the access token expires (0 when there is none). */
  secondsLeft(): number {
    if (!this.#token) return 0;
    return Math.max(0, Math.floor((this.#expiresAt - this.#deps.now()) / 1000));
  }

  getActingTenant = (): string | null => this.#state.actingTenant;

  setActingTenant(tenant: string | null): void {
    const value = tenant && tenant.trim() ? tenant.trim() : null;
    const principal = this.#state.principal;
    if (value && (!principal || !principal.isPlatformAdmin)) {
      throw new Error('only platform admins can act on another tenant');
    }
    const acting = value && principal && value === principal.homeTenantId ? null : value;
    this.#set({
      actingTenant: acting,
      principal: principal ? { ...principal, tenantId: acting ?? principal.homeTenantId } : null,
    });
  }

  // -- session lifecycle -------------------------------------------------------------

  /** Restore a session from the refresh cookie (page load). */
  async init(): Promise<void> {
    if (this.#state.status !== 'initializing') return;
    const token = await this.refresh();
    if (!token && this.#state.status === 'initializing') this.#set({ status: 'anonymous' });
  }

  async login(email: string, password: string, tenant: string | null): Promise<void> {
    const out = await this.#deps.transport.login(email, password, tenant);
    this.#oidcRefreshToken = null;
    this.#accept({ token: out.access_token, expiresIn: out.expires_in }, principalFromUser(out.user, 'password'));
  }

  /** Complete an OIDC sign-in: the API's view of the token becomes the principal. */
  async acceptOidc(token: string, expiresIn: number, refreshToken: string | null): Promise<void> {
    const me = await this.#deps.transport.me(token);
    this.#oidcRefreshToken = refreshToken;
    this.#accept({ token, expiresIn }, principalFromMe(me, 'oidc'));
  }

  /**
   * New access token, shared by concurrent callers. Resolves to null when
   * the session is gone (status becomes `expired` or `anonymous`) or a
   * transient failure prevented the refresh (the session is kept).
   */
  refresh = (): Promise<string | null> => {
    const status = this.#state.status;
    if (status !== 'initializing' && status !== 'authenticated') return Promise.resolve(null);
    if (!this.#inflight) {
      this.#inflight = this.#doRefresh().finally(() => {
        this.#inflight = null;
      });
    }
    return this.#inflight;
  };

  /** Refresh now if the token expires within the early-refresh window (tab became visible). */
  ensureFresh(): Promise<string | null> {
    if (this.#state.status !== 'authenticated') return Promise.resolve(null);
    if (this.#expiresAt - this.#deps.now() > EARLY_REFRESH_MS) return Promise.resolve(this.#token);
    return this.refresh();
  }

  async logout(): Promise<void> {
    const token = this.getToken();
    const method = this.#state.principal?.method;
    this.#clear('anonymous');
    if (method !== 'oidc') {
      try {
        await this.#deps.transport.logout(token);
      } catch {
        // The local session is gone either way; the refresh cookie expires on its own.
      }
    }
  }

  /** The API refused our credentials outright (e.g. account disabled): end the session. */
  expire(): void {
    if (this.#state.status === 'authenticated') this.#clear('expired');
  }

  /** Stop timers (tests, unmount). */
  dispose(): void {
    this.#cancelTimer();
    this.#listeners.clear();
  }

  // -- internals ----------------------------------------------------------------------

  async #doRefresh(): Promise<string | null> {
    const wasAuthenticated = this.#state.status === 'authenticated';
    const principal = this.#state.principal;
    if (principal?.method === 'oidc') return this.#refreshOidc();
    const generation = this.#generation;
    try {
      const out = await this.#deps.lock(REFRESH_LOCK, () => this.#deps.transport.refresh());
      if (generation !== this.#generation) return this.getToken();
      const next = principalFromUser(out.user, 'password');
      this.#accept({ token: out.access_token, expiresIn: out.expires_in }, next);
      return out.access_token;
    } catch (err) {
      if (generation !== this.#generation) return this.getToken();
      if (isSessionRejected(err) || !wasAuthenticated) {
        this.#clear(wasAuthenticated ? 'expired' : 'anonymous');
        return null;
      }
      this.#schedule(RETRY_DELAY_MS);
      return null;
    }
  }

  async #refreshOidc(): Promise<string | null> {
    const rt = this.#oidcRefreshToken;
    if (!rt || !this.#deps.oidc) {
      // Without a refresh token the IdP session must be re-entered.
      if (this.getToken()) {
        this.#schedule(Math.max(MIN_REFRESH_DELAY_MS, this.#expiresAt - this.#deps.now()));
        return null;
      }
      this.#clear('expired');
      return null;
    }
    try {
      const out = await this.#deps.oidc.refresh(rt);
      if (!out) {
        this.#clear('expired');
        return null;
      }
      this.#oidcRefreshToken = out.refreshToken ?? rt;
      this.#setToken(out.token, out.expiresIn);
      return out.token;
    } catch {
      this.#schedule(RETRY_DELAY_MS);
      return null;
    }
  }

  #accept(issued: IssuedToken, principal: Principal): void {
    if (this.#state.status !== 'authenticated' || this.#state.principal?.userId !== principal.userId) this.#generation += 1;
    this.#setToken(issued.token, issued.expiresIn);
    const acting = this.#state.actingTenant;
    const keepActing = acting && principal.isPlatformAdmin && principal.homeTenantId === this.#state.principal?.homeTenantId;
    this.#set({
      status: 'authenticated',
      principal: keepActing ? { ...principal, tenantId: acting } : principal,
      actingTenant: keepActing ? acting : null,
    });
  }

  #setToken(token: string, expiresIn: number): void {
    const lifetimeMs = Math.max(1, expiresIn) * 1000;
    this.#token = token;
    this.#expiresAt = this.#deps.now() + lifetimeMs;
    const early = Math.min(lifetimeMs * 0.8, lifetimeMs - EARLY_REFRESH_MS);
    this.#schedule(Math.max(MIN_REFRESH_DELAY_MS, early));
  }

  #schedule(delayMs: number): void {
    this.#cancelTimer();
    this.#timer = this.#deps.setTimer(() => {
      this.#timer = null;
      void this.refresh();
    }, delayMs);
  }

  #cancelTimer(): void {
    if (this.#timer !== null) {
      this.#deps.clearTimer(this.#timer);
      this.#timer = null;
    }
  }

  #clear(status: 'anonymous' | 'expired'): void {
    this.#generation += 1;
    this.#cancelTimer();
    this.#token = null;
    this.#expiresAt = 0;
    this.#oidcRefreshToken = null;
    this.#set({ status, principal: null, actingTenant: null });
  }
}
