import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiError, fakeTransport, token } from '../test/helpers';
import { AuthStore, REFRESH_LOCK, type AuthStoreDeps } from './store';

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function makeStore(overrides: Partial<AuthStoreDeps> = {}) {
  const timers: Array<{ fn: () => void; ms: number }> = [];
  let now = 1_000_000;
  const lock = vi.fn((_name: string, fn: () => Promise<unknown>) => fn());
  const store = new AuthStore({
    transport: fakeTransport(),
    now: () => now,
    setTimer: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    clearTimer: () => undefined,
    lock: lock as unknown as AuthStoreDeps['lock'],
    ...overrides,
  });
  return {
    store,
    timers,
    lock,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AuthStore', () => {
  it('keeps the access token in memory only', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const cookie = document.cookie;
    const { store } = makeStore();
    await store.login('a@acme.test', 'secret', null);

    expect(store.getToken()).toBe('login-token');
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).toBe(cookie);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    // Not reachable through the observable state or serialisation.
    expect(JSON.stringify(store.getState())).not.toContain('login-token');
    expect(JSON.stringify(store)).not.toContain('login-token');
    expect(Object.values(store).some((v) => v === 'login-token')).toBe(false);
  });

  it('exposes the principal from the login response', async () => {
    const { store } = makeStore({ transport: fakeTransport({ login: vi.fn(async () => token('t', { role: 'admin', is_platform_admin: true })) }) });
    await store.login('a@acme.test', 'pw', 'acme');
    expect(store.getState()).toMatchObject({
      status: 'authenticated',
      principal: { role: 'admin', tenantId: 'acme', homeTenantId: 'acme', isPlatformAdmin: true, method: 'password' },
    });
  });

  it('shares one refresh request between concurrent callers (single flight)', async () => {
    const gate = deferred<ReturnType<typeof token>>();
    const refresh = vi.fn(() => gate.promise);
    const { store, lock } = makeStore({ transport: fakeTransport({ refresh }) });
    await store.login('a@acme.test', 'pw', null);

    const results = Promise.all([store.refresh(), store.refresh(), store.refresh()]);
    gate.resolve(token('fresh-token'));
    expect(await results).toEqual(['fresh-token', 'fresh-token', 'fresh-token']);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(lock).toHaveBeenCalledWith(REFRESH_LOCK, expect.any(Function));
    expect(store.getToken()).toBe('fresh-token');

    // A later refresh is a new request.
    refresh.mockResolvedValueOnce(token('newer-token'));
    await expect(store.refresh()).resolves.toBe('newer-token');
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('restores a session from the refresh cookie on load', async () => {
    const refresh = vi.fn(async () => token('cookie-token'));
    const { store } = makeStore({ transport: fakeTransport({ refresh }) });
    expect(store.getState().status).toBe('initializing');
    await store.init();
    expect(store.getState().status).toBe('authenticated');
    expect(store.getToken()).toBe('cookie-token');
  });

  it('starts anonymous when there is no refresh cookie', async () => {
    const { store } = makeStore();
    await store.init();
    expect(store.getState()).toMatchObject({ status: 'anonymous', principal: null });
    expect(store.getToken()).toBeNull();
  });

  it('ends the session as expired when the API refuses the refresh', async () => {
    const { store } = makeStore();
    await store.login('a@acme.test', 'pw', null);
    await expect(store.refresh()).resolves.toBeNull();
    expect(store.getState()).toMatchObject({ status: 'expired', principal: null });
    expect(store.getToken()).toBeNull();
    // No further network refreshes once the session is gone.
    await expect(store.refresh()).resolves.toBeNull();
  });

  it('keeps the session through a transient refresh failure and retries later', async () => {
    const refresh = vi.fn(async () => {
      throw apiError(503, 'service_unavailable');
    });
    const { store, timers } = makeStore({ transport: fakeTransport({ refresh }) });
    await store.login('a@acme.test', 'pw', null);
    await expect(store.refresh()).resolves.toBeNull();
    expect(store.getState().status).toBe('authenticated');
    expect(store.getToken()).toBe('login-token');
    expect(timers.at(-1)?.ms).toBe(15_000);
  });

  it('schedules a refresh before the access token expires', async () => {
    const refresh = vi.fn(async () => token('scheduled-token'));
    const { store, timers } = makeStore({ transport: fakeTransport({ refresh, login: vi.fn(async () => token('t', {}, 900)) }) });
    await store.login('a@acme.test', 'pw', null);
    const timer = timers.at(-1)!;
    // 900 s token: refresh at min(80%, expiry - 60 s) = 720 s.
    expect(timer.ms).toBe(720_000);
    timer.fn();
    await vi.waitFor(() => expect(store.getToken()).toBe('scheduled-token'));
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('reports no token once it has expired', async () => {
    const { store, advance } = makeStore({ transport: fakeTransport({ login: vi.fn(async () => token('short', {}, 60)) }) });
    await store.login('a@acme.test', 'pw', null);
    expect(store.getToken()).toBe('short');
    advance(60_001);
    expect(store.getToken()).toBeNull();
  });

  it('does not let a stale load-time refresh sign out a user who just logged in', async () => {
    const gate = deferred<ReturnType<typeof token>>();
    const { store } = makeStore({ transport: fakeTransport({ refresh: vi.fn(() => gate.promise) }) });
    const init = store.init();
    await store.login('a@acme.test', 'pw', null);
    gate.reject(apiError(401, 'invalid_session'));
    await init;
    expect(store.getState().status).toBe('authenticated');
    expect(store.getToken()).toBe('login-token');
  });

  it('revokes the session on logout and forgets the token', async () => {
    const transport = fakeTransport();
    const { store } = makeStore({ transport });
    await store.login('a@acme.test', 'pw', null);
    await store.logout();
    expect(transport.logout).toHaveBeenCalledWith('login-token');
    expect(store.getState()).toMatchObject({ status: 'anonymous', principal: null });
    expect(store.getToken()).toBeNull();
  });

  it('lets only platform admins act on another tenant', async () => {
    const { store } = makeStore();
    await store.login('a@acme.test', 'pw', null);
    expect(() => store.setActingTenant('other')).toThrow(/platform admins/);

    const admin = makeStore({ transport: fakeTransport({ login: vi.fn(async () => token('t', { role: 'admin', is_platform_admin: true })) }) });
    await admin.store.login('p@acme.test', 'pw', null);
    admin.store.setActingTenant('globex');
    expect(admin.store.getActingTenant()).toBe('globex');
    expect(admin.store.getState().principal).toMatchObject({ tenantId: 'globex', homeTenantId: 'acme' });
    admin.store.setActingTenant('acme');
    expect(admin.store.getActingTenant()).toBeNull();
  });

  it('refreshes OIDC sessions through the identity provider, not the cookie endpoint', async () => {
    const transport = fakeTransport();
    const oidc = { refresh: vi.fn(async () => ({ token: 'idp-2', expiresIn: 300, refreshToken: 'rt-2' })) };
    const { store } = makeStore({ transport, oidc });
    await store.acceptOidc('idp-1', 300, 'rt-1');
    expect(store.getState().principal?.method).toBe('oidc');
    await expect(store.refresh()).resolves.toBe('idp-2');
    expect(oidc.refresh).toHaveBeenCalledWith('rt-1');
    expect(transport.refresh).not.toHaveBeenCalled();
    await store.refresh();
    expect(oidc.refresh).toHaveBeenLastCalledWith('rt-2');
  });
});
