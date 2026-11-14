import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

import { ApiError, type ApiClient } from '../api/client';
import type { TokenOut, UserOut } from '../modules/soc/api/types';
import { SessionProvider } from '../auth/AuthContext';
import type { Session } from '../auth/session';
import { AuthStore, type AuthTransport } from '../auth/store';
import { ToastProvider } from '../components/Toast';
import { DensityProvider } from '../theme/density';
import { ThemeProvider } from '../theme/theme';

export function user(overrides: Partial<UserOut> = {}): UserOut {
  return {
    id: 'u-1',
    tenant_id: 'acme',
    email: 'analyst@acme.test',
    role: 'analyst',
    is_platform_admin: false,
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

export function token(access: string, overrides: Partial<UserOut> = {}, expiresIn = 3600): TokenOut {
  return { access_token: access, token_type: 'bearer', expires_in: expiresIn, user: user(overrides) };
}

export function apiError(status: number, code: string, message = code, requestId = 'req-test-0001'): ApiError {
  return new ApiError({ status, code, message, requestId });
}

export function fakeTransport(overrides: Partial<AuthTransport> = {}): AuthTransport {
  return {
    login: vi.fn(async () => token('login-token')),
    verifyMfa: vi.fn(async () => token('mfa-token')),
    enrollMfa: vi.fn(async () => ({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/LG-SOTF:a?secret=JBSWY3DPEHPK3PXP', qr: null, expires_in: 900 })),
    confirmMfa: vi.fn(async () => ({ recovery_codes: ['aaaaa-bbbbb'], session: token('enrolled-token') })),
    refresh: vi.fn(async () => {
      throw apiError(401, 'invalid_session');
    }),
    logout: vi.fn(async () => undefined),
    me: vi.fn(async () => ({ kind: 'user' as const, tenant_id: 'acme', home_tenant_id: 'acme', auth_method: 'oidc', role: 'analyst', user_id: 'u-1' })),
    ...overrides,
  };
}

/** An ApiClient whose requests are answered by `handler(method, path, body)`. */
export function fakeApi(handler: (method: string, path: string, body?: unknown) => unknown | Promise<unknown>) {
  const calls: Array<{ method: string; path: string; body?: unknown; query?: unknown }> = [];
  const request = async <T,>(method: string, path: string, options: { body?: unknown; query?: unknown } = {}): Promise<T> => {
    calls.push({ method, path, body: options.body, query: options.query });
    return (await handler(method, path, options.body)) as T;
  };
  const api: ApiClient = {
    request,
    get: (p, o) => request('GET', p, o),
    post: (p, b, o) => request('POST', p, { ...o, body: b }),
    patch: (p, b, o) => request('PATCH', p, { ...o, body: b }),
    del: (p, o) => request('DELETE', p, o),
  };
  return { api, calls };
}

/** A signed-in session with the given role. */
export async function signedInSession(api: ApiClient, overrides: Partial<UserOut> = {}): Promise<Session> {
  const auth = new AuthStore({
    transport: fakeTransport({ login: vi.fn(async () => token('t', overrides)) }),
    lock: (_n, fn) => fn(),
    setTimer: () => 0,
    clearTimer: () => undefined,
  });
  await auth.login('x@acme.test', 'pw', null);
  return { auth, api };
}

export function renderWithSession(ui: ReactElement, session: Session, { route = '/' }: { route?: string } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <SessionProvider session={session}>
      <QueryClientProvider client={client}>
        <ThemeProvider>
          <DensityProvider>
            <ToastProvider>
              <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
            </ToastProvider>
          </DensityProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </SessionProvider>
  );
  return { client, ...render(ui, { wrapper: Wrapper }) };
}
