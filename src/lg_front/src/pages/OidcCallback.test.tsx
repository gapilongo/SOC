import { screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type * as OidcModule from '../auth/oidc';
import { AuthStore } from '../auth/store';
import type * as ConfigModule from '../config';
import { fakeApi, fakeTransport, renderWithSession } from '../test/helpers';

const order: string[] = [];

vi.mock('../config', async (importOriginal) => {
  const actual = await importOriginal<typeof ConfigModule>();
  const config = actual.parseConfig({
    oidc: { issuer: 'https://idp.example', clientId: 'web', authorizationEndpoint: 'https://idp.example/authorize', tokenEndpoint: 'https://idp.example/token' },
  });
  return { ...actual, getConfig: () => config };
});

const completeLogin = vi.fn(async (_config: unknown, url: string) => {
  order.push(`redeem ${new URL(url).search} (address bar: ${window.location.search || 'clean'})`);
  return { token: 'sso-token', expiresIn: 300, refreshToken: null, returnTo: '/alerts' };
});

vi.mock('../auth/oidc', async (importOriginal) => ({
  ...(await importOriginal<typeof OidcModule>()),
  completeLogin: (config: unknown, url: string) => completeLogin(config, url),
}));

const { default: OidcCallbackPage } = await import('./OidcCallback');

function session() {
  const auth = new AuthStore({ transport: fakeTransport(), lock: (_n, fn) => fn(), setTimer: () => 0, clearTimer: () => undefined });
  return { auth, api: fakeApi(() => null).api };
}

afterEach(() => {
  order.length = 0;
  completeLogin.mockClear();
  window.history.replaceState(null, '', '/');
});

describe('OIDC callback', () => {
  it('clears the code from the address bar first and redeems it once under StrictMode', async () => {
    window.history.replaceState(null, '', '/auth/callback?code=code-1&state=state-1');
    const s = session();
    renderWithSession(
      <StrictMode>
        <Routes>
          <Route path="/auth/callback" element={<OidcCallbackPage />} />
          <Route path="/alerts" element={<p>alerts page</p>} />
        </Routes>
      </StrictMode>,
      s,
      { route: '/auth/callback' },
    );

    expect(await screen.findByText('alerts page')).toBeInTheDocument();
    expect(completeLogin).toHaveBeenCalledTimes(1);
    expect(order).toEqual(['redeem ?code=code-1&state=state-1 (address bar: clean)']);
    expect(window.location.search).toBe('');
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('shows the failure and a way back to sign-in', async () => {
    completeLogin.mockRejectedValueOnce(new Error('The sign-in response was not for this browser.'));
    window.history.replaceState(null, '', '/auth/callback?code=code-2&state=state-2');
    const s = session();
    renderWithSession(
      <Routes>
        <Route path="/auth/callback" element={<OidcCallbackPage />} />
      </Routes>,
      s,
      { route: '/auth/callback' },
    );

    expect(await screen.findByText(/not for this browser/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to sign in' })).toHaveAttribute('href', '/login');
    expect(completeLogin).toHaveBeenCalledTimes(1);
    expect(window.location.search).toBe('');
  });
});
