import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import { AuthStore } from '../auth/store';
import { apiError, fakeApi, fakeTransport, renderWithSession, token } from '../test/helpers';
import LoginPage from './Login';

function session(login = vi.fn(async () => token('t'))) {
  const auth = new AuthStore({ transport: fakeTransport({ login }), lock: (_n, fn) => fn(), setTimer: () => 0, clearTimer: () => undefined });
  return { auth, api: fakeApi(() => null).api };
}

const routes = (
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/" element={<p>dashboard</p>} />
  </Routes>
);

describe('LoginPage', () => {
  it('signs in and continues to the app', async () => {
    const login = vi.fn(async () => token('t'));
    const s = session(login);
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await userEvent.type(screen.getByLabelText('Email'), 'analyst@acme.test');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(screen.getByText('dashboard')).toBeInTheDocument());
    expect(login).toHaveBeenCalledWith('analyst@acme.test', 'correct horse', null);
  });

  it('shows a generic failure with the request id', async () => {
    const s = session(
      vi.fn(async () => {
        throw apiError(401, 'invalid_credentials', 'invalid credentials', 'req-login-42');
      }),
    );
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await userEvent.type(screen.getByLabelText('Email'), 'a@acme.test');
    await userEvent.type(screen.getByLabelText('Password'), 'nope');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/Sign-in failed/)).toBeInTheDocument();
    expect(screen.getByText('req-login-42')).toBeInTheDocument();
  });

  it('explains an expired session', async () => {
    const s = session();
    await s.auth.login('a@acme.test', 'pw', null);
    s.auth.expire();
    renderWithSession(routes, s, { route: '/login' });
    expect(screen.getByText(/session has expired/)).toBeInTheDocument();
  });
});
