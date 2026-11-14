import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import type { LoginOut, MfaChallengeOut } from '../modules/soc/api/types';
import { AuthStore, type AuthTransport } from '../auth/store';
import { apiError, fakeApi, fakeTransport, renderWithSession, token } from '../test/helpers';
import LoginPage from './Login';

function session(login: AuthTransport['login'] = vi.fn(async () => token('t')), extra: Partial<AuthTransport> = {}) {
  const auth = new AuthStore({ transport: fakeTransport({ login, ...extra }), lock: (_n, fn) => fn(), setTimer: () => 0, clearTimer: () => undefined });
  return { auth, api: fakeApi(() => null).api };
}

function challenge(overrides: Partial<MfaChallengeOut> = {}): MfaChallengeOut {
  return { mfa_required: true, mfa_token: 'challenge-1', expires_in: 300, enrollment_required: false, methods: ['totp', 'recovery_code'], ...overrides };
}

const routes = (
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/" element={<p>dashboard</p>} />
  </Routes>
);

async function signIn(email = 'analyst@acme.test', password = 'correct horse') {
  await userEvent.type(screen.getByLabelText('Email'), email);
  await userEvent.type(screen.getByLabelText('Password'), password);
  await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
}

describe('LoginPage', () => {
  it('signs in and continues to the app', async () => {
    const login = vi.fn(async () => token('t'));
    const s = session(login);
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();
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
    await signIn('a@acme.test', 'nope');
    expect(await screen.findByText(/Sign-in failed/)).toBeInTheDocument();
    expect(screen.getByText('req-login-42')).toBeInTheDocument();
  });

  it('asks for the tenant when the account exists in several tenants', async () => {
    const s = session(
      vi.fn(async () => {
        throw apiError(401, 'tenant_required', 'enter the tenant', 'req-login-43');
      }),
    );
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn('a@acme.test');
    expect(await screen.findByText(/exists in several tenants/)).toBeInTheDocument();
  });

  it('explains an expired session', async () => {
    const s = session();
    await s.auth.login('a@acme.test', 'pw', null);
    s.auth.expire();
    renderWithSession(routes, s, { route: '/login' });
    expect(screen.getByText(/session has expired/)).toBeInTheDocument();
  });
});

describe('LoginPage two-step verification', () => {
  it('asks for an authenticator code after the password, then signs in', async () => {
    const verifyMfa = vi.fn(async () => token('after-mfa'));
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge()), { verifyMfa });
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();

    expect(await screen.findByRole('heading', { name: 'Two-step verification' })).toBeInTheDocument();
    // The password step did not start a session.
    expect(s.auth.getState().status).toBe('anonymous');
    expect(s.auth.getToken()).toBeNull();
    const field = screen.getByLabelText('Authentication code');
    expect(field).toHaveAttribute('autocomplete', 'one-time-code');
    expect(field).toHaveAttribute('inputmode', 'numeric');
    expect(field).toHaveFocus();

    await userEvent.type(field, '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(screen.getByText('dashboard')).toBeInTheDocument());
    expect(verifyMfa).toHaveBeenCalledWith('challenge-1', '123456');
    expect(s.auth.getToken()).toBe('after-mfa');
    // The challenge token is never persisted.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('keeps the step and explains a wrong code', async () => {
    const verifyMfa = vi.fn(async () => {
      throw apiError(401, 'invalid_mfa_code', 'the verification code is not valid', 'req-mfa-1');
    });
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge()), { verifyMfa });
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();
    await userEvent.type(await screen.findByLabelText('Authentication code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText(/That code is not valid/)).toBeInTheDocument();
    expect(screen.getByLabelText('Authentication code')).toHaveValue('');
    expect(s.auth.getState().status).toBe('anonymous');
  });

  it('accepts a recovery code and warns how many are left', async () => {
    const verifyMfa = vi.fn(async () => ({ ...token('after-recovery'), recovery_codes_remaining: 2 }));
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge()), { verifyMfa });
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();
    await userEvent.click(await screen.findByRole('button', { name: 'Use a recovery code' }));
    const field = screen.getByLabelText('Recovery code');
    expect(field).toHaveAttribute('inputmode', 'text');
    await userEvent.type(field, 'abcde-12345');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText(/You have 2 recovery codes left/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(screen.getByText('dashboard')).toBeInTheDocument());
    expect(verifyMfa).toHaveBeenCalledWith('challenge-1', 'abcde-12345');
  });

  it('offers no recovery code link when the challenge does not allow it', async () => {
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge({ methods: ['totp'] })));
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();
    await screen.findByLabelText('Authentication code');
    expect(screen.queryByRole('button', { name: 'Use a recovery code' })).not.toBeInTheDocument();
  });

  it('goes back to the password form when the challenge expired', async () => {
    const verifyMfa = vi.fn(async () => {
      throw apiError(401, 'invalid_mfa_token', 'expired');
    });
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge()), { verifyMfa });
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();
    await userEvent.type(await screen.findByLabelText('Authentication code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText(/verification step expired/)).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
  });

  it('forces enrollment: QR code and key, then recovery codes before entering the app', async () => {
    const enrollMfa = vi.fn(async () => ({
      secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      otpauth_uri: 'otpauth://totp/LG-SOTF:analyst%40acme.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      qr: ['101', '010', '101'],
      expires_in: 900,
    }));
    const confirmMfa = vi.fn(async () => ({ recovery_codes: ['aaaaa-bbbbb', 'ccccc-ddddd'], session: token('enrolled') }));
    const s = session(vi.fn(async (): Promise<LoginOut> => challenge({ enrollment_required: true, methods: [] })), {
      enrollMfa,
      confirmMfa,
    });
    await s.auth.init();
    renderWithSession(routes, s, { route: '/login' });
    await signIn();

    expect(await screen.findByRole('heading', { name: 'Set up two-step verification' })).toBeInTheDocument();
    expect(await screen.findByRole('img', { name: /QR code/ })).toBeInTheDocument();
    expect(screen.getByTestId('mfa-secret')).toHaveTextContent('JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP');
    expect(screen.getByRole('link', { name: /authenticator app/ })).toHaveAttribute('href', expect.stringMatching(/^otpauth:\/\/totp\//));
    expect(enrollMfa).toHaveBeenCalledTimes(1);
    expect(enrollMfa).toHaveBeenCalledWith('challenge-1');

    await userEvent.type(screen.getByLabelText('Authentication code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Turn on and sign in' }));
    expect(await screen.findByTestId('recovery-codes')).toHaveTextContent('aaaaa-bbbbb');
    expect(confirmMfa).toHaveBeenCalledWith('challenge-1', '654321');
    // The session starts only after the codes were acknowledged.
    expect(s.auth.getState().status).toBe('anonymous');
    expect(screen.queryByText('dashboard')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'I have saved my recovery codes' }));
    await waitFor(() => expect(screen.getByText('dashboard')).toBeInTheDocument());
    expect(s.auth.getToken()).toBe('enrolled');
  });
});
