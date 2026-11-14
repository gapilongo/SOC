import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { MfaStatusOut } from '../api/types';
import { fakeApi, renderWithSession, signedInSession, user } from '../../../test/helpers';
import AccountSecurityPage from './AccountSecurityPage';
import UsersPage from './UsersPage';

describe('AccountSecurityPage', () => {
  it('enrolls an authenticator and shows the recovery codes once', async () => {
    let status: MfaStatusOut = { available: true, enabled: false, required: true, recovery_codes_remaining: 0 };
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/auth/mfa') return status;
      if (path === '/auth/mfa/enroll') return { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr: ['1'], expires_in: 900 };
      if (path === '/auth/mfa/confirm') {
        status = { available: true, enabled: true, enabled_at: '2026-09-30T10:00:00Z', required: true, recovery_codes_remaining: 10 };
        return { recovery_codes: ['aaaaa-bbbbb', 'ccccc-ddddd'] };
      }
      return null;
    });
    renderWithSession(<AccountSecurityPage />, await signedInSession(api));
    expect(await screen.findByText(/organisation requires two-step verification/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Set up authenticator app' }));
    expect(await screen.findByRole('img', { name: /QR code/ })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Authentication code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Turn on two-step verification' }));
    const dialog = await screen.findByRole('dialog', { name: 'Your recovery codes' });
    expect(within(dialog).getByTestId('recovery-codes')).toHaveTextContent('ccccc-ddddd');
    expect(calls.find((c) => c.path === '/auth/mfa/confirm')?.body).toEqual({ code: '123456' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'I have saved them' }));
    expect(await screen.findByText('Recovery codes left')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Turn off' })).toBeInTheDocument();
  });

  it('explains that single sign-on accounts use the identity provider', async () => {
    const { api } = fakeApi(() => ({ available: false, enabled: false, required: false }));
    renderWithSession(<AccountSecurityPage />, await signedInSession(api));
    expect(await screen.findByText(/no local password/)).toBeInTheDocument();
  });
});

describe('UsersPage MFA', () => {
  it('shows MFA status and resets it after confirmation', async () => {
    const people = [
      user({ id: 'u-1', email: 'me@acme.test', role: 'admin', mfa_enabled: true }),
      user({ id: 'u-2', email: 'lost@acme.test', mfa_enabled: true }),
      user({ id: 'u-3', email: 'sso@acme.test', oidc_provisioned: true }),
    ];
    const { api, calls } = fakeApi((method, path) => (method === 'GET' && path === '/users' ? people : method === 'GET' ? [] : null));
    renderWithSession(<UsersPage />, await signedInSession(api, { id: 'u-1', role: 'admin' }));
    expect(await screen.findByTestId('mfa-u-2')).toHaveTextContent('on');
    expect(screen.getByTestId('mfa-u-3')).toHaveTextContent('SSO');
    // No reset for yourself (use Account security) or for accounts without MFA.
    expect(screen.queryByRole('button', { name: 'Reset MFA of me@acme.test' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reset MFA of sso@acme.test' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Reset MFA of lost@acme.test' }));
    const dialog = await screen.findByRole('dialog', { name: 'Reset MFA' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reset MFA' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/users/u-2/mfa/reset')).toBe(true));
  });
});
