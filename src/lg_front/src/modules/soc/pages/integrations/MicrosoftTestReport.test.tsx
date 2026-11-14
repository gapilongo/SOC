import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { MicrosoftTestReport as Report } from '../../../../api/types';
import { MicrosoftTestReport } from './MicrosoftTestReport';

const REPORT: Report = {
  ok: false,
  tokens: {
    graph: { status: 'failed', error: 'consent_missing', aadsts: 65001, hint: 'admin consent is missing', roles: null },
    defender: { status: 'ok', roles: ['Machine.Isolate'] },
  },
  capabilities: {
    'defender.isolation': {
      status: 'missing_permission',
      enabled: true,
      live: false,
      permissions: [
        { role: 'Machine.Isolate', api: 'defender', status: 'granted', via: 'token', required: true },
        { role: 'Machine.Read.All', api: 'defender', status: 'missing', via: 'token', required: true },
      ],
      checks: [{ name: 'list machines', status: 'forbidden', detail: 'HTTP 403 Forbidden' }],
    },
    'entra.account': {
      status: 'not_enabled',
      enabled: false,
      live: false,
      permissions: [
        { role: 'User Administrator', api: 'graph', status: 'unknown', via: 'directory_role', required: true, guidance: 'assign the role' },
      ],
      checks: [],
    },
  },
  certificate: { thumbprint_sha1: 'A'.repeat(40), thumbprint_sha256: 'B'.repeat(64), not_after: '2027-01-01T00:00:00Z', days_left: 90 },
};

describe('MicrosoftTestReport', () => {
  it('shows the token panel and the capability x permission matrix', () => {
    render(<MicrosoftTestReport report={REPORT} />);
    const tokens = screen.getByRole('region', { name: 'Tokens' });
    expect(within(tokens).getByText('Consent missing')).toBeInTheDocument();
    expect(within(tokens).getByText('AADSTS65001')).toBeInTheDocument();
    expect(within(tokens).getByText('admin consent is missing')).toBeInTheDocument();
    expect(within(tokens).getByText(/Roles in the token: Machine.Isolate/)).toBeInTheDocument();

    const table = screen.getByRole('table', { name: 'Capabilities and permissions' });
    const isolation = within(table).getByRole('row', { name: /defender.isolation/ });
    expect(within(isolation).getByText('Missing permission')).toBeInTheDocument();
    expect(within(isolation).getByText('missing')).toBeInTheDocument();
    expect(within(isolation).getByText('granted')).toBeInTheDocument();
    expect(within(isolation).getByText(/list machines: HTTP 403 Forbidden/)).toBeInTheDocument();
    const account = within(table).getByRole('row', { name: /entra.account/ });
    expect(within(account).getByText('unknown')).toBeInTheDocument();
    expect(within(account).getByText(/directory role/i)).toBeInTheDocument();
    expect(screen.getByText(/expires .* \(\s*90 days\)/)).toBeInTheDocument();
  });

  it('works with zero capabilities', () => {
    render(<MicrosoftTestReport report={{ ok: true, tokens: { graph: { status: 'ok', roles: [] } }, capabilities: {} }} />);
    expect(screen.getByText('No capability is installed yet.')).toBeInTheDocument();
    expect(screen.getByText('Roles in the token: none')).toBeInTheDocument();
    expect(screen.queryByText(/admin consent missing/)).not.toBeInTheDocument();
  });

  it('does not ask for admin consent for the Exchange RBAC only mail setup', () => {
    const mail: Report = {
      ok: true,
      tokens: { graph: { status: 'ok', roles: [] } },
      capabilities: {
        'mail.remediate': {
          status: 'ok',
          enabled: true,
          live: true,
          permissions: [
            { role: 'Mail.ReadWrite', api: 'graph', status: 'unknown', via: 'token', required: true, guidance: 'not in the token' },
            { role: 'Application Mail.ReadWrite', api: 'graph', status: 'unknown', via: 'exchange_rbac', required: true },
          ],
          checks: [{ name: 'mailbox access', status: 'ok' }],
        },
      },
    };
    render(<MicrosoftTestReport report={mail} />);
    expect(screen.getByText('Roles in the token: none')).toBeInTheDocument();
    expect(screen.queryByText(/admin consent missing/)).not.toBeInTheDocument();
  });

  it('asks for admin consent when an enabled capability lacks a token permission', () => {
    const missing: Report = {
      ok: false,
      tokens: { graph: { status: 'ok', roles: [] } },
      capabilities: {
        'entra.account': {
          status: 'missing_permission',
          enabled: true,
          live: false,
          permissions: [{ role: 'User.EnableDisableAccount.All', api: 'graph', status: 'missing', via: 'token', required: true }],
          checks: [],
        },
      },
    };
    render(<MicrosoftTestReport report={missing} />);
    expect(screen.getByText(/none \(admin consent missing\?\)/)).toBeInTheDocument();
  });

  it('shows the warning of a tenant-wide grant', () => {
    const warned: Report = {
      ok: true,
      tokens: { graph: { status: 'ok', roles: ['Mail.Send'] } },
      capabilities: {
        'mail.notify': {
          status: 'ok',
          enabled: true,
          live: false,
          permissions: [
            { role: 'Mail.Send', api: 'graph', status: 'granted', via: 'token', required: true, warning: 'granted tenant-wide by Entra admin consent' },
          ],
          checks: [],
        },
      },
    };
    render(<MicrosoftTestReport report={warned} />);
    expect(screen.getByText('granted tenant-wide by Entra admin consent')).toBeInTheDocument();
  });
});
