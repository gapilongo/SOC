import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { DeliveryOut, IntegrationCreateIn, IntegrationOut } from '../../api/types';
import { safeHref } from '../../components/TicketLinks';
import { fakeApi, renderWithSession, signedInSession } from '../../test/helpers';
import { describeResult } from './DeliveryLog';
import IntegrationsPage from './IntegrationsPage';
import { buildIntegrationConfig, eventsFor, splitIntegrationConfig } from './specs';

function integration(overrides: Partial<IntegrationOut> = {}): IntegrationOut {
  return {
    id: 'int-1',
    tenant_id: 'acme',
    kind: 'slack',
    name: 'SOC channel',
    enabled: true,
    events: ['escalation.created'],
    min_severity: 'medium',
    config: { channel_label: '#soc' },
    secrets: { webhook_url: true, bot_token: false, signing_secret: false },
    created_at: '2026-09-30T10:00:00Z',
    updated_at: '2026-09-30T10:00:00Z',
    ...overrides,
  };
}

const delivery: DeliveryOut = {
  id: 'd-1',
  event_id: 'e-1',
  event_type: 'escalation.created',
  operation: 'notify',
  status: 'dead',
  attempts: 8,
  next_attempt_at: '2026-09-30T10:00:00Z',
  last_error: 'DeliveryError: HTTP 404: no_service',
  title: 'Beacon from ws-042',
  created_at: '2026-09-30T09:00:00Z',
};

describe('integration form helpers', () => {
  it('builds typed config and keeps unknown keys from the JSON box', () => {
    const config = buildIntegrationConfig(
      'email',
      { recipients: 'soc@example.com, oncall@example.com', rate_limit_per_minute: '10' },
      {},
      '{"subject_prefix": "[SOC]"}',
    );
    expect(config).toEqual({ recipients: ['soc@example.com', 'oncall@example.com'], rate_limit_per_minute: 10, subject_prefix: '[SOC]' });
    expect(() => buildIntegrationConfig('slack', { rate_limit_per_minute: 'fast' }, {}, '')).toThrow(/whole number/);
    expect(() => buildIntegrationConfig('slack', {}, {}, '[1]')).toThrow(/JSON object/);
  });

  it('round-trips stored config, booleans default as the server does', () => {
    const split = splitIntegrationConfig('jira', { base_url: 'https://a.atlassian.net', labels: ['lg-sotf', 'soc'], priority_map: { high: 'High' } });
    expect(split.values).toMatchObject({ base_url: 'https://a.atlassian.net', labels: 'lg-sotf, soc' });
    expect(split.flags).toEqual({ comment_on_decision: true, response_actions: true });
    expect(JSON.parse(split.extra)).toEqual({ priority_map: { high: 'High' } });
  });

  it('offers only ticket events to ticketing integrations', () => {
    expect(eventsFor('jira')).toEqual(['escalation.created', 'escalation.decided']);
    expect(eventsFor('slack')).toContain('alert.critical_received');
  });

  it('summarises delivery results and refuses non-http ticket links', () => {
    expect(describeResult({ ...delivery, status: 'sent', last_error: null, result: { ticket: 'SOC-7', created: false } })).toBe('ticket SOC-7 (existing)');
    expect(describeResult({ ...delivery, result: { http_status: 200 } })).toBe('HTTP 200');
    expect(safeHref('javascript:alert(1)')).toBeNull();
    expect(safeHref('https://acme.atlassian.net/browse/SOC-7')).toBe('https://acme.atlassian.net/browse/SOC-7');
  });
});

describe('IntegrationsPage', () => {
  it('lists integrations, sends a test and shows the delivery log', async () => {
    const { api, calls } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/integrations') return [integration()];
      if (method === 'POST' && path === '/integrations/int-1/test') return { ok: true, detail: 'test message delivered', http_status: 200 };
      if (method === 'GET' && path === '/integrations/int-1/deliveries') return [delivery];
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<IntegrationsPage />, session);

    const row = (await screen.findByText('SOC channel')).closest('tr') as HTMLElement;
    expect(within(row).getByText('Slack')).toBeInTheDocument();
    await userEvent.click(within(row).getByRole('button', { name: 'Test SOC channel' }));
    await screen.findByText(/test message delivered/);
    await userEvent.click(within(row).getByRole('button', { name: 'Delivery log of SOC channel' }));
    expect(await screen.findByText(/HTTP 404: no_service/)).toBeInTheDocument();
    expect(calls.map((c) => `${c.method} ${c.path}`)).toContain('POST /integrations/int-1/test');
  });

  it('lists a kind from a newer API by its name and offers no form for it', async () => {
    const { api } = fakeApi((method, path) => {
      if (method === 'GET' && path === '/integrations') return [integration({ kind: 'pagerduty', name: 'On-call', secrets: {} })];
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<IntegrationsPage />, session);
    const row = (await screen.findByText('On-call')).closest('tr') as HTMLElement;
    expect(within(row).getByText('pagerduty')).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: 'Edit On-call' })).toBeDisabled();
    expect(within(row).getByRole('button', { name: 'Delete On-call' })).toBeEnabled();
  });

  it('creates a Teams integration with write-only credentials', async () => {
    const { api, calls } = fakeApi((method, path, body) => {
      if (method === 'GET' && path === '/integrations') return [];
      if (method === 'POST' && path === '/integrations') return integration({ ...(body as IntegrationCreateIn), id: 'int-2', secrets: { webhook_url: true } });
      throw new Error(`unexpected ${method} ${path}`);
    });
    const session = await signedInSession(api, { role: 'admin' });
    renderWithSession(<IntegrationsPage />, session);

    await userEvent.click(await screen.findByRole('button', { name: 'Add integration' }));
    await userEvent.selectOptions(screen.getByLabelText('Kind'), 'teams');
    expect(screen.getByText(/Office 365 connectors are retired/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Name'), 'Teams SOC');
    await userEvent.type(screen.getByLabelText(/Workflow webhook URL/), 'https://prod-00.westeurope.logic.azure.com/wf');
    await userEvent.click(screen.getByLabelText('Critical alert received'));
    await userEvent.click(screen.getByRole('button', { name: 'Create integration' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/integrations')).toBe(true));
    const body = calls.find((c) => c.method === 'POST' && c.path === '/integrations')?.body as IntegrationCreateIn;
    expect(body.kind).toBe('teams');
    expect(body.secret).toEqual({ webhook_url: 'https://prod-00.westeurope.logic.azure.com/wf' });
    expect(body.events).toContain('alert.critical_received');
  });
});
