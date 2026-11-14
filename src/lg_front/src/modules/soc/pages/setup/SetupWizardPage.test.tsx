import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { OnboardingStatusOut, SetupOut } from '../../api/types';
import { can } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import { fakeApi, renderWithSession, signedInSession } from '../../../../test/helpers';
import PovPage from '../PovPage';
import { SetupCallout } from './SetupCallout';
import SetupWizardPage from './SetupWizardPage';
import { asProfileId, initialProfile } from './steps';
import { residencyText } from './useSetup';

const PROFILES: SetupOut['llm_profiles'] = [
  {
    id: 'mistral_eu',
    label: 'Mistral AI (EU)',
    residency: 'eu',
    description: "Mistral's API, hosted in the EU.",
    provider: 'openai',
    fast_model: 'mistral-small-latest',
    deep_model: 'mistral-medium-latest',
    env: [
      { name: 'LG_SOTF_LLM__PROVIDER', value: 'openai' },
      { name: 'LG_SOTF_LLM__BASE_URL', value: 'https://api.mistral.ai/v1' },
    ],
  },
  {
    id: 'ollama_local',
    label: 'Ollama on this server (local)',
    residency: 'local',
    description: 'A model served by Ollama next to LG-SOTF.',
    provider: 'ollama',
    fast_model: 'qwen3:8b',
    deep_model: 'qwen3:8b',
    env: [{ name: 'LG_SOTF_LLM__PROVIDER', value: 'ollama' }],
  },
  {
    id: 'anthropic',
    label: 'Anthropic (outside the EU)',
    residency: 'us',
    description: "Anthropic's API.",
    provider: 'anthropic',
    fast_model: 'claude-haiku-4-5',
    deep_model: 'claude-opus-5-5',
    env: [{ name: 'LG_SOTF_LLM__PROVIDER', value: 'anthropic' }],
  },
];

function setupOut(overrides: Partial<SetupOut> = {}): SetupOut {
  return {
    completed: false,
    completed_at: null,
    tenant_id: 'acme',
    tenant_name: 'Default',
    organisation: null,
    llm_profile: null,
    default_llm_profile: 'mistral_eu',
    configured_llm: { provider: 'fake', enabled: true, fast_model: 'fake-fast', deep_model: 'fake-deep', residency: 'offline', profile: null },
    llm_profiles: PROFILES,
    ...overrides,
  };
}

function statusOut(overrides: Partial<OnboardingStatusOut> = {}): OnboardingStatusOut {
  return { tenant_id: 'acme', steps: [], completed: 0, total: 4, complete: false, dismissed: false, samples_sent: false, first_verdict: false, ...overrides };
}

/** The API as the wizard drives it: setup state, MFA, the model test, samples and their triage. */
function wizardApi() {
  let setup = setupOut();
  let status = statusOut();
  return fakeApi((method, path, body) => {
    if (path === '/onboarding/setup' && method === 'PUT') {
      const b = body as { organisation: string; tenant_name: string; llm_profile: string | null };
      setup = { ...setup, organisation: b.organisation, tenant_name: b.tenant_name, llm_profile: b.llm_profile };
      return setup;
    }
    if (path === '/onboarding/setup/complete') {
      setup = { ...setup, completed: true, completed_at: '2026-11-07T10:00:00Z' };
      return setup;
    }
    if (path === '/onboarding/setup') return setup;
    if (path === '/auth/mfa') return { available: true, enabled: false, required: false };
    if (path === '/tenant/llm/test') {
      return { provider: 'fake', enabled: true, ok: true, tiers: [{ tier: 'fast', model: 'fake-fast', ok: true, latency_ms: 3, structured_output: 'json_schema', error_code: null, error: null }] };
    }
    if (path === '/onboarding/sample-alerts') {
      status = { ...status, samples_sent: true, first_verdict: true };
      return { source_id: 'demo:samples', received: 5, inserted: 5, duplicates: 0, enqueued: 5, alert_ids: [] };
    }
    if (path === '/onboarding/status') return status;
    throw new Error(`unexpected ${method} ${path}`);
  });
}

function App() {
  return (
    <Routes>
      <Route path="/setup" element={<SetupWizardPage />} />
      <Route path="/pov" element={<PovPage />} />
      <Route path="/" element={<SetupCallout />} />
    </Routes>
  );
}

describe('first-run setup wizard', () => {
  it('walks from the admin to the first triaged alert and lands on the Overview with the PoV link', async () => {
    const user = userEvent.setup();
    const { api, calls } = wizardApi();
    renderWithSession(<App />, await signedInSession(api, { role: 'admin', is_platform_admin: true, email: 'root@acme.test' }), { route: '/setup' });

    // 1. The admin.
    expect(await screen.findByRole('heading', { name: 'Step 1 of 5: Your account' })).toBeInTheDocument();
    expect(screen.getByText('root@acme.test')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Account security' })).toHaveAttribute('href', '/account');
    expect(within(screen.getByRole('list', { name: 'Setup steps' })).getByText('Your account').closest('li')).toHaveAttribute('aria-current', 'step');
    await user.click(screen.getByRole('button', { name: 'Confirm and continue' }));

    // 2. Organisation and tenant.
    const step2 = await screen.findByRole('heading', { name: 'Step 2 of 5: Organisation' });
    expect(step2).toHaveFocus();
    const save = screen.getByRole('button', { name: 'Save and continue' });
    expect(save).toBeDisabled();
    await user.type(screen.getByLabelText('Organisation'), 'Acme Group');
    await user.clear(screen.getByLabelText('First tenant'));
    await user.type(screen.getByLabelText('First tenant'), 'Acme SOC');
    await user.click(save);

    // 3. The model: EU by default, the configured offline model is flagged, the test runs.
    await screen.findByRole('heading', { name: 'Step 3 of 5: Language model' });
    expect(screen.getByRole('radio', { name: /Mistral AI \(EU\)/ })).toBeChecked();
    expect(screen.getByText(/Configured now: fake, offline demo model/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Settings for Mistral AI (EU)' })).toHaveTextContent('LG_SOTF_LLM__BASE_URL=https://api.mistral.ai/v1');
    await user.click(screen.getByRole('radio', { name: /Ollama on this server/ }));
    expect(screen.getByRole('region', { name: 'Settings for Ollama on this server (local)' })).toHaveTextContent('LG_SOTF_LLM__PROVIDER=ollama');
    await user.click(screen.getByRole('button', { name: 'Test model' }));
    expect(await screen.findByText('both tiers answered')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save and continue' }));

    // 4. Sample alerts until the first verdict.
    await screen.findByRole('heading', { name: 'Step 4 of 5: Sample alerts' });
    expect(screen.getByText('No sample alerts sent yet.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Send sample alerts' }));
    expect(await screen.findByText(/First alert triaged/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'See how the alerts were triaged' })).toHaveAttribute('href', '/alerts?view=all');
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    // 5. Finish: the summary, then the Overview's proof-of-value link.
    await screen.findByRole('heading', { name: 'Step 5 of 5: Finish' });
    expect(screen.getByText('Acme Group')).toBeInTheDocument();
    expect(screen.getByText('Ollama on this server (local)')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Finish setup' }));
    const pov = await screen.findByRole('link', { name: 'Start a proof of value' });
    expect(screen.getByText('Setup complete')).toBeInTheDocument();
    await user.click(pov);
    expect(await screen.findByRole('heading', { name: 'Proof of value', level: 1 })).toBeInTheDocument();

    const puts = calls.filter((c) => c.method === 'PUT');
    expect(puts.map((c) => c.body)).toEqual([
      { organisation: 'Acme Group', tenant_name: 'Acme SOC', llm_profile: null },
      { organisation: 'Acme Group', tenant_name: 'Acme SOC', llm_profile: 'ollama_local' },
    ]);
    expect(calls.find((c) => c.path === '/onboarding/setup/complete')?.body).toEqual({ skipped: false });
  });

  it('goes back a step and can be skipped', async () => {
    const user = userEvent.setup();
    const { api, calls } = wizardApi();
    renderWithSession(<App />, await signedInSession(api, { role: 'admin', is_platform_admin: true }), { route: '/setup' });
    await user.click(await screen.findByRole('button', { name: 'Confirm and continue' }));
    await user.click(await screen.findByRole('button', { name: 'Back' }));
    expect(await screen.findByRole('heading', { name: 'Step 1 of 5: Your account' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Skip setup' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/onboarding/setup/complete')?.body).toEqual({ skipped: true }));
    // Skipped: back on the Overview, no notice (setup counts as done).
    await waitFor(() => expect(screen.queryByRole('heading', { name: /Step/ })).not.toBeInTheDocument());
    expect(screen.queryByText('Setup complete')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Start setup' })).not.toBeInTheDocument();
  });

  it('says when setup is already done', async () => {
    const { api } = fakeApi((_m, path) => (path === '/auth/mfa' ? { available: true, enabled: true, required: true } : setupOut({ completed: true, completed_at: '2026-11-07T10:00:00Z' })));
    renderWithSession(<SetupWizardPage />, await signedInSession(api, { role: 'admin', is_platform_admin: true }));
    expect(await screen.findByText('Setup is complete')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Skip setup' })).not.toBeInTheDocument();
    expect(await screen.findByText('on')).toBeInTheDocument();
  });
});

describe('the Overview setup callout', () => {
  it('invites the platform admin until setup is done', async () => {
    const { api } = fakeApi(() => setupOut());
    renderWithSession(<SetupCallout />, await signedInSession(api, { role: 'admin', is_platform_admin: true }));
    expect(await screen.findByRole('link', { name: 'Start setup' })).toHaveAttribute('href', '/setup');
    expect(screen.getByRole('heading', { name: 'Finish setting up LG-SOTF' })).toBeInTheDocument();
  });

  it('never asks for anyone but a platform admin in their home tenant', async () => {
    const { api, calls } = fakeApi(() => setupOut());
    renderWithSession(<SetupCallout />, await signedInSession(api, { role: 'admin' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toEqual([]);
    expect(screen.queryByRole('link', { name: 'Start setup' })).not.toBeInTheDocument();
  });
});

describe('setup helpers', () => {
  const p = (overrides: Partial<Principal>): Principal => ({
    userId: 'u-1',
    email: 'a@acme.test',
    role: 'admin',
    tenantId: 'acme',
    homeTenantId: 'acme',
    isPlatformAdmin: true,
    method: 'password',
    ...overrides,
  });

  it('gates the wizard', () => {
    expect(can.setup(p({}))).toBe(true);
    expect(can.setup(p({ isPlatformAdmin: false }))).toBe(false);
    expect(can.setup(p({ tenantId: 'other' }))).toBe(false);
    expect(can.setup(p({ userId: null }))).toBe(false);
    expect(can.setup(p({ role: 'analyst' }))).toBe(false);
    expect(can.setup(null)).toBe(false);
  });

  it('preselects the saved pick, then an EU or local configured model, then the default', () => {
    expect(initialProfile(setupOut({ llm_profile: 'anthropic' }))).toBe('anthropic');
    const ollama = setupOut({ configured_llm: { ...setupOut().configured_llm, provider: 'ollama', residency: 'local', profile: 'ollama_local' } });
    expect(initialProfile(ollama)).toBe('ollama_local');
    const us = setupOut({ configured_llm: { ...setupOut().configured_llm, provider: 'anthropic', residency: 'us', profile: 'anthropic' } });
    expect(initialProfile(us)).toBe('mistral_eu');
    expect(asProfileId('nope')).toBeNull();
    expect(residencyText('cn')).toEqual({ label: 'Hosted in China', flag: true });
    expect(residencyText('from-a-newer-api').label).toBe('Hosting region unknown');
  });
});
