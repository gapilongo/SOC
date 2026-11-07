/**
 * The steps of the first-run setup wizard. Each step is a form or a check
 * with one primary action that moves on; the page owns the step order.
 */

import { useQuery } from '@tanstack/react-query';
import { CheckCircle2, CircleDashed } from 'lucide-react';
import { useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { isOneOf, type LlmProfileId, type LlmProfileOut, type SetupOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { Banner, Button, DefinitionList, ErrorMessage, StatePill, TextField } from '../../components/ui';
import { alertsHref } from '../../lib/links';
import { SampleAlertsButton } from '../onboarding/Onboarding';
import { LlmTestCard } from '../settings/LlmTestCard';
import { residencyText, useSaveSetup } from './useSetup';

const PROFILE_IDS: readonly LlmProfileId[] = ['mistral_eu', 'ollama_local', 'self_hosted', 'anthropic'];

export function asProfileId(value: string | null | undefined): LlmProfileId | null {
  return isOneOf(PROFILE_IDS, value) ? value : null;
}

/** The profile to preselect: the saved pick, else the configured model when it is EU or local, else the default. */
export function initialProfile(setup: SetupOut): string {
  const configured = setup.configured_llm;
  const configuredOk = configured.profile && !residencyText(configured.residency).flag;
  return setup.llm_profile ?? (configuredOk ? configured.profile : null) ?? setup.default_llm_profile;
}

export interface StepProps {
  setup: SetupOut;
  onNext: () => void;
}

function StepActions({ children, onBack }: { children: ReactNode; onBack?: () => void }) {
  return (
    <div className="mt-5 flex flex-wrap items-center gap-2">
      {children}
      {onBack && (
        <Button variant="quiet" onClick={onBack}>
          Back
        </Button>
      )}
    </div>
  );
}

// 1. Admin ------------------------------------------------------------------

export function AdminStep({ onNext }: StepProps) {
  const api = useApi();
  const { principal } = useAuth();
  const mfa = useQuery({ queryKey: qk.mfaStatus.all, queryFn: ({ signal }) => endpoints.mfaStatus(api, signal) });
  return (
    <>
      <p className="text-sm text-secondary">
        This account administers the install: it manages tenants and their users, and is the first admin of this tenant.
      </p>
      <div className="mt-4">
        <DefinitionList
          items={[
            ['Email', principal?.email ?? '-'],
            ['Role', 'Admin and platform admin'],
            [
              'Two-step sign-in',
              mfa.data ? (
                <Badge tone={mfa.data.enabled ? 'good' : 'warn'}>{mfa.data.enabled ? 'on' : 'off'}</Badge>
              ) : (
                '-'
              ),
            ],
          ]}
        />
      </div>
      {mfa.data && !mfa.data.enabled && (
        <p className="mt-3 text-sm text-secondary">
          Turn on two-step sign-in for this account in{' '}
          <Link to="/account" className="text-link hover:underline">
            Account security
          </Link>
          ; it is required for platform admins in production.
        </p>
      )}
      <p className="mt-3 text-sm text-secondary">
        The bootstrap password is only read when the first account is created: remove{' '}
        <code className="font-mono text-xs">LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD</code> from the env file once you have signed in.
      </p>
      <StepActions>
        <Button variant="primary" onClick={onNext}>
          Confirm and continue
        </Button>
      </StepActions>
    </>
  );
}

// 2. Organisation and tenant -------------------------------------------------

export function OrganisationStep({ setup, onNext, onBack }: StepProps & { onBack: () => void }) {
  const save = useSaveSetup();
  const [organisation, setOrganisation] = useState(setup.organisation ?? '');
  const [tenantName, setTenantName] = useState(setup.tenant_name);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(
      { organisation: organisation.trim(), tenant_name: tenantName.trim(), llm_profile: asProfileId(setup.llm_profile) },
      { onSuccess: onNext },
    );
  };
  return (
    <form onSubmit={submit}>
      <div className="grid max-w-xl gap-4">
        <TextField
          label="Organisation"
          hint="Your company or, for an MSSP, your own firm. Shown on reports."
          value={organisation}
          onChange={(e) => setOrganisation(e.target.value)}
          required
          maxLength={200}
          autoComplete="organization"
        />
        <TextField
          label="First tenant"
          hint={`The tenant your alerts go to now (ID ${setup.tenant_id}, which does not change). An MSSP adds a tenant per customer later.`}
          value={tenantName}
          onChange={(e) => setTenantName(e.target.value)}
          required
          maxLength={200}
        />
      </div>
      {save.error ? (
        <div className="mt-3">
          <ErrorMessage error={save.error} compact />
        </div>
      ) : null}
      <StepActions onBack={onBack}>
        <Button type="submit" variant="primary" busy={save.isPending} disabled={!organisation.trim() || !tenantName.trim()}>
          Save and continue
        </Button>
      </StepActions>
    </form>
  );
}

// 3. Language model ------------------------------------------------------------

function ProfileOption({ profile, checked, active, onChange }: { profile: LlmProfileOut; checked: boolean; active: boolean; onChange: () => void }) {
  const where = residencyText(profile.residency);
  return (
    <label className="flex items-start gap-3 rounded-control border border-subtle bg-canvas/50 p-3 text-sm has-[:checked]:border-focus">
      <input type="radio" name="llm-profile" value={profile.id} checked={checked} onChange={onChange} className="mt-1 accent-accent" />
      <span className="min-w-0 flex-1 font-medium text-fg">
        {profile.label}
        <span className="mt-1 flex flex-wrap items-center gap-2 font-normal">
          <StatePill tone={where.flag ? 'waiting' : 'ok'}>{where.label}</StatePill>
          {active && <StatePill tone="processing">Configured now</StatePill>}
        </span>
        <span className="mt-1 block font-normal text-secondary">{profile.description}</span>
      </span>
    </label>
  );
}

function ApplyProfile({ profile }: { profile: LlmProfileOut }) {
  const lines = profile.env.map((v) => `${v.name}=${v.value}`).join('\n');
  return (
    <div className="space-y-2 text-sm">
      <p className="text-secondary">
        To use {profile.label}, set these in the env file of the api and worker services (keep the API key there, never in a
        config file), then restart both. Test the model again afterwards.
      </p>
      <pre
        role="region"
        aria-label={`Settings for ${profile.label}`}
        // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        className="overflow-x-auto rounded-control border border-subtle bg-canvas p-3 font-mono text-xs text-body"
      >
        {lines}
      </pre>
    </div>
  );
}

export function ModelStep({ setup, onNext, onBack }: StepProps & { onBack: () => void }) {
  const save = useSaveSetup();
  const [picked, setPicked] = useState(() => initialProfile(setup));
  const configured = setup.configured_llm;
  const where = residencyText(configured.residency);
  const profile = setup.llm_profiles.find((p) => p.id === picked);
  const next = () =>
    save.mutate(
      { organisation: setup.organisation ?? setup.tenant_name, tenant_name: setup.tenant_name, llm_profile: asProfileId(picked) },
      { onSuccess: onNext },
    );
  return (
    <div className="space-y-4">
      <p className="text-sm text-secondary">
        Triage sends alert data to this model. The model is set in the install's configuration; pick where it should run and
        test the one configured now.
      </p>
      <Banner
        tone={where.flag ? 'warning' : 'info'}
        title={`Configured now: ${configured.provider}, ${where.label.toLowerCase()}`}
      >
        Models <span className="font-mono">{configured.fast_model}</span> (fast) and{' '}
        <span className="font-mono">{configured.deep_model}</span> (deep).
        {where.flag && ' Pick an EU or local model below for production use.'}
      </Banner>
      <fieldset>
        <legend className="mb-2 text-ctl font-semibold text-fg">Model profile</legend>
        <div className="space-y-2">
          {setup.llm_profiles.map((p) => (
            <ProfileOption key={p.id} profile={p} checked={picked === p.id} active={configured.profile === p.id} onChange={() => setPicked(p.id)} />
          ))}
        </div>
      </fieldset>
      {profile && configured.profile !== profile.id && <ApplyProfile profile={profile} />}
      <LlmTestCard />
      {save.error ? <ErrorMessage error={save.error} compact /> : null}
      <StepActions onBack={onBack}>
        <Button variant="primary" busy={save.isPending} onClick={next}>
          Save and continue
        </Button>
      </StepActions>
    </div>
  );
}

// 4. Sample alerts -------------------------------------------------------------

function useTriageProgress() {
  const api = useApi();
  return useQuery({
    queryKey: qk.onboarding.all,
    queryFn: ({ signal }) => endpoints.onboardingStatus(api, signal),
    // Poll while the samples are on their way to a first verdict.
    refetchInterval: (query) => (query.state.data?.samples_sent && !query.state.data.first_verdict ? 2_000 : false),
  });
}

export function SamplesStep({ onNext, onBack }: StepProps & { onBack: () => void }) {
  const status = useTriageProgress();
  const s = status.data;
  const verdict = Boolean(s?.first_verdict);
  return (
    <>
      <p className="text-sm text-secondary">
        Five synthetic alerts (a brute-force login, a test-file detection, beaconing, an encoded PowerShell command and a
        scheduled scan) go through the normal pipeline and are triaged by the model. They use reserved test domains and
        addresses only and are not counted in your usage.
      </p>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <SampleAlertsButton sent={Boolean(s?.samples_sent)} />
      </div>
      <p className="mt-4 flex items-center gap-2 text-sm" role="status" aria-live="polite">
        {verdict ? (
          <CheckCircle2 className="h-5 w-5 flex-none text-ok-fg" aria-hidden="true" />
        ) : (
          <CircleDashed className="h-5 w-5 flex-none text-muted" aria-hidden="true" />
        )}
        <span className={verdict ? 'text-fg' : 'text-secondary'}>
          {!s?.samples_sent
            ? 'No sample alerts sent yet.'
            : verdict
              ? 'First alert triaged: it is closed or waiting for an analyst.'
              : 'Waiting for the first verdict...'}
        </span>
      </p>
      {verdict && (
        <p className="mt-2 text-sm">
          <Link to={alertsHref({ view: 'all' })} className="text-link hover:underline">
            See how the alerts were triaged
          </Link>
        </p>
      )}
      <StepActions onBack={onBack}>
        <Button variant={verdict ? 'primary' : 'secondary'} onClick={onNext}>
          {verdict ? 'Continue' : 'Continue without waiting'}
        </Button>
      </StepActions>
    </>
  );
}

// 5. Finish --------------------------------------------------------------------

export function FinishStep({ setup, onFinish, onBack, busy }: { setup: SetupOut; onFinish: () => void; onBack: () => void; busy: boolean }) {
  const profile = setup.llm_profiles.find((p) => p.id === setup.llm_profile);
  return (
    <>
      <DefinitionList
        items={[
          ['Organisation', setup.organisation ?? '-'],
          ['First tenant', setup.tenant_name],
          ['Model profile', profile?.label ?? 'Not picked'],
          ['Model configured now', `${setup.configured_llm.provider} (${residencyText(setup.configured_llm.residency).label.toLowerCase()})`],
        ]}
      />
      <p className="mt-4 text-sm text-secondary">
        Next: connect a real alert source, invite your analysts and start a proof of value on your own alerts. The{' '}
        <Link to="/getting-started" className="text-link hover:underline">
          Getting started
        </Link>{' '}
        page keeps the checklist.
      </p>
      <StepActions onBack={onBack}>
        <Button variant="primary" busy={busy} onClick={onFinish}>
          Finish setup
        </Button>
      </StepActions>
    </>
  );
}
