/**
 * First-run checklist (tenant admins): the full list on the Getting started
 * page and a dismissible banner on the dashboard. The state is computed by
 * the API from the tenant's own data (`/onboarding/status`).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, Circle, Send, X } from 'lucide-react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../../../api/endpoints';
import { afterAlertsAdded, afterOnboardingChange } from '../../../../api/invalidate';
import { qk } from '../../../../api/queryKeys';
import type { OnboardingStatusOut, OnboardingStepOut } from '../../../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { useToast } from '../../../../components/Toast';
import { Button, cx } from '../../../../components/ui';

export interface StepText {
  title: string;
  description: string;
  to: string;
  action: string;
}

export const STEP_TEXT: Record<string, StepText> = {
  source_connected: {
    title: 'Connect an alert source',
    description: 'Register your SIEM or EDR, or push alerts to the ingest API with an API key.',
    to: '/sources',
    action: 'Open sources',
  },
  notifications_configured: {
    title: 'Configure notifications',
    description: 'Send escalations to chat or e-mail so nobody has to watch the console.',
    to: '/integrations',
    action: 'Open integrations',
  },
  teammate_invited: {
    title: 'Invite a teammate',
    description: 'Add analysts who will review escalations and approve actions.',
    to: '/users',
    action: 'Open users',
  },
  autonomy_reviewed: {
    title: 'Review the autonomy policy',
    description: 'Decide which response actions may run on their own and which need an approval.',
    to: '/settings',
    action: 'Open settings',
  },
  first_alert_triaged: {
    title: 'See your first alert triaged',
    description: 'Once an alert has a verdict you can review how the analysis reached it. Sample alerts count.',
    to: '/alerts',
    action: 'Open alerts',
  },
};

export function useOnboardingStatus(enabled = true) {
  const api = useApi();
  return useQuery({
    queryKey: qk.onboarding.all,
    queryFn: ({ signal }) => endpoints.onboardingStatus(api, signal),
    enabled,
    staleTime: 30_000,
  });
}

function useOnboardingMutation<T>(fn: () => Promise<T>, onDone: (out: T) => void) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: (out) => {
      onDone(out);
      void afterOnboardingChange(client);
    },
  });
}

export function useSendSamples() {
  const api = useApi();
  const toast = useToast();
  const client = useQueryClient();
  return useOnboardingMutation(
    () => endpoints.sendSampleAlerts(api),
    (out) => {
      void afterAlertsAdded(client);
      toast.success(
        out.inserted
          ? `${out.inserted} sample alerts sent; they are being triaged now.`
          : 'The sample alerts were already sent; nothing new was added.',
      );
    },
  );
}

export function useDismissOnboarding() {
  const api = useApi();
  const client = useQueryClient();
  return useOnboardingMutation(
    () => endpoints.dismissOnboarding(api),
    (out: OnboardingStatusOut) => client.setQueryData(qk.onboarding.all, out),
  );
}

export function useMarkReviewed() {
  const api = useApi();
  const client = useQueryClient();
  return useOnboardingMutation(
    () => endpoints.markAutonomyReviewed(api),
    (out: OnboardingStatusOut) => client.setQueryData(qk.onboarding.all, out),
  );
}

/** Steps that count towards completion (an unavailable one, e.g. without the integrations feature, is hidden). */
export function visibleSteps(status: OnboardingStatusOut): OnboardingStepOut[] {
  return status.steps.filter((s) => s.available && STEP_TEXT[s.id]);
}

function StepIcon({ done }: { done: boolean }) {
  return done ? (
    <CheckCircle2 className="h-5 w-5 flex-none text-ok-fg" aria-hidden="true" />
  ) : (
    <Circle className="h-5 w-5 flex-none text-muted" aria-hidden="true" />
  );
}

export function OnboardingChecklist({ status }: { status: OnboardingStatusOut }) {
  const reviewed = useMarkReviewed();
  return (
    <ol className="space-y-3" aria-label="Getting started steps">
      {visibleSteps(status).map((step) => {
        const text = STEP_TEXT[step.id];
        return (
          <li key={step.id} className="flex flex-wrap items-start gap-x-3 gap-y-2 rounded-control border border-subtle bg-canvas/50 p-3">
            <StepIcon done={step.done} />
            {/* At least 12rem of text: on a phone the links move under it instead of squeezing it. */}
            <div className="min-w-[min(12rem,100%)] flex-1">
              <p className={cx('text-sm font-medium', step.done ? 'text-secondary' : 'text-fg')}>
                {text.title}
                <span className="sr-only">{step.done ? ' (done)' : ' (to do)'}</span>
              </p>
              <p className="mt-0.5 text-sm text-muted">{text.description}</p>
            </div>
            <div className="ml-auto flex flex-none flex-wrap items-center gap-2">
              {step.id === 'autonomy_reviewed' && !step.done && (
                <Button size="sm" variant="quiet" busy={reviewed.isPending} onClick={() => reviewed.mutate()}>
                  Mark reviewed
                </Button>
              )}
              <Link
                to={text.to}
                className="rounded-control border border-control px-2.5 py-1 text-xs text-fg hover:bg-raised-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus"
              >
                {text.action}
              </Link>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function SampleAlertsButton({ sent }: { sent: boolean }) {
  const send = useSendSamples();
  return (
    <Button
      variant={sent ? 'secondary' : 'primary'}
      size="sm"
      busy={send.isPending}
      onClick={() => send.mutate()}
      icon={<Send className="h-3.5 w-3.5" aria-hidden="true" />}
      title="Five synthetic alerts with reserved test indicators; sending them again adds nothing."
    >
      {sent ? 'Send sample alerts again' : 'Send sample alerts'}
    </Button>
  );
}

/** Dashboard banner: progress, the next steps, sample alerts; hidden once dismissed or complete. */
export function OnboardingBanner() {
  const status = useOnboardingStatus();
  const dismiss = useDismissOnboarding();
  const s = status.data;
  if (!s || s.dismissed || s.complete) return null;
  const steps = visibleSteps(s);
  const next = steps.filter((step) => !step.done).slice(0, 3);
  return (
    <section aria-label="Getting started" className="mb-5 rounded-card border border-link/50 bg-tint-info p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-fg">
            Getting started: {s.completed} of {s.total} done
          </h2>
          <ul className="mt-2 space-y-1 text-sm text-link">
            {next.map((step) => (
              <li key={step.id} className="flex items-center gap-2">
                <StepIcon done={false} />
                <Link to={STEP_TEXT[step.id].to} className="hover:underline">
                  {STEP_TEXT[step.id].title}
                </Link>
              </li>
            ))}
          </ul>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SampleAlertsButton sent={s.samples_sent} />
          <Link to="/getting-started" className="text-sm text-link hover:underline">
            All steps
          </Link>
          <Button
            size="sm"
            variant="quiet"
            aria-label="Dismiss the getting started banner"
            busy={dismiss.isPending}
            onClick={() => dismiss.mutate()}
            icon={<X className="h-4 w-4" aria-hidden="true" />}
          />
        </div>
      </div>
    </section>
  );
}
