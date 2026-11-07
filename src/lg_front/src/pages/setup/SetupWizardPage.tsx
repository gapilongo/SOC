/**
 * First-run setup wizard (the install's platform admin): confirm the admin,
 * name the organisation and the first tenant, pick and test the language
 * model, send sample alerts, then land on the Overview with a link to start a
 * proof of value. Every step can be revisited; nothing here changes the
 * running model, which is install configuration.
 */

import { Check } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Banner, Button, Card, ErrorMessage, LoadingState, PageHeader, cx } from '../../components/ui';
import { formatDateTime } from '../../lib/format';
import { AdminStep, FinishStep, ModelStep, OrganisationStep, SamplesStep } from './steps';
import { useCompleteSetup, useSetup } from './useSetup';

export const SETUP_STEPS = ['Your account', 'Organisation', 'Language model', 'Sample alerts', 'Finish'] as const;

/** Router state the Overview reads to show the "setup complete" banner once. */
export interface SetupDoneState {
  setupDone: true;
}

function Stepper({ current }: { current: number }) {
  return (
    <ol aria-label="Setup steps" className="mb-5 flex flex-wrap gap-2">
      {SETUP_STEPS.map((label, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li
            key={label}
            aria-current={active ? 'step' : undefined}
            className={cx(
              'flex items-center gap-2 rounded-control border px-2.5 py-1 text-xs',
              active ? 'border-focus bg-raised font-semibold text-fg' : 'border-subtle text-secondary',
            )}
          >
            <span
              className={cx(
                'flex h-5 w-5 flex-none items-center justify-center rounded-full border text-xs tabular-nums',
                done ? 'border-ok-fg text-ok-fg' : 'border-control',
              )}
              aria-hidden="true"
            >
              {done ? <Check className="h-3 w-3" strokeWidth={2.5} /> : i + 1}
            </span>
            {/* Phones show the current step's name only; the others keep theirs for screen readers. */}
            <span className={active ? undefined : 'sr-only sm:not-sr-only'}>
              {label}
              {done && <span className="sr-only"> (done)</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

export default function SetupWizardPage() {
  const q = useSetup();
  const complete = useCompleteSetup();
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const moved = useRef(false);

  // Keyboard and screen-reader users land on the new step's title, not at the top of the page.
  useEffect(() => {
    if (moved.current) heading.current?.focus();
    moved.current = true;
  }, [step]);

  const go = (to: number) => setStep(Math.max(0, Math.min(SETUP_STEPS.length - 1, to)));
  const next = () => go(step + 1);
  const back = () => go(step - 1);
  const finish = (skipped: boolean) =>
    complete.mutate(skipped, {
      onSuccess: () => navigate('/', skipped ? undefined : { state: { setupDone: true } satisfies SetupDoneState }),
    });

  const s = q.data;
  return (
    <>
      <PageHeader
        title="Set up LG-SOTF"
        description="Five short steps take this install to its first triaged alert."
        actions={
          s && !s.completed ? (
            <Button size="sm" variant="quiet" busy={complete.isPending && complete.variables === true} onClick={() => finish(true)}>
              Skip setup
            </Button>
          ) : undefined
        }
      />
      {q.isPending && <LoadingState label="Loading setup" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {complete.error ? <ErrorMessage error={complete.error} compact /> : null}
      {s && (
        <>
          {s.completed && (
            <Banner tone="info" title="Setup is complete" className="mb-5">
              Finished {s.completed_at ? formatDateTime(s.completed_at) : ''}. You can go through the steps again; saving changes
              them.
            </Banner>
          )}
          <Stepper current={step} />
          <Card>
            <h2 ref={heading} tabIndex={-1} className="mb-3 text-base font-semibold text-fg focus:outline-none">
              Step {step + 1} of {SETUP_STEPS.length}: {SETUP_STEPS[step]}
            </h2>
            {step === 0 && <AdminStep setup={s} onNext={next} />}
            {step === 1 && <OrganisationStep setup={s} onNext={next} onBack={back} />}
            {step === 2 && <ModelStep setup={s} onNext={next} onBack={back} />}
            {step === 3 && <SamplesStep setup={s} onNext={next} onBack={back} />}
            {step === 4 && (
              <FinishStep setup={s} onBack={back} onFinish={() => finish(false)} busy={complete.isPending && complete.variables === false} />
            )}
          </Card>
        </>
      )}
    </>
  );
}
