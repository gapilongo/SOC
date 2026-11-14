/**
 * The proof-of-value wizard (tenant admins): name the run and pick the
 * history window, pick the shadow period, review, start. Starting records the
 * run through the API; the server then runs the backtest read-only. No
 * command line is involved.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { afterPovRunChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import { useApi } from '../../auth/AuthContext';
import { Stepper } from '../../components/Stepper';
import { useToast } from '../../components/Toast';
import { Banner, Button, Card, DefinitionList, ErrorMessage, PageHeader, TextField, buttonClass } from '../../components/ui';
import { formatInt } from '../../lib/format';
import { POV_HREF } from '../../lib/links';
import { BACKTEST_ALERT_LIMIT, BACKTEST_DAYS, MAX_NAME_CHARS, SHADOW_DAYS, inProgress, parseDays, type DayLimits } from './pov';

export const POV_STEPS = ['History window', 'Shadow period', 'Review and start'] as const;

const dayFormat = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
const DAY_MS = 86_400_000;

/** "14 days: 14 Nov 2026 to 28 Nov 2026" for a window of `days` that starts `startOffsetDays` from now. */
function windowText(days: number, startOffsetDays: number, now: number): string {
  const start = now + startOffsetDays * DAY_MS;
  return `${formatInt(days)} ${days === 1 ? 'day' : 'days'}: ${dayFormat.format(start)} to ${dayFormat.format(start + days * DAY_MS)}`;
}

function daysError(value: string, limits: DayLimits): string | null {
  return parseDays(value, limits) === null ? `A whole number from ${limits.min} to ${limits.max}.` : null;
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

export default function PovWizardPage() {
  const api = useApi();
  const client = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [history, setHistory] = useState(String(BACKTEST_DAYS.initial));
  const [shadow, setShadow] = useState(String(SHADOW_DAYS.initial));
  const [now] = useState(() => Date.now());
  const heading = useRef<HTMLHeadingElement>(null);
  const moved = useRef(false);

  // Keyboard and screen-reader users land on the new step's title, not at the top of the page.
  useEffect(() => {
    if (moved.current) heading.current?.focus();
    moved.current = true;
  }, [step]);

  const runs = useQuery({ queryKey: qk.pov.runs, queryFn: ({ signal }) => endpoints.povRuns(api, signal) });
  const blocking = runs.data?.items.find(inProgress);
  const trimmed = name.trim();
  const historyDays = parseDays(history, BACKTEST_DAYS);
  const shadowDays = parseDays(shadow, SHADOW_DAYS);
  const start = useMutation({
    mutationFn: () => endpoints.createPovRun(api, { name: trimmed, backtest_days: historyDays ?? undefined, shadow_days: shadowDays ?? undefined }),
    onSuccess: (run) => {
      toast.success(`Proof of value "${run.name}" started.`);
      void afterPovRunChange(client);
      navigate(POV_HREF);
    },
  });
  const next = (e: FormEvent) => {
    e.preventDefault();
    setStep((s) => s + 1);
  };
  const back = () => setStep((s) => s - 1);

  return (
    <>
      <PageHeader
        title="New proof of value"
        description="Three short steps: a window of history to replay, a shadow period on live alerts, then start. Nothing here needs the command line."
      />
      {blocking && (
        <Banner
          tone="warning"
          title="A proof of value is already in progress"
          className="mb-5"
          actions={
            <Link to={POV_HREF} className={buttonClass('secondary', 'sm')}>
              Open it
            </Link>
          }
        >
          "{blocking.name}" has to end, or be stopped, before another one starts.
        </Banner>
      )}
      <Stepper steps={POV_STEPS} current={step} label="Proof-of-value steps" />
      <Card>
        <h2 ref={heading} tabIndex={-1} className="mb-3 text-base font-semibold text-fg focus:outline-none">
          Step {step + 1} of {POV_STEPS.length}: {POV_STEPS[step]}
        </h2>
        {step === 0 && (
          <form onSubmit={next} className="max-w-xl space-y-4" aria-label="History window">
            <p className="text-sm text-secondary">
              The backtest replays the alerts your analysts already decided through the current triage and compares the result
              with their decisions. It reads your alerts and writes nothing.
            </p>
            <TextField
              label="Name"
              value={name}
              maxLength={MAX_NAME_CHARS}
              onChange={(e) => setName(e.target.value)}
              hint="Shown on the run, for example the customer and the month."
            />
            <TextField
              label="Days of history to replay"
              inputMode="numeric"
              value={history}
              onChange={(e) => setHistory(e.target.value)}
              hint={`Alerts decided in the last ${BACKTEST_DAYS.min} to ${BACKTEST_DAYS.max} days, the ${formatInt(BACKTEST_ALERT_LIMIT)} oldest at most.`}
              error={daysError(history, BACKTEST_DAYS)}
            />
            <StepActions>
              <Button type="submit" variant="primary" disabled={!trimmed || historyDays === null}>
                Continue
              </Button>
            </StepActions>
          </form>
        )}
        {step === 1 && (
          <form onSubmit={next} className="max-w-xl space-y-4" aria-label="Shadow period">
            <p className="text-sm text-secondary">
              After the backtest, the run observes the alerts that arrive during the shadow period. Your analysts keep working
              as usual; at the end the reports compare the triage with their decisions.
            </p>
            <TextField
              label="Days of shadow period"
              inputMode="numeric"
              value={shadow}
              onChange={(e) => setShadow(e.target.value)}
              hint={`From ${SHADOW_DAYS.min} to ${SHADOW_DAYS.max} days, starting when you start the run.`}
              error={daysError(shadow, SHADOW_DAYS)}
            />
            <StepActions onBack={back}>
              <Button type="submit" variant="primary" disabled={shadowDays === null}>
                Continue
              </Button>
            </StepActions>
          </form>
        )}
        {step === 2 && historyDays !== null && shadowDays !== null && (
          <>
            <DefinitionList
              items={[
                ['Name', trimmed],
                ['History window', windowText(historyDays, -historyDays, now)],
                ['Shadow period', windowText(shadowDays, 0, now)],
                [
                  'What the run changes',
                  'Nothing. The backtest runs in read-only transactions and stops at the routing decision: no alert is updated, no response action is planned and nobody is notified.',
                ],
                ['Model usage', 'The backtest calls the configured model for each alert it replays.'],
              ]}
            />
            {start.error ? (
              <div className="mt-4">
                <ErrorMessage error={start.error} compact />
              </div>
            ) : null}
            <StepActions onBack={back}>
              <Button variant="primary" busy={start.isPending} disabled={Boolean(blocking)} onClick={() => start.mutate()}>
                Start proof of value
              </Button>
            </StepActions>
          </>
        )}
      </Card>
    </>
  );
}
