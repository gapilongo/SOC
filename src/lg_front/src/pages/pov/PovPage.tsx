/**
 * Proof of value (tenant admins): the tenant's runs. The latest run shows its
 * two phases, the backtest over history with its result and the shadow
 * period with a link to the reports over it. A run only reads the tenant's
 * alerts; starting one is the wizard at /pov/new.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { afterPovRunChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import type { PovRunOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { ConfirmDialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Card, DefinitionList, EmptyState, ErrorMessage, LoadingState, PageHeader, StatePill, buttonClass } from '../../components/ui';
import { formatDateAndTime, formatDateTime, formatInt } from '../../lib/format';
import { POV_WIZARD_HREF, reportsHref } from '../../lib/links';
import { formatRate } from '../../lib/reports';
import { backtestStatus, backtestSummary, inProgress, runStatus, shadowRange, shadowStatus, type StatusText } from './pov';

/** How often the page asks again while a backtest is waiting or running. */
const BACKTEST_POLL_MS = 5_000;

const day = (value: string) => formatDateAndTime(value).date;

function Phase({ title, status, children }: { title: string; status: StatusText; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="rounded-control border border-subtle bg-canvas/50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id={id} className="text-sm font-semibold text-fg">
          {title}
        </h3>
        <StatePill tone={status.tone}>{status.label}</StatePill>
      </div>
      <div className="mt-2 space-y-2 text-sm text-secondary">{children}</div>
    </section>
  );
}

function BacktestOutcome({ run }: { run: PovRunOut }) {
  const { status, error, result } = run.backtest;
  if (status === 'pending') return <p>Waiting for the scheduler to start it; this page updates on its own.</p>;
  if (status === 'running') return <p>Replaying the alerts through the current pipeline. With many alerts this takes a while.</p>;
  if (status === 'no_data') return <p>No analyst decided an alert in this window, so there was nothing to replay.</p>;
  if (status === 'failed') return <p className="text-danger-fg">The backtest did not finish: {error ?? 'no reason was recorded'}.</p>;
  const summary = backtestSummary(result);
  if (!summary) return <p>The backtest is complete.</p>;
  return (
    <DefinitionList
      items={[
        ['Alerts replayed', formatInt(summary.items)],
        ['Confirmed threats among them', formatInt(summary.threats)],
        ['Threats the triage would have closed', `${formatInt(summary.missed)} of ${formatInt(summary.threats)}`],
        ['Missed-threat rate', formatRate(summary.missedRate)],
        ['Replays that failed', formatInt(summary.errors)],
      ]}
    />
  );
}

function RunCard({ run, onStop }: { run: PovRunOut; onStop: () => void }) {
  return (
    <Card
      title={run.name}
      actions={
        <>
          <StatePill tone={runStatus(run.status).tone}>{runStatus(run.status).label}</StatePill>
          {inProgress(run) && (
            <Button size="sm" onClick={onStop}>
              Stop this run
            </Button>
          )}
        </>
      }
    >
      <p className="mb-3 text-xs text-muted">
        Started {formatDateTime(run.created_at)}
        {run.cancelled_at ? `; stopped ${formatDateTime(run.cancelled_at)}` : ''}
      </p>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-2">
        <Phase title="1. Backtest over history" status={backtestStatus(run.backtest.status)}>
          <p>
            The alerts your analysts decided from {day(run.backtest.window_start)} to {day(run.backtest.window_end)}, replayed
            read-only and compared with their decisions.
          </p>
          <BacktestOutcome run={run} />
        </Phase>
        <Phase title="2. Shadow period" status={shadowStatus(run.shadow.status)}>
          <p>
            Live alerts from {day(run.shadow.window_start)} to {day(run.shadow.window_end)}. The run observes them and changes
            none.
          </p>
          <p>
            <Link to={reportsHref(shadowRange(run))} className="text-link underline">
              Open the reports for this period
            </Link>
          </p>
        </Phase>
      </div>
    </Card>
  );
}

export default function PovPage() {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [stopping, setStopping] = useState<PovRunOut | null>(null);
  const runs = useQuery({
    queryKey: qk.pov.runs,
    queryFn: ({ signal }) => endpoints.povRuns(api, signal),
    refetchInterval: (query) => (query.state.data?.items[0]?.status === 'backtest' ? BACKTEST_POLL_MS : false),
  });
  const [latest, ...earlier] = runs.data?.items ?? [];
  // The list carries no backtest result: the latest run is read on its own.
  const detail = useQuery({
    queryKey: qk.pov.run(latest?.id ?? ''),
    queryFn: ({ signal }) => endpoints.povRun(api, latest.id, signal),
    enabled: Boolean(latest),
    refetchInterval: (query) => (query.state.data?.status === 'backtest' ? BACKTEST_POLL_MS : false),
  });
  const stop = useMutation({
    mutationFn: (run: PovRunOut) => endpoints.cancelPovRun(api, run.id),
    onSuccess: (run) => {
      toast.success(`Stopped "${run.name}".`);
      setStopping(null);
      void afterPovRunChange(client);
    },
    onError: (err) => toast.error(err, 'The run was not stopped'),
  });
  const shown = latest && detail.data?.id === latest.id ? detail.data : latest;

  return (
    <>
      <PageHeader
        title="Proof of value"
        description="Measure what the triage does on your own alerts before you rely on it. A run only reads: it changes no alert, takes no response action and notifies nobody."
        actions={
          runs.data && !runs.data.items.some(inProgress) ? (
            <Link to={POV_WIZARD_HREF} className={buttonClass('primary', 'sm')}>
              New proof of value
            </Link>
          ) : undefined
        }
      />
      {runs.isPending && <LoadingState label="Loading proof-of-value runs" />}
      {runs.isError && <ErrorMessage error={runs.error} onRetry={() => void runs.refetch()} />}
      {runs.data && !shown && (
        <Card>
          <EmptyState title="No proof of value yet">
            A proof of value replays a window of the alerts your analysts decided, then observes your live alerts for a period,
            and shows how the triage compares with your analysts.
          </EmptyState>
        </Card>
      )}
      {shown && (
        <div className="space-y-5">
          <RunCard run={shown} onStop={() => setStopping(shown)} />
          {earlier.length > 0 && (
            <Card title="Earlier runs">
              <ul className="space-y-2 text-sm" aria-label="Earlier runs">
                {earlier.map((run) => (
                  <li key={run.id} className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-body">
                      {run.name} <span className="text-muted">({day(run.created_at)})</span>
                    </span>
                    <StatePill tone={runStatus(run.status).tone}>{runStatus(run.status).label}</StatePill>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
      <ConfirmDialog
        open={stopping !== null}
        title="Stop this proof of value?"
        confirmLabel="Stop run"
        danger
        busy={stop.isPending}
        onConfirm={() => stopping && stop.mutate(stopping)}
        onCancel={() => setStopping(null)}
      >
        Its shadow period ends now and a backtest that has not started is not run; one that is already running finishes. You can
        start another proof of value afterwards.
      </ConfirmDialog>
    </>
  );
}
