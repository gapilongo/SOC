import { useQuery } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../api/endpoints';
import { qk } from '../api/queryKeys';
import { ALERT_STATUSES, DISPOSITIONS, SEVERITIES } from '../api/types';
import { useApi, useAuth } from '../auth/AuthContext';
import { can } from '../auth/roles';
import { OnboardingBanner } from '../components/Onboarding';
import { Button, Card, ErrorMessage, LoadingState, PageHeader, SelectField } from '../components/ui';
import { formatDateTime, formatDuration, formatInt, formatUsd } from '../lib/format';
import { formatHours, formatPct } from '../lib/reports';
import { usePollInterval } from '../lib/visibility';
import { useLive } from '../live/LiveProvider';

const WINDOWS = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
  { hours: 720, label: 'Last 30 days' },
];

function Stat({ label, value, hint, to }: { label: string; value: string; hint?: string; to?: string }) {
  const body = (
    <>
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </>
  );
  const cls = 'block rounded-card border border-subtle bg-raised p-4';
  return to ? (
    <Link to={to} className={`${cls} hover:border-control focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus`}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

/** Single-series horizontal bars (count per category); values are labelled in text, never by color alone. */
function Breakdown({ title, counts, order, linkFor }: { title: string; counts: Record<string, number>; order: readonly string[]; linkFor?: (k: string) => string }) {
  const keys = [...order, ...Object.keys(counts).filter((k) => !order.includes(k))];
  const max = Math.max(1, ...keys.map((k) => counts[k] ?? 0));
  return (
    <Card title={title}>
      <table className="w-full text-sm">
        <caption className="sr-only">{title}</caption>
        <thead className="sr-only">
          <tr>
            <th scope="col">Category</th>
            <th scope="col">Count</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => {
            const n = counts[k] ?? 0;
            const label = k.replace(/_/g, ' ');
            return (
              <tr key={k}>
                <th scope="row" className="w-40 py-1 pr-3 text-left font-normal capitalize text-secondary">
                  {linkFor ? (
                    <Link to={linkFor(k)} className="hover:text-fg hover:underline">
                      {label}
                    </Link>
                  ) : (
                    label
                  )}
                </th>
                <td className="py-1">
                  <div className="flex items-center gap-2">
                    <div className="h-2.5 flex-1 rounded-sm bg-raised-2" aria-hidden="true">
                      <div className="bar-fill h-2.5 rounded-sm bg-accent-hover" style={{ width: `${(n / max) * 100}%` }} />
                    </div>
                    <span className="w-14 text-right tabular-nums text-fg">{formatInt(n)}</span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Card>
  );
}

export default function DashboardPage() {
  const api = useApi();
  const [windowHours, setWindowHours] = useState(24);
  const { status: live } = useLive();
  // Poll as a fallback to the live stream; paused while the tab is hidden.
  const interval = usePollInterval(live === 'open' ? 60_000 : 20_000);
  const q = useQuery({
    queryKey: qk.dashboard.summary(windowHours),
    queryFn: ({ signal }) => endpoints.dashboard(api, windowHours, signal),
    refetchInterval: interval,
    refetchIntervalInBackground: false,
  });
  const d = q.data;
  const { principal } = useAuth();

  return (
    <>
      {can.admin(principal) && <OnboardingBanner />}
      <PageHeader
        title="Dashboard"
        description={d ? `Updated ${formatDateTime(d.generated_at)}. Figures cover alerts ingested since ${formatDateTime(d.since)}.` : undefined}
        actions={
          <>
            <SelectField label="Window" value={windowHours} onChange={(e) => setWindowHours(Number(e.target.value))} wrapperClassName="w-44">
              {WINDOWS.map((w) => (
                <option key={w.hours} value={w.hours}>
                  {w.label}
                </option>
              ))}
            </SelectField>
            <Button
              className="self-end"
              onClick={() => void q.refetch()}
              busy={q.isFetching}
              icon={<RefreshCw className="h-4 w-4" aria-hidden="true" />}
            >
              Refresh
            </Button>
          </>
        }
      />
      {q.isPending && <LoadingState label="Loading dashboard" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {d && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat
              label="Handled without human"
              value={formatPct(d.handled_without_human_rate)}
              hint={`${formatInt(d.handled_without_human ?? 0)} of ${formatInt((d.handled_without_human ?? 0) + (d.needed_human ?? 0))} finished alerts`}
              to="/reports"
            />
            <Stat
              label="Analyst hours saved"
              value={formatHours(d.analyst_hours_saved ?? 0)}
              hint={`Estimate: ${formatInt(d.minutes_per_alert ?? 15)} min per handled alert`}
              to="/reports"
            />
            <Stat label="Alerts" value={formatInt(d.alerts_total)} to="/alerts" />
            <Stat label="Open escalations" value={formatInt(d.open_escalations)} to="/escalations" />
            <Stat label="Queue depth" value={formatInt(d.queue_depth)} hint="Workflow runs waiting or running" />
            <Stat label="MTTA" value={formatDuration(d.mtta_s)} hint={`${formatInt(d.acknowledged)} acknowledged`} />
            <Stat label="MTTR" value={formatDuration(d.mttr_s)} hint={`${formatInt(d.resolved)} resolved`} />
            <Stat label="LLM cost" value={formatUsd(d.llm_cost_usd)} hint={`${formatInt(d.llm_tokens)} tokens`} />
          </div>
          {d.alerts_total === 0 && (
            <p className="rounded-control border border-subtle bg-raised px-4 py-3 text-sm text-secondary">
              No alerts were ingested in this window. Connect a source under Sources or send alerts to the ingest API.
            </p>
          )}
          <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-4">
            <Breakdown title="By severity" counts={d.by_severity} order={[...SEVERITIES].reverse()} linkFor={(k) => `/alerts?severity=${encodeURIComponent(k)}`} />
            <Breakdown title="By status" counts={d.by_status} order={ALERT_STATUSES} linkFor={(k) => `/alerts?status=${encodeURIComponent(k)}`} />
            <Breakdown title="By disposition" counts={d.by_disposition} order={DISPOSITIONS} linkFor={(k) => `/alerts?disposition=${encodeURIComponent(k)}`} />
            <Breakdown title="Unfinished workflow runs" counts={d.runs_by_status} order={[]} />
          </div>
        </div>
      )}
    </>
  );
}
