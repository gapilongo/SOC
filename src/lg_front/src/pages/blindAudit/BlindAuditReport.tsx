/**
 * The Reports page's "Blind audit" tab: the production false-negative rate
 * among auto-closed alerts, estimated from blind labels of a random sample,
 * with its 95% interval, n and the scaling to the sampling frame.
 */

import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import type { BlindAuditEstimate, BlindAuditReportOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Card, EmptyState, ErrorMessage, LoadingState } from '../../components/ui';
import { formatDateTime, formatInt } from '../../lib/format';
import { formatInterval, formatPct, formatRate } from '../../lib/reports';

/** "about 150 (51 to 411)" missed threats among the frame, or "-" without a labelled sample. */
export function missedText(e: BlindAuditEstimate): string {
  if (e.estimated_missed === null) return '-';
  const range = e.estimated_missed_low !== null && e.estimated_missed_high !== null ? ` (${formatInt(Math.round(e.estimated_missed_low))} to ${formatInt(Math.round(e.estimated_missed_high))})` : '';
  return `about ${formatInt(Math.round(e.estimated_missed))}${range}`;
}

/** A run's own rate and Wilson interval, from its stratum. */
function strataRate(r: BlindAuditReportOut, runId: string): string {
  const stratum = r.strata.find((st) => st.run_id === runId);
  return stratum ? formatRate(stratum.false_negative_rate) : '-';
}

export function BlindAuditTab({ from, to, tile }: { from: string; to: string; tile: (label: string, value: string, hint?: ReactNode) => ReactNode }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.reportBlindAudit.range(from, to),
    queryFn: ({ signal }) => endpoints.blindAuditReport(api, from, to, signal),
  });
  if (q.isPending) return <LoadingState label="Loading blind audit report" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />;
  const r: BlindAuditReportOut = q.data;
  const e = r.estimate;
  const fn = e.false_negative_rate;
  return (
    <div className="space-y-5">
      {e.status === 'insufficient_data' && (
        <p role="status" className="rounded-control border border-warn/60 bg-tint-warn px-4 py-3 text-sm text-warn-fg">
          {e.summary}: too few labelled samples in this range for the estimate to mean much. <Link to="/blind-audit" className="underline">Label more samples</Link>.
        </p>
      )}
      {e.status !== 'insufficient_data' && !e.complete && (
        <p role="status" className="rounded-control border border-warn/60 bg-tint-warn px-4 py-3 text-sm text-warn-fg">
          Incomplete: {formatInt(e.pending)} sample(s) still wait for a label. Until every run is labelled, read the worst case too.
        </p>
      )}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {tile(
          'Missed threats among auto-closed (FN rate)',
          formatPct(fn.rate),
          <>
            Stratified over the runs; {formatInt(e.malicious)} malicious of {formatInt(e.malicious + e.benign)} labelled samples (n). {formatInterval(fn)}
          </>,
        )}
        {tile('Estimated missed in the frame', missedText(e), `${formatInt(e.estimated_frame)} of ${formatInt(e.frame_size)} eligible auto-closed alerts are in runs with labels.`)}
        {tile(
          'Worst case',
          formatPct(e.worst_case_rate),
          `Unsure and waiting samples counted as malicious; up to ${formatPct(e.worst_case_rate_high)} (95%).`,
        )}
        {tile(
          'Agreement with the AI',
          formatPct(e.agreement_rate.rate),
          `${formatInt(e.labelled)} labelled, ${formatInt(e.unsure)} unsure, ${formatInt(e.pending)} waiting. ${formatInterval(e.agreement_rate)}`,
        )}
      </div>
      {r.uncovered.length > 0 && (
        <Card title="Time no run covered">
          <ul className="space-y-1 text-sm text-body" aria-label="Uncovered time">
            {r.uncovered.map((u) => (
              <li key={u.from}>
                {formatDateTime(u.from)} to {formatDateTime(u.to)}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted">Alerts closed then are in no sampling frame (before the first run, or not sampled yet).</p>
        </Card>
      )}
      {r.labels_by_organisation.length > 0 && (
        <Card title="Who labelled">
          <ul className="space-y-1 text-sm text-body" aria-label="Labels by organisation">
            {r.labels_by_organisation.map((o) => (
              <li key={o.organisation ?? 'tenant'}>
                {o.organisation ? `MSSP ${o.organisation}` : 'This tenant'}: {formatInt(o.labelled)} labels ({formatInt(o.malicious)} malicious,{' '}
                {formatInt(o.benign)} benign, {formatInt(o.unsure)} unsure)
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card title="Sampling runs">
        {r.runs.length === 0 ? (
          <EmptyState title="No sampling run in this range">
            Turn on the weekly sample in the tenant settings (blind_audit), run lg-sotf audit-sample, or have an admin draw one on the{' '}
            <Link to="/blind-audit" className="text-link underline">
              Blind audit page
            </Link>
            .
          </EmptyState>
        ) : (
          // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Sampling runs table">
            <table className="w-full min-w-[640px] text-left text-sm">
              <caption className="sr-only">Blind audit sampling runs</caption>
              <thead className="text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="py-2 pr-3">Window</th>
                  <th scope="col" className="py-2 pr-3 text-right">Frame</th>
                  <th scope="col" className="py-2 pr-3 text-right">Sampled</th>
                  <th scope="col" className="py-2 pr-3 text-right">Malicious</th>
                  <th scope="col" className="py-2 pr-3 text-right">Benign</th>
                  <th scope="col" className="py-2 pr-3 text-right">Unsure</th>
                  <th scope="col" className="py-2 pr-3 text-right">FN rate (95% CI)</th>
                  <th scope="col" className="py-2">Seed</th>
                </tr>
              </thead>
              <tbody>
                {r.runs.map((run) => (
                  <tr key={run.id} className="border-t border-subtle tabular-nums">
                    <td className="py-1.5 pr-3 text-body">
                      {formatDateTime(run.window_start)} to {formatDateTime(run.window_end)}
                    </td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(run.frame_size)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(run.sample_size)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(run.malicious)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(run.benign)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(run.unsure)}</td>
                    <td className="py-1.5 pr-3 text-right">{strataRate(r, run.id)}</td>
                    <td className="py-1.5 font-mono text-xs">{run.seed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="How to read this">
        <ul className="list-disc space-y-1 pl-5 text-sm text-secondary">
          {r.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
