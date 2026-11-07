import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Download, Printer } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';

import { endpoints } from '../api/endpoints';
import { qk } from '../api/queryKeys';
import type { MonthlyReportOut } from '../api/types';
import { useApi } from '../auth/AuthContext';
import { useToast } from '../components/Toast';
import { Button, ErrorMessage, LoadingState } from '../components/ui';
import { downloadText } from '../lib/download';
import { formatDateTime, formatDuration, formatInt, formatUsd } from '../lib/format';
import { SUGGESTION_LABEL, formatHours, formatInterval, formatPct, formatRate, notEnoughData } from '../lib/reports';

const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const TOP_DETECTIONS = 25;

function monthName(month: string): string {
  const [y, m] = month.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleString(undefined, { month: 'long', year: 'numeric', timeZone: 'UTC' });
}

function PaperTile({ label, value, hint }: { label: string; value: string; hint?: ReactNode }) {
  return (
    <div className="break-inside-avoid rounded-control border border-strong p-3">
      <div className="text-[11px] font-medium uppercase tracking-wide text-secondary">{label}</div>
      <div className="text-xl font-semibold tabular-nums text-fg">{value}</div>
      {hint && <div className="text-xs text-secondary">{hint}</div>}
    </div>
  );
}

function Report({ r }: { r: MonthlyReportOut }) {
  const t = r.value.totals;
  const o = r.accuracy.overall;
  return (
    <article className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold">
          Monthly report: {r.tenant_name}, {monthName(r.month)}
        </h1>
        <p className="text-sm text-secondary">
          Tenant {r.tenant_id}. Period {r.value.from} to {r.value.to} (UTC). Generated {formatDateTime(r.generated_at)}.
        </p>
      </header>
      <section aria-labelledby="m-value">
        <h2 id="m-value" className="mb-2 border-b-2 border-subtle text-lg font-semibold">
          1. Value
        </h2>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4 print:grid-cols-4">
          <PaperTile label="Handled without a human" value={formatPct(t.handled_without_human_rate)} hint={`${formatInt(t.handled_without_human)} of ${formatInt(t.handled_without_human + t.needed_human)} finished alerts. ${formatInterval(t.handled_without_human_rate_ci)}`} />
          <PaperTile label="Analyst hours saved (estimate)" value={formatHours(t.analyst_hours_saved)} hint={`${r.value.minutes_per_alert} min per handled alert`} />
          <PaperTile label="Alerts ingested" value={formatInt(t.alerts_ingested)} hint={`${formatInt(t.in_progress)} still in progress`} />
          <PaperTile label="Auto-closed benign" value={formatInt(t.auto_closed_benign)} />
          <PaperTile label="Auto-contained" value={formatInt(t.auto_contained)} hint={`${formatInt(t.auto_contained_dry_run)} more in dry-run mode`} />
          <PaperTile label="Escalated" value={formatInt(t.escalated)} hint={`${formatInt(t.human_decided)} decided by an analyst`} />
          <PaperTile label="Mean time to verdict" value={formatDuration(t.mean_time_to_verdict_s)} />
          <PaperTile label="MTTA / MTTR" value={`${formatDuration(t.mtta_s)} / ${formatDuration(t.mttr_s)}`} />
          <PaperTile label="SLA breaches" value={formatInt(t.sla_breaches)} hint={`${formatInt(r.value.escalations_breached)} escalations`} />
          <PaperTile label="LLM cost per alert" value={formatUsd(t.llm_cost_per_alert_usd)} hint={`${formatUsd(t.llm_cost_usd)} in total`} />
          <PaperTile label="Suppressed / cached / grouped" value={`${formatInt(t.suppressed_by_rule)} / ${formatInt(t.verdict_cache_hits)} / ${formatInt(t.grouped_into_escalation)}`} />
        </div>
      </section>
      <section aria-labelledby="m-accuracy">
        <h2 id="m-accuracy" className="mb-2 border-b-2 border-subtle text-lg font-semibold">
          2. Accuracy on your data
        </h2>
        {o.status === 'insufficient_data' && (
          <p className="mb-2 rounded-control border border-warn/60 bg-tint-warn px-3 py-2 text-sm text-warn-fg">
            {notEnoughData(o.samples, r.accuracy.min_samples)}: too few analyst-decided alerts for these rates to mean much.
          </p>
        )}
        <p className="text-sm">
          <span className="text-2xl font-bold">{formatPct(o.false_negative_rate)}</span> false-negative rate: the AI said benign on {formatInt(o.false_negatives)} of{' '}
          {formatInt(o.analyst_malicious)} alerts an analyst confirmed malicious. <span className="text-secondary">{formatInterval(o.false_negative_rate_ci)}</span>
        </p>
        <p className="text-sm">
          Agreement {formatRate(o.agreement_rate_ci, o.agreement_rate)}; false-positive rate (of benign) {formatRate(o.false_positive_rate_ci, o.false_positive_rate)}; AI
          inconclusive {formatRate(o.ai_inconclusive_rate_ci, o.ai_inconclusive_rate)}.
        </p>
        {r.accuracy.by_model.length > 0 && (
          // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
          <div role="region" aria-label="Accuracy by model" tabIndex={0} className="relative mt-2 overflow-x-auto print:overflow-visible">
            <table className="w-full text-sm">
              <caption className="text-left text-xs text-secondary">By model</caption>
              <thead>
                <tr className="text-left text-xs uppercase text-secondary">
                  <th scope="col" className="py-1 pr-2">Model</th>
                  <th scope="col" className="py-1 pr-2 text-right">Samples</th>
                  <th scope="col" className="py-1 pr-2 text-right">Agreement</th>
                  <th scope="col" className="py-1 text-right">False-negative rate</th>
                </tr>
              </thead>
              <tbody>
                {r.accuracy.by_model.map((m) => (
                  <tr key={m.model} className="border-t border-subtle tabular-nums">
                    <td className="break-all py-1 pr-2">{m.model}</td>
                    <td className="py-1 pr-2 text-right">{formatInt(m.accuracy.samples)}</td>
                    <td className="py-1 pr-2 text-right">{formatRate(m.accuracy.agreement_rate_ci, m.accuracy.agreement_rate)}</td>
                    <td className="py-1 text-right">{formatRate(m.accuracy.false_negative_rate_ci, m.accuracy.false_negative_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section aria-labelledby="m-detections">
        <h2 id="m-detections" className="mb-2 border-b-2 border-subtle text-lg font-semibold">
          3. Detection tuning
        </h2>
        {/* On a phone the table scrolls on its own (and takes the keyboard focus to scroll); on paper it prints whole. */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <div role="region" aria-label="Detection tuning" tabIndex={0} className="relative overflow-x-auto print:overflow-visible">
          <table className="w-full text-sm">
            <caption className="text-left text-xs text-secondary">Busiest {Math.min(TOP_DETECTIONS, r.detections.detections.length)} detections by volume</caption>
            <thead>
              <tr className="text-left text-xs uppercase text-secondary">
                <th scope="col" className="py-1 pr-2">Source</th>
                <th scope="col" className="py-1 pr-2">Rule</th>
                <th scope="col" className="py-1 pr-2 text-right">Volume</th>
                <th scope="col" className="py-1 pr-2 text-right">Benign</th>
                <th scope="col" className="py-1 pr-2 text-right">Analyst FP</th>
                <th scope="col" className="py-1">Suggestion</th>
              </tr>
            </thead>
            <tbody>
              {r.detections.detections.slice(0, TOP_DETECTIONS).map((d) => (
                <tr key={`${d.source_id}-${d.rule_field}-${d.rule}`} className="break-inside-avoid border-t border-subtle align-top tabular-nums">
                  <td className="py-1 pr-2">{d.source_id}</td>
                  <td className="break-words py-1 pr-2">{d.rule}</td>
                  <td className="py-1 pr-2 text-right">{formatInt(d.volume)}</td>
                  <td className="py-1 pr-2 text-right">{formatRate(d.benign_rate_ci, d.benign_rate, 0)}</td>
                  <td className="py-1 pr-2 text-right">{formatInt(d.analyst_false_positive)}</td>
                  <td className="py-1">
                    <strong>{d.suggestion ? SUGGESTION_LABEL[d.suggestion] : 'None'}</strong>
                    <span className="block text-xs text-secondary">{d.reason}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section aria-labelledby="m-notes">
        <h2 id="m-notes" className="mb-2 border-b-2 border-subtle text-lg font-semibold">
          Definitions and limits
        </h2>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {[...r.value.notes, ...r.accuracy.notes, ...r.detections.notes].map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      </section>
    </article>
  );
}

/** Printable monthly report (outside the app layout so the browser prints only the report). */
export default function MonthlyReportPage() {
  const api = useApi();
  const toast = useToast();
  const { month = '' } = useParams();
  const valid = MONTH.test(month);
  const [downloading, setDownloading] = useState(false);
  const q = useQuery({
    queryKey: qk.reportMonthly.month(month),
    queryFn: ({ signal }) => endpoints.monthlyReport(api, month, signal),
    enabled: valid,
  });
  const download = async () => {
    setDownloading(true);
    try {
      const html = await endpoints.monthlyReportHtml(api, month);
      downloadText(`lg-sotf-report-${q.data?.tenant_id ?? 'tenant'}-${month}.html`, html, 'text/html;charset=utf-8');
    } catch (err) {
      toast.error(err, 'Download failed');
    } finally {
      setDownloading(false);
    }
  };
  return (
    // A paper document: always the light palette, whatever the app theme.
    <div data-theme="light" className="min-h-screen bg-canvas py-6 text-fg print:bg-raised print:py-0">
      <div className="mx-auto mb-4 flex max-w-4xl flex-wrap items-center gap-2 px-4 print:hidden">
        <Link to="/reports" className="inline-flex items-center gap-1 text-sm text-body hover:underline">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back to reports
        </Link>
        <span className="flex-1" />
        <Button onClick={() => window.print()} disabled={!q.data} icon={<Printer className="h-4 w-4" aria-hidden="true" />}>
          Print or save as PDF
        </Button>
        <Button onClick={() => void download()} disabled={!q.data} busy={downloading} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
          Download HTML
        </Button>
      </div>
      <main className="mx-auto max-w-4xl rounded-control bg-raised px-4 py-8 sm:px-8 text-fg shadow print:max-w-none print:rounded-none print:p-0 print:shadow-none">
        {!valid && <p role="alert">The month must be YYYY-MM.</p>}
        {valid && q.isPending && <LoadingState label="Loading monthly report" />}
        {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
        {q.data && <Report r={q.data} />}
      </main>
    </div>
  );
}
