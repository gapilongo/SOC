import { useMutation, useQuery } from '@tanstack/react-query';
import { Download, FileText } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints } from '../api/endpoints';
import { qk } from '../api/queryKeys';
import type { AccuracyBlock, AccuracyReportOut, DetectionOut, FeedbackRate, RateInterval, ValueDay, ValueReportOut } from '../api/types';
import { useApi, useAuth } from '../../../auth/AuthContext';
import { can } from '../../../auth/roles';
import { Badge } from '../components/Badge';
import { useToast } from '../../../components/Toast';
import { Button, Card, EmptyState, ErrorMessage, LoadingState, PageHeader, Tabs, TextField, Truncated, cx } from '../../../components/ui';
import { downloadText } from '../../../lib/download';
import { formatDuration, formatInt, formatUsd } from '../../../lib/format';
import { BlindAuditTab } from './blindAudit/BlindAuditReport';
import { SUGGESTION_LABEL, defaultRange, feedbackInterval, formatHours, formatInterval, formatPct, formatRate, monthOf, notEnoughData, rangeError, rateDetail } from '../lib/reports';

type Tab = 'value' | 'accuracy' | 'detections' | 'blind_audit';
const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'value', label: 'Value' },
  { id: 'accuracy', label: 'Accuracy' },
  { id: 'detections', label: 'Detections' },
  { id: 'blind_audit', label: 'Blind audit' },
];

// Validated categorical pair (dark surface): blue = handled without a human, orange = needed a human.
const HANDLED_COLOR = '#3987e5';
const NEEDED_COLOR = '#d95926';

export function Tile({ label, value, hint }: { label: string; value: string; hint?: ReactNode }) {
  return (
    // A subgrid of the row: labels, values and hints line up across the tiles even when a label wraps.
    <div className="row-span-3 grid grid-rows-subgrid gap-0 rounded-card border border-subtle bg-raised p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
      <div className="mt-0.5 text-xs text-muted">{hint}</div>
    </div>
  );
}

function Notes({ notes }: { notes: string[] }) {
  if (!notes.length) return null;
  return (
    <Card title="How to read this">
      <ul className="list-disc space-y-1 pl-5 text-sm text-secondary">
        {notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </Card>
  );
}

function InsufficientData({ samples, needed }: { samples: number; needed: number }) {
  return (
    <p role="status" className="rounded-control border border-warn/60 bg-tint-warn px-4 py-3 text-sm text-warn-fg">
      {notEnoughData(samples, needed)}: too few analyst-decided alerts in this range for these rates to mean much. They are shown
      for reference only.
    </p>
  );
}

/** The status badge of a rate with a minimum sample: "ok", or the shared small-sample wording. */
function SampleBadge({ status, n, needed }: { status: string; n: number; needed: number }) {
  return status === 'ok' ? <Badge tone="good">ok</Badge> : <Badge tone="warn">{notEnoughData(n, needed)}</Badge>;
}

/** A table cell's rate with its sample and interval underneath: "75.0%" over "3 of 4; 95% CI ...". */
function RateCell({ r, fallback, digits = 1 }: { r: RateInterval | null | undefined; fallback: number | null; digits?: number }) {
  if (!r || r.rate === null) return <>{formatRate(r, fallback, digits)}</>;
  return (
    <>
      {formatPct(r.rate, digits)}
      <span className="block text-xs text-muted">{rateDetail(r)}</span>
    </>
  );
}

// ------------------------------------------------------------------- value

/** Stacked daily bars: handled without a human, then needed a human; the table below carries the same data. */
export function DailyChart({ days }: { days: ValueDay[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 800;
  const height = 220;
  const pad = { l: 44, r: 8, t: 12, b: 28 };
  const plotW = width - pad.l - pad.r;
  const plotH = height - pad.t - pad.b;
  const max = Math.max(1, ...days.map((d) => d.handled_without_human + d.needed_human));
  const step = plotW / Math.max(1, days.length);
  const barW = Math.max(1, step - 2);
  const labelEvery = Math.ceil(days.length / 8);
  const y = (n: number) => (n / max) * plotH;
  const active = hover !== null ? days[hover] : null;
  return (
    <figure>
      <div className="mb-2 flex flex-wrap gap-4 text-xs text-secondary" aria-hidden="true">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: HANDLED_COLOR }} />
          Handled without a human
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: NEEDED_COLOR }} />
          Needed a human
        </span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Alerts handled without a human and alerts that needed a human per day, ${days.length} days, peak ${formatInt(max)}`}
      >
        {[0, 0.5, 1].map((f) => {
          const ty = pad.t + plotH - f * plotH;
          return (
            <g key={f}>
              <line x1={pad.l} x2={width - pad.r} y1={ty} y2={ty} className="stroke-strong" strokeWidth={1} />
              <text x={pad.l - 6} y={ty + 4} textAnchor="end" fontSize={11} className="fill-muted">
                {formatInt(Math.round(f * max))}
              </text>
            </g>
          );
        })}
        {days.map((d, i) => {
          const x = pad.l + i * step + 1;
          const hHandled = y(d.handled_without_human);
          const hNeeded = y(d.needed_human);
          const base = pad.t + plotH;
          // 2px surface gap between the stacked segments.
          const gap = hHandled > 0 && hNeeded > 0 ? 2 : 0;
          return (
            <g key={d.day}>
              {hHandled > 0 && (
                <rect x={x} y={base - hHandled} width={barW} height={hHandled} rx={Math.min(4, barW / 2)} fill={HANDLED_COLOR} opacity={hover === null || hover === i ? 1 : 0.6} />
              )}
              {hNeeded > 0 && (
                <rect
                  x={x}
                  y={base - hHandled - gap - hNeeded}
                  width={barW}
                  height={Math.max(0, hNeeded)}
                  rx={Math.min(4, barW / 2)}
                  fill={NEEDED_COLOR}
                  opacity={hover === null || hover === i ? 1 : 0.6}
                />
              )}
              <rect x={pad.l + i * step} y={pad.t} width={step} height={plotH} fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={height - 8} textAnchor="middle" fontSize={11} className="fill-muted">
                  {d.day.slice(5)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-1 min-h-[1.25rem] text-xs text-secondary" aria-live="polite">
        {active
          ? `${active.day}: ${formatInt(active.alerts_ingested)} ingested, ${formatInt(active.handled_without_human)} handled without a human, ${formatInt(active.needed_human)} needed a human, ${formatInt(active.in_progress)} in progress`
          : 'Hover a bar for the day. The table below lists every day.'}
      </figcaption>
    </figure>
  );
}

function ValueTab({ from, to }: { from: string; to: string }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.reportValue.range(from, to),
    queryFn: ({ signal }) => endpoints.valueReport(api, from, to, signal),
  });
  if (q.isPending) return <LoadingState label="Loading value report" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />;
  const r: ValueReportOut = q.data;
  const t = r.totals;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
        <Tile label="Handled without a human" value={formatPct(t.handled_without_human_rate)} hint={`${formatInt(t.handled_without_human)} of ${formatInt(t.handled_without_human + t.needed_human)} finished alerts. ${formatInterval(t.handled_without_human_rate_ci)}`} />
        <Tile label="Analyst hours saved (estimate)" value={formatHours(t.analyst_hours_saved)} hint={`${r.minutes_per_alert} min per handled alert (tenant setting)`} />
        <Tile label="Alerts ingested" value={formatInt(t.alerts_ingested)} hint={`${formatInt(t.in_progress)} still in progress`} />
        <Tile label="Auto-closed benign" value={formatInt(t.auto_closed_benign)} hint={`${formatInt(t.suppressed_by_rule)} by suppression rules, ${formatInt(t.verdict_cache_hits)} by cached analyst verdicts`} />
        <Tile label="Auto-contained" value={formatInt(t.auto_contained)} hint={`${formatInt(t.auto_contained_dry_run)} more in dry-run mode`} />
        <Tile label="Escalated" value={formatInt(t.escalated)} hint={`${formatInt(t.human_decided)} decided by an analyst, ${formatInt(t.grouped_into_escalation)} grouped`} />
        <Tile label="Mean time to verdict" value={formatDuration(t.mean_time_to_verdict_s)} hint={`${formatInt(t.verdicts)} verdicts`} />
        <Tile label="MTTA" value={formatDuration(t.mtta_s)} hint={`${formatInt(t.acknowledged)} of ${formatInt(t.escalations_created)} escalations claimed`} />
        <Tile label="MTTR" value={formatDuration(t.mttr_s)} hint={`automated ${formatDuration(t.mttr_auto_s)}, with an analyst ${formatDuration(t.mttr_human_s)}`} />
        <Tile label="SLA breaches" value={formatInt(t.sla_breaches)} hint={`${formatInt(r.escalations_breached)} escalations`} />
        <Tile label="LLM cost per alert" value={formatUsd(t.llm_cost_per_alert_usd)} hint={`${formatUsd(t.llm_cost_usd)} in total`} />
      </div>
      <Card title="Daily outcomes">{r.days.length ? <DailyChart days={r.days} /> : <EmptyState title="No days in range" />}</Card>
      {/* With no day there is no table: the chart card above already says so. */}
      {r.days.length > 0 && (
        <Card title="Daily figures">
          <div className="relative max-h-[28rem] overflow-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <caption className="sr-only">Value report by day</caption>
              <thead className="sticky top-0 bg-raised text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="py-2 pr-3">Day</th>
                  <th scope="col" className="py-2 pr-3 text-right">Ingested</th>
                  <th scope="col" className="py-2 pr-3 text-right">Handled w/o human</th>
                  <th scope="col" className="py-2 pr-3 text-right">Needed human</th>
                  <th scope="col" className="py-2 pr-3 text-right">Hours saved</th>
                  <th scope="col" className="py-2 pr-3 text-right">MTTR</th>
                  <th scope="col" className="py-2 pr-3 text-right">SLA breaches</th>
                  <th scope="col" className="py-2 text-right">LLM cost</th>
                </tr>
              </thead>
              <tbody>
                {r.days.map((d) => (
                  <tr key={d.day} className="border-t border-subtle tabular-nums">
                    <td className="py-1.5 pr-3 text-body">{d.day}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(d.alerts_ingested)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(d.handled_without_human)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(d.needed_human)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatHours(d.analyst_hours_saved)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatDuration(d.mttr_s)}</td>
                    <td className="py-1.5 pr-3 text-right">{formatInt(d.sla_breaches)}</td>
                    <td className="py-1.5 text-right">{formatUsd(d.llm_cost_usd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      <Notes notes={r.notes} />
    </div>
  );
}

// ---------------------------------------------------------------- accuracy

export function ConfusionMatrix({ block }: { block: AccuracyBlock }) {
  const cols = ['malicious', 'benign', 'inconclusive'];
  return (
    <table className="w-full text-sm">
      <caption className="mb-2 text-left text-xs text-muted">Rows: the analyst's final decision. Columns: the AI verdict on the first escalation.</caption>
      <thead className="text-xs uppercase tracking-wide text-muted">
        <tr>
          <th scope="col" className="py-2 pr-3 text-left">Analyst \ AI</th>
          {cols.map((c) => (
            <th key={c} scope="col" className="py-2 pr-3 text-right capitalize">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {['malicious', 'benign'].map((row) => (
          <tr key={row} className="border-t border-subtle tabular-nums">
            <th scope="row" className="py-1.5 pr-3 text-left font-normal capitalize text-body">
              {row}
            </th>
            {cols.map((c) => {
              const n = block.confusion_matrix[row]?.[c] ?? 0;
              const missed = row === 'malicious' && c === 'benign' && n > 0;
              return (
                <td key={c} className={cx('py-1.5 pr-3 text-right', missed ? 'font-semibold text-danger-fg' : 'text-fg')}>
                  {formatInt(n)}
                  {missed && <span className="sr-only"> (false negatives)</span>}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The API's minimum answers before a feedback rate is "ok" (services/reporting.py MIN_FEEDBACK_SAMPLES). */
const MIN_FEEDBACK_SAMPLES = 10;

function feedbackRow(label: string, r: FeedbackRate) {
  return (
    <tr key={label} className="border-t border-subtle tabular-nums">
      <th scope="row" className="py-1.5 pr-3 text-left font-normal text-body">
        {label}
      </th>
      <td className="py-1.5 pr-3 text-right">
        <RateCell r={feedbackInterval(r)} fallback={r.rate} />
      </td>
      <td className="py-1.5 pr-3 text-right">{formatInt(r.samples)}</td>
      <td className="py-1.5">
        <SampleBadge status={r.status} n={r.samples} needed={MIN_FEEDBACK_SAMPLES} />
      </td>
    </tr>
  );
}

function AccuracyTab({ from, to }: { from: string; to: string }) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.reportAccuracy.range(from, to),
    queryFn: ({ signal }) => endpoints.accuracyReport(api, from, to, signal),
  });
  if (q.isPending) return <LoadingState label="Loading accuracy report" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />;
  const r: AccuracyReportOut = q.data;
  const o = r.overall;
  return (
    <div className="space-y-5">
      {o.status === 'insufficient_data' && <InsufficientData samples={o.samples} needed={r.min_samples} />}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Tile
          label="False-negative rate (headline)"
          value={formatPct(o.false_negative_rate)}
          hint={
            <>
              AI said benign on {formatInt(o.false_negatives)} of {formatInt(o.analyst_malicious)} alerts an analyst confirmed malicious. {formatInterval(o.false_negative_rate_ci)}
            </>
          }
        />
        <Tile label="Agreement with analysts" value={formatPct(o.agreement_rate)} hint={`${formatInt(o.agreement)} of ${formatInt(o.samples)} decisions. ${formatInterval(o.agreement_rate_ci)}`} />
        <Tile
          label="False-positive rate"
          value={formatPct(o.false_positive_rate)}
          hint={`AI said malicious on ${formatInt(o.false_positives)} of ${formatInt(o.analyst_benign)} benign alerts. ${formatInterval(o.false_positive_rate_ci)} Inconclusive on ${formatRate(o.ai_inconclusive_rate_ci, o.ai_inconclusive_rate)} of all.`}
        />
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-2">
        <Card title="Confusion matrix">
          <ConfusionMatrix block={o} />
        </Card>
        <Card title="By model">
          {r.by_model.length === 0 ? (
            <EmptyState title="No analyst decisions in this range" />
          ) : (
            // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
            // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
            <div role="region" aria-label="Accuracy by model" tabIndex={0} className="relative overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Accuracy by model</caption>
                <thead className="text-xs uppercase tracking-wide text-muted">
                  <tr>
                    <th scope="col" className="py-2 pr-3 text-left">Model</th>
                    <th scope="col" className="py-2 pr-3 text-right">Samples</th>
                    <th scope="col" className="py-2 pr-3 text-right">Agreement</th>
                    <th scope="col" className="py-2 pr-3 text-right">False negatives</th>
                    <th scope="col" className="py-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {r.by_model.map((m) => (
                    <tr key={m.model} className="border-t border-subtle tabular-nums">
                      <th scope="row" className="break-all py-1.5 pr-3 text-left font-normal text-body">
                        {m.model}
                      </th>
                      <td className="py-1.5 pr-3 text-right">{formatInt(m.accuracy.samples)}</td>
                      <td className="py-1.5 pr-3 text-right">
                        <RateCell r={m.accuracy.agreement_rate_ci} fallback={m.accuracy.agreement_rate} />
                      </td>
                      <td className="py-1.5 pr-3 text-right">
                        <RateCell r={m.accuracy.false_negative_rate_ci} fallback={m.accuracy.false_negative_rate} />
                      </td>
                      <td className="py-1.5">
                        <SampleBadge status={m.accuracy.status} n={m.accuracy.samples} needed={r.min_samples} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
      <Card title={`Analyst feedback (${formatInt(r.feedback.total)} decisions)`}>
        <table className="w-full text-sm">
          <caption className="sr-only">Structured analyst feedback</caption>
          <thead className="text-xs uppercase tracking-wide text-muted">
            <tr>
              <th scope="col" className="py-2 pr-3 text-left">Question</th>
              <th scope="col" className="py-2 pr-3 text-right">Yes</th>
              <th scope="col" className="py-2 pr-3 text-right">Answers</th>
              <th scope="col" className="py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {feedbackRow('Triage was correct', r.feedback.triage_correct)}
            {feedbackRow('Analysis was accurate', r.feedback.analysis_accurate)}
            {feedbackRow('Correlation was helpful', r.feedback.correlation_helpful)}
          </tbody>
        </table>
        <p className="mt-2 text-xs text-muted">Average review time {formatDuration(r.feedback.avg_review_duration_s)}.</p>
      </Card>
      <Notes notes={r.notes} />
    </div>
  );
}

// -------------------------------------------------------------- detections

function DetectionsTab({ from, to }: { from: string; to: string }) {
  const api = useApi();
  const { principal } = useAuth();
  const toast = useToast();
  const [proposed, setProposed] = useState<Record<string, string>>({});
  const q = useQuery({
    queryKey: qk.reportDetections.range(from, to),
    queryFn: ({ signal }) => endpoints.detectionsReport(api, from, to, signal),
  });
  const propose = useMutation({
    mutationFn: (d: DetectionOut) => endpoints.proposeSuppression(api, { source_id: d.source_id, rule_field: d.rule_field, rule: d.rule, from, to }),
    onSuccess: (rule, d) => {
      setProposed((p) => ({ ...p, [key(d)]: rule.id }));
      toast.success('Suppression proposed. It is disabled until an admin reviews and enables it under Suppressions.');
    },
    onError: (err) => toast.error(err, 'Could not propose a suppression'),
  });
  const mayPropose = can.createSuppression(principal);
  if (q.isPending) return <LoadingState label="Loading detections report" />;
  if (q.isError) return <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />;
  const r = q.data;
  return (
    <div className="space-y-5">
      <Card title="Detections by volume">
        {r.detections.length === 0 ? (
          <EmptyState title="No alerts in this range" />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[960px] text-left text-sm">
              <caption className="sr-only">Detections by source and rule</caption>
              <thead className="text-xs uppercase tracking-wide text-muted">
                <tr>
                  <th scope="col" className="py-2 pr-3">Source</th>
                  <th scope="col" className="py-2 pr-3">Rule</th>
                  <th scope="col" className="py-2 pr-3 text-right">Volume</th>
                  <th scope="col" className="py-2 pr-3 text-right">Benign</th>
                  <th scope="col" className="py-2 pr-3 text-right">Auto-closed</th>
                  <th scope="col" className="py-2 pr-3 text-right">Analyst FP</th>
                  <th scope="col" className="py-2 pr-3">Median severity</th>
                  <th scope="col" className="py-2 pr-3">Suggestion</th>
                  <th scope="col" className="py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {r.detections.map((d) => {
                  const done = proposed[key(d)];
                  return (
                    <tr key={key(d)} className="border-t border-subtle align-top">
                      <td className="py-2 pr-3 text-body">
                        <Truncated value={d.source_id} className="max-w-[7rem]" />
                      </td>
                      <td className="min-w-[10rem] max-w-xs break-words py-2 pr-3 text-fg">
                        {d.rule}
                        {d.rule_field === 'title' && <span className="block text-xs text-muted">(alert title; no rule name)</span>}
                      </td>
                      <td className="py-2 pr-3 text-right tabular-nums">{formatInt(d.volume)}</td>
                      <td className="py-2 pr-3 text-right tabular-nums">
                        <RateCell r={d.benign_rate_ci} fallback={d.benign_rate} digits={0} />
                        {!d.benign_rate_ci && <span className="block text-xs text-muted">of {formatInt(d.decided)} decided</span>}
                      </td>
                      <td className="py-2 pr-3 text-right tabular-nums">{formatInt(d.auto_closed)}</td>
                      <td className="py-2 pr-3 text-right tabular-nums">{formatInt(d.analyst_false_positive)}</td>
                      <td className="py-2 pr-3 capitalize text-body">{d.median_severity ?? '-'}</td>
                      <td className="max-w-[14rem] py-2 pr-3">
                        {d.suggestion ? <Badge tone={d.suggestion === 'candidate_suppression' ? 'info' : 'warn'}>{SUGGESTION_LABEL[d.suggestion]}</Badge> : <span className="text-muted">None</span>}
                        <span className="mt-1 block text-xs text-secondary">{d.reason}</span>
                      </td>
                      <td className="py-2">
                        {mayPropose && d.can_propose_suppression && (
                          done ? (
                            <Link to="/suppressions" className="text-xs text-link hover:underline">
                              Proposed: review under Suppressions
                            </Link>
                          ) : (
                            <Button size="sm" onClick={() => propose.mutate(d)} busy={propose.isPending && propose.variables === d}>
                              Propose suppression
                            </Button>
                          )
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {r.truncated && <p className="mt-2 text-xs text-muted">Showing the {formatInt(r.limit)} busiest detections; export the CSV for the same list.</p>}
      </Card>
      <Notes notes={r.notes} />
    </div>
  );
}

function key(d: DetectionOut): string {
  return `${d.source_id}\u0000${d.rule_field}\u0000${d.rule}`;
}

// -------------------------------------------------------------------- page

export default function ReportsPage() {
  const api = useApi();
  const toast = useToast();
  const initial = defaultRange();
  const [from, setFrom] = useState(initial.from);
  const [to, setTo] = useState(initial.to);
  const [tab, setTab] = useState<Tab>('value');
  const [exporting, setExporting] = useState(false);
  const invalid = rangeError(from, to);
  const exportKind = tab === 'value' || tab === 'detections' ? tab : null;

  const exportCsv = async () => {
    if (!exportKind || invalid) return;
    setExporting(true);
    try {
      const csv = await endpoints.reportCsv(api, exportKind, from, to);
      downloadText(`lg-sotf-${exportKind}-${from}-${to}.csv`, csv, 'text/csv;charset=utf-8');
    } catch (err) {
      toast.error(err, 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Reports"
        description="Measured on this tenant's own alerts and analyst decisions. Days are UTC."
        actions={
          <>
            <Button
              onClick={() => void exportCsv()}
              disabled={!exportKind || Boolean(invalid)}
              busy={exporting}
              icon={<Download className="h-4 w-4" aria-hidden="true" />}
              title={exportKind ? undefined : 'This report has no CSV export.'}
            >
              Export CSV
            </Button>
            <Link
              to={`/reports/monthly/${monthOf(to)}`}
              className="inline-flex items-center gap-2 rounded-control border border-control px-3.5 py-2 text-sm font-medium text-fg hover:bg-raised-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus"
            >
              <FileText className="h-4 w-4" aria-hidden="true" />
              Open monthly report
            </Link>
          </>
        }
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <TextField label="From" type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} />
        <TextField label="To" type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} />
        {invalid && (
          <p role="alert" className="pb-2 text-sm text-warn-fg">
            {invalid}
          </p>
        )}
      </div>
      <Tabs variant="underline" label="Report" tabs={TABS} value={tab} onChange={setTab}>
        {invalid ? null : tab === 'value' ? (
          <ValueTab from={from} to={to} />
        ) : tab === 'accuracy' ? (
          <AccuracyTab from={from} to={to} />
        ) : tab === 'blind_audit' ? (
          <BlindAuditTab from={from} to={to} tile={(label, value, hint) => <Tile label={label} value={value} hint={hint} />} />
        ) : (
          <DetectionsTab from={from} to={to} />
        )}
      </Tabs>
    </>
  );
}
