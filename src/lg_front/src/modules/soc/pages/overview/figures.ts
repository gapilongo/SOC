/**
 * Pure helpers of the Overview: windows, sample-size guards and the wording
 * of each figure. Nothing here adds to what the API measured: a figure is a
 * field of the dashboard summary or of the blind-audit report, and where the
 * sample is too small the helper says so and gives no rate.
 */

import type { BlindAuditEstimate, DashboardOut } from '../../api/types';
import { formatDuration, formatInt } from '../../../../lib/format';
import { formatPct } from '../../lib/reports';

export interface OverviewWindow {
  hours: number;
  /** The switch label. */
  short: string;
  /** "the last 24 hours" (used in sentences). */
  phrase: string;
}

export const WINDOWS: readonly OverviewWindow[] = [
  { hours: 24, short: '24h', phrase: 'the last 24 hours' },
  { hours: 168, short: '7d', phrase: 'the last 7 days' },
  { hours: 720, short: '30d', phrase: 'the last 30 days' },
];

export const DEFAULT_WINDOW_HOURS = 24;

export function windowPhrase(hours: number): string {
  return WINDOWS.find((w) => w.hours === hours)?.phrase ?? `the last ${formatInt(hours)} hours`;
}

/**
 * Below this many observations a mean or a share is not shown: one slow claim
 * or one escalated alert would read as a trend ("0%" of one alert).
 */
export const MIN_SAMPLE = 5;

export const RISK_ORDER = ['critical', 'high', 'medium', 'low'] as const;

export const plural = (n: number, one: string, many: string) => `${formatInt(n)} ${n === 1 ? one : many}`;

/** "n=1; at least 5 needed": why a rate or a mean is withheld. */
export function sampleNote(n: number, needed: number): string {
  return `n=${formatInt(n)}; at least ${formatInt(needed)} needed`;
}

// Closed without a person ---------------------------------------------------------

/**
 * The window's finished alerts by whether a person was involved (the API's
 * `handled_without_human` and `needed_human`; alerts still being processed
 * and the built-in sample alerts are in neither).
 */
export interface HandledSplit {
  handled: number;
  needed: number;
  /** handled + needed: what the API divides by. */
  finished: number;
  /** Shares of `finished` (0..1); null while the sample is too small for a share. */
  handledShare: number | null;
  neededShare: number | null;
}

function whole(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.round(value) : null;
}

/** The split, or null on an API that does not send it. */
export function handledSplit(d: DashboardOut): HandledSplit | null {
  const handled = whole(d.handled_without_human);
  const needed = whole(d.needed_human);
  if (handled === null || needed === null) return null;
  const finished = handled + needed;
  const rate = d.handled_without_human_rate;
  const enough = finished >= MIN_SAMPLE && typeof rate === 'number' && Number.isFinite(rate);
  return { handled, needed, finished, handledShare: enough ? rate : null, neededShare: enough ? 1 - rate : null };
}

/** The headline of the block: one sentence a reader can check against the table under it. */
export function handledStatement(d: DashboardOut, split: HandledSplit | null, phrase: string): string {
  if (d.alerts_total === 0) return `No alert was received in ${phrase}.`;
  if (!split) return `${plural(d.alerts_total, 'alert was', 'alerts were')} received in ${phrase}.`;
  if (split.finished === 0) return `None of the ${plural(d.alerts_total, 'alert', 'alerts')} received in ${phrase} is finished yet.`;
  const reached = split.needed === 0 ? 'None' : formatInt(split.needed);
  return `${formatInt(split.handled)} of ${plural(split.finished, 'finished alert was', 'finished alerts were')} closed without a person. ${reached} reached one.`;
}

export interface Mean {
  /** "7m 00s", or null while the sample is too small for a mean. */
  value: string | null;
  /** The observations behind it. */
  n: number;
}

/** Mean escalation creation to claim, over escalations claimed in the window. */
export function claimMean(d: DashboardOut): Mean {
  const enough = d.acknowledged >= MIN_SAMPLE && d.mtta_s !== null && d.mtta_s !== undefined;
  return { value: enough ? formatDuration(d.mtta_s) : null, n: d.acknowledged };
}

/** Mean arrival to close, over alerts closed in the window. */
export function closeMean(d: DashboardOut): Mean {
  const enough = d.resolved >= MIN_SAMPLE && d.mttr_s !== null && d.mttr_s !== undefined;
  return { value: enough ? formatDuration(d.mttr_s) : null, n: d.resolved };
}

// Blind audit ----------------------------------------------------------------------

/**
 * What the blind-audit block can say:
 * `none` no close was sampled in the period; `unlabelled` samples exist and
 * none has a malicious-or-benign label; `few` labels exist, too few for a
 * rate; `rate` the API gives the missed-threat rate with its interval.
 */
export type AuditState = 'none' | 'unlabelled' | 'few' | 'rate';

export interface AuditFigure {
  state: AuditState;
  /** Samples labelled malicious or benign: the n of the rate. */
  decided: number;
  /** "0.6%" and "0.0% to 3.1%", in the `rate` state. */
  rate: string | null;
  interval: string | null;
  /** "12.0%": unsure and waiting samples counted as malicious, when some remain. */
  worstCase: string | null;
}

export function auditFigure(e: BlindAuditEstimate): AuditFigure {
  const decided = e.malicious + e.benign;
  const base = { decided, rate: null, interval: null, worstCase: null };
  if (e.sampled === 0) return { ...base, state: 'none' };
  if (decided === 0) return { ...base, state: 'unlabelled' };
  const fn = e.false_negative_rate;
  if (e.status === 'insufficient_data' || decided < e.min_samples || fn.rate === null) return { ...base, state: 'few' };
  const open = e.pending + e.unsure;
  return {
    state: 'rate',
    decided,
    rate: formatPct(fn.rate),
    interval: fn.ci_low !== null && fn.ci_high !== null ? `${formatPct(fn.ci_low)} to ${formatPct(fn.ci_high)}` : null,
    worstCase: open > 0 && e.worst_case_rate !== null ? formatPct(e.worst_case_rate) : null,
  };
}

const DAY = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });

/** "16 Oct to 14 Nov": a report window of whole UTC days. */
export function dayRange(from: string, to: string): string {
  const day = (value: string) => {
    const d = new Date(`${value}T00:00:00Z`);
    return Number.isNaN(d.getTime()) ? value : DAY.format(d);
  };
  return `${day(from)} to ${day(to)}`;
}
