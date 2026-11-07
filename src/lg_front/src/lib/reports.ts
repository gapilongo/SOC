/** Helpers for the Reports page and the printable monthly report. */

import type { FeedbackRate, RateInterval } from '../api/types';
import { formatInt } from './format';

/** `YYYY-MM-DD` of a date in UTC (report windows are whole UTC days). */
export function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** The default report window: the 30 days ending today (UTC). */
export function defaultRange(today: Date = new Date()): { from: string; to: string } {
  return { from: isoDay(new Date(today.getTime() - 29 * 86_400_000)), to: isoDay(today) };
}

/** `YYYY-MM` of a `YYYY-MM-DD` day (the monthly report of the range's last day). */
export function monthOf(day: string): string {
  return /^\d{4}-\d{2}/.test(day) ? day.slice(0, 7) : isoDay(new Date()).slice(0, 7);
}

/** Validates a report window like the API does (at most 366 days, `to` not before `from`). */
export function rangeError(from: string, to: string): string | null {
  if (!from || !to) return 'Choose a start and an end date.';
  const start = Date.parse(`${from}T00:00:00Z`);
  const end = Date.parse(`${to}T00:00:00Z`);
  if (Number.isNaN(start) || Number.isNaN(end)) return 'Dates must be valid.';
  if (end < start) return 'The end date must not be before the start date.';
  if ((end - start) / 86_400_000 + 1 > 366) return 'A report covers at most 366 days.';
  return null;
}

/** A fraction (0..1) as a percentage; `-` when the rate is undefined (no data). */
export function formatPct(fraction: number | null | undefined, digits = 1): string {
  if (fraction === null || fraction === undefined || !Number.isFinite(fraction)) return '-';
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined || !Number.isFinite(hours)) return '-';
  return `${hours.toLocaleString(undefined, { maximumFractionDigits: 1 })} h`;
}

/**
 * The one wording for a sample too small to read, the same as the API's reports
 * (`lg_sotf.domain.rates.not_enough_data`): "Not enough data (n=4; at least 10 needed)".
 */
export function notEnoughData(n: number, needed?: number): string {
  return `Not enough data (n=${formatInt(n)}${needed ? `; at least ${formatInt(needed)} needed` : ''})`;
}

/** "95% CI 12.0% to 31.4%" for a rate's Wilson interval, or an empty string without one. */
export function formatInterval(r: RateInterval | null | undefined): string {
  if (!r || r.ci_low === null || r.ci_high === null) return '';
  return `95% CI ${formatPct(r.ci_low)} to ${formatPct(r.ci_high)}`;
}

/**
 * "93.3% (14 of 15; 95% CI 70.2% to 98.8%)": a rate with its sample size and Wilson interval, worded
 * like the API's reports (`format_rate`); "Not enough data (n=0)" without a sample. An API that sent
 * no interval gets the bare rate (`fallback`).
 */
export function formatRate(r: RateInterval | null | undefined, fallback?: number | null, digits = 1): string {
  if (!r) return formatPct(fallback, digits);
  if (r.rate === null) return notEnoughData(r.n);
  return `${formatPct(r.rate, digits)} (${rateDetail(r)})`;
}

/** "14 of 15; 95% CI 70.2% to 98.8%": the sample and interval part of `formatRate`. */
export function rateDetail(r: RateInterval): string {
  const k = r.rate === null ? 0 : Math.round(r.rate * r.n);
  const ci = formatInterval(r);
  return `${formatInt(k)} of ${formatInt(r.n)}${ci ? `; ${ci}` : ''}`;
}

/** A FeedbackRate's own `n`/`ci_low`/`ci_high` as a RateInterval (null from an API without them). */
export function feedbackInterval(r: FeedbackRate): RateInterval | null {
  return r.n === null || r.n === undefined ? null : { rate: r.rate, n: r.n, ci_low: r.ci_low ?? null, ci_high: r.ci_high ?? null };
}

export const SUGGESTION_LABEL: Record<string, string> = {
  tune_rule: 'Tune rule',
  candidate_suppression: 'Candidate suppression',
};
