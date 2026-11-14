/**
 * Proof-of-value runs: the limits the wizard checks (the API's), the words
 * for each status, and what the page reads from a run.
 */

import type { JsonObject, PovRunOut, RateInterval } from '../../api/types';
import type { StateTone } from '../../components/ui';
import { humanize } from '../../lib/format';
import { isJsonObject } from '../../lib/json';
import { isoDay } from '../../lib/reports';

export interface DayLimits {
  min: number;
  max: number;
  initial: number;
}

export const BACKTEST_DAYS: DayLimits = { min: 1, max: 366, initial: 90 };
export const SHADOW_DAYS: DayLimits = { min: 1, max: 90, initial: 14 };
export const MAX_NAME_CHARS = 120;
/** A backtest replays at most this many alerts (each one calls the model). */
export const BACKTEST_ALERT_LIMIT = 500;

/** A whole number of days within `limits`, or null. */
export function parseDays(value: string, limits: DayLimits): number | null {
  const v = value.trim();
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  return n >= limits.min && n <= limits.max ? n : null;
}

export interface StatusText {
  label: string;
  tone: StateTone;
}

const RUN_STATUS: Record<string, StatusText> = {
  backtest: { label: 'Backtest in progress', tone: 'processing' },
  shadow: { label: 'Shadow period', tone: 'processing' },
  completed: { label: 'Completed', tone: 'ok' },
  cancelled: { label: 'Stopped', tone: 'neutral' },
};

const BACKTEST_STATUS: Record<string, StatusText> = {
  pending: { label: 'Waiting to start', tone: 'waiting' },
  running: { label: 'Running', tone: 'processing' },
  completed: { label: 'Completed', tone: 'ok' },
  no_data: { label: 'No decided alerts', tone: 'neutral' },
  failed: { label: 'Failed', tone: 'bad' },
};

const SHADOW_STATUS: Record<string, StatusText> = {
  scheduled: { label: 'Not started', tone: 'waiting' },
  running: { label: 'Observing', tone: 'processing' },
  completed: { label: 'Ended', tone: 'ok' },
};

/** A status the app does not know (a newer API) is shown as it is, in words. */
function text(table: Record<string, StatusText>, status: string): StatusText {
  return table[status] ?? { label: humanize(status), tone: 'neutral' };
}

export const runStatus = (status: string) => text(RUN_STATUS, status);
export const backtestStatus = (status: string) => text(BACKTEST_STATUS, status);
export const shadowStatus = (status: string) => text(SHADOW_STATUS, status);

/** A run that still blocks a new one: its backtest or its shadow period is not over. */
export function inProgress(run: PovRunOut): boolean {
  return run.status === 'backtest' || run.status === 'shadow';
}

/** The shadow period as a report window: whole UTC days, both included. */
export function shadowRange(run: PovRunOut): { from: string; to: string } {
  const start = Date.parse(run.shadow.window_start);
  const end = Math.max(start, Date.parse(run.shadow.window_end) - 1);
  return { from: isoDay(new Date(start)), to: isoDay(new Date(end)) };
}

/** The headline figures of a completed backtest. */
export interface BacktestSummary {
  /** Analyst-decided alerts replayed. */
  items: number;
  /** Replays that failed (not scored). */
  errors: number;
  /** Alerts analysts confirmed as threats, among the scored ones. */
  threats: number;
  /** Confirmed threats the triage would have closed on its own. */
  missed: number;
  missedRate: RateInterval | null;
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function interval(value: unknown): RateInterval | null {
  if (!isJsonObject(value) || typeof value.n !== 'number') return null;
  const part = (v: unknown) => (typeof v === 'number' ? v : null);
  return { rate: part(value.rate), n: value.n, ci_low: part(value.ci_low), ci_high: part(value.ci_high) };
}

/** Reads the stored evaluation report (`backtest.result`); null when it has no metrics. */
export function backtestSummary(result: JsonObject | null | undefined): BacktestSummary | null {
  const metrics = result?.metrics;
  if (!isJsonObject(metrics)) return null;
  const intervals = isJsonObject(metrics.intervals) ? metrics.intervals : {};
  return {
    items: count(metrics.items),
    errors: count(metrics.errors),
    threats: count(metrics.malicious_items),
    missed: count(metrics.malicious_false_negatives),
    missedRate: interval(intervals.malicious_false_negative_rate),
  };
}
