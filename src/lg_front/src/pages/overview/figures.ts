/** Pure helpers of the Overview: windows, sample-size guards and labels. */

import type { DashboardOut } from '../../api/types';
import { formatDuration, formatInt } from '../../lib/format';
import { formatPct, notEnoughData } from '../../lib/reports';

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
 * Below this many observations a mean or a rate is not shown: one slow claim
 * or one escalated alert would read as a trend ("0%" of one alert).
 */
export const MIN_SAMPLE = 5;

export interface Figure {
  value: string;
  /** What it counts, over what. */
  sub: string;
  /** False when the sample is too small to show the value. */
  enough: boolean;
}

function notEnough(n: number): Figure {
  return { value: '—', sub: notEnoughData(n, MIN_SAMPLE), enough: false };
}

/** Share of the window's finished alerts closed without an analyst. */
export function handledFigure(d: DashboardOut, phrase: string): Figure {
  const handled = d.handled_without_human ?? 0;
  const finished = handled + (d.needed_human ?? 0);
  if (finished < MIN_SAMPLE || d.handled_without_human_rate === null || d.handled_without_human_rate === undefined) {
    return notEnough(finished);
  }
  return {
    value: formatPct(d.handled_without_human_rate, 0),
    sub: `${formatInt(handled)} of ${formatInt(finished)} finished alerts ingested in ${phrase}`,
    enough: true,
  };
}

/** Mean escalation creation to claim, over escalations claimed in the window. */
export function mttaFigure(d: DashboardOut, phrase: string): Figure {
  if (d.acknowledged < MIN_SAMPLE || d.mtta_s === null || d.mtta_s === undefined) return notEnough(d.acknowledged);
  return { value: formatDuration(d.mtta_s), sub: `Over ${formatInt(d.acknowledged)} escalations claimed in ${phrase}`, enough: true };
}

/** Mean ingestion to close, over alerts closed in the window. */
export function mttrFigure(d: DashboardOut, phrase: string): Figure {
  if (d.resolved < MIN_SAMPLE || d.mttr_s === null || d.mttr_s === undefined) return notEnough(d.resolved);
  return { value: formatDuration(d.mttr_s), sub: `Over ${formatInt(d.resolved)} alerts closed in ${phrase}`, enough: true };
}

/** Alert statuses in pipeline order with their words and state tone. */
export const STATUS_STEPS = [
  { status: 'new', label: 'New', tone: 'neutral' },
  { status: 'queued', label: 'Queued', tone: 'neutral' },
  { status: 'processing', label: 'Processing', tone: 'processing' },
  { status: 'waiting_human', label: 'Waiting for an analyst', tone: 'waiting' },
  { status: 'waiting_approval', label: 'Waiting for approval', tone: 'approval' },
  { status: 'closed', label: 'Closed', tone: 'ok' },
  { status: 'failed', label: 'Failed', tone: 'bad' },
] as const;

export const RISK_ORDER = ['critical', 'high', 'medium', 'low'] as const;

export const plural = (n: number, one: string, many: string) => `${formatInt(n)} ${n === 1 ? one : many}`;
