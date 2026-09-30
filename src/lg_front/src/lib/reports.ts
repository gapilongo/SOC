/** Helpers for the Reports page and the printable monthly report. */

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

/** "95% range 12.0% to 31.4%" for a Wilson interval, or an empty string. */
export function formatRange(ci: [number, number] | null | undefined): string {
  return ci ? `95% range ${formatPct(ci[0])} to ${formatPct(ci[1])}` : '';
}

/** Trigger a download of `text` as a file (CSV exports carry a BOM for spreadsheet apps). */
export function downloadText(filename: string, text: string, type: string): void {
  const parts = type.startsWith('text/csv') ? ['﻿', text] : [text];
  const blob = new Blob(parts, { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename.replace(/[^A-Za-z0-9._-]/g, '_');
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export const SUGGESTION_LABEL: Record<string, string> = {
  tune_rule: 'Tune rule',
  candidate_suppression: 'Candidate suppression',
};
