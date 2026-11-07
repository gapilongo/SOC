/**
 * CSV export (RFC 4180 quoting) with a spreadsheet formula-injection guard.
 *
 * Alert titles, entity names and audit details come from untrusted sources.
 * A cell starting with `=`, `+`, `-`, `@`, a tab or a carriage return can be
 * executed as a formula by spreadsheet applications, so such text cells are
 * prefixed with a single quote (OWASP "CSV injection" guidance). Numbers are
 * written as numbers and never altered.
 */

import { downloadText } from './download';

const FORMULA_PREFIX = /^[=+\-@\t\r]/;
const NEEDS_QUOTES = /[",\r\n]/;

export function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  let text: string;
  if (value instanceof Date) text = value.toISOString();
  else if (typeof value === 'object') text = JSON.stringify(value);
  else text = String(value);
  if (FORMULA_PREFIX.test(text) || FORMULA_PREFIX.test(text.trimStart())) text = `'${text}`;
  if (NEEDS_QUOTES.test(text) || text !== text.trim()) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export interface CsvColumn<T> {
  header: string;
  value: (row: T) => unknown;
}

export function toCsv<T>(columns: ReadonlyArray<CsvColumn<T>>, rows: ReadonlyArray<T>): string {
  const lines = [columns.map((c) => escapeCsvCell(c.header)).join(',')];
  for (const row of rows) lines.push(columns.map((c) => escapeCsvCell(c.value(row))).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

/** Trigger a download of `csv` (UTF-8 with BOM so spreadsheet apps detect the encoding). */
export function downloadCsv(filename: string, csv: string): void {
  downloadText(filename, csv, 'text/csv;charset=utf-8');
}

export function csvFilename(prefix: string, now: Date = new Date()): string {
  const stamp = now.toISOString().replace(/[:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${prefix}-${stamp}.csv`;
}
