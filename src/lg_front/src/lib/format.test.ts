import { describe, expect, it } from 'vitest';

import {
  formatCountdown,
  formatDateAndTime,
  formatDateTime,
  formatDuration,
  formatInt,
  formatRelative,
  formatUsd,
  formatUsdAxis,
  humanize,
  isoToLocalInput,
  localInputToIso,
  shortId,
} from './format';

const NOW = Date.parse('2026-11-07T12:00:00Z');
const at = (seconds: number) => new Date(NOW + seconds * 1000).toISOString();

describe('dates', () => {
  it('formats a timestamp, and passes through what is not one', () => {
    expect(formatDateTime(null)).toBe('-');
    expect(formatDateTime('')).toBe('-');
    expect(formatDateTime('not a date')).toBe('not a date');
    expect(formatDateTime('2026-11-07T12:00:00Z')).toMatch(/2026/);
    expect(formatDateAndTime(undefined)).toEqual({ date: '-', time: '' });
    expect(formatDateAndTime('soon')).toEqual({ date: 'soon', time: '' });
    const parts = formatDateAndTime('2026-11-07T12:00:00Z');
    expect(parts.date).toMatch(/2026/);
    expect(parts.time).toMatch(/\d{2}/);
  });

  it('words a time relative to now in the nearest unit', () => {
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    expect(formatRelative(null, NOW)).toBe('-');
    expect(formatRelative('whenever', NOW)).toBe('whenever');
    expect(formatRelative(at(-30), NOW)).toBe(rtf.format(-30, 'second'));
    expect(formatRelative(at(-600), NOW)).toBe(rtf.format(-10, 'minute'));
    expect(formatRelative(at(2 * 3600), NOW)).toBe(rtf.format(2, 'hour'));
    expect(formatRelative(at(-3 * 86400), NOW)).toBe(rtf.format(-3, 'day'));
    // Without `now`, the clock is read.
    expect(formatRelative(new Date().toISOString())).toBe(rtf.format(0, 'second'));
  });

  it('converts between ISO and a datetime-local input', () => {
    expect(localInputToIso('')).toBeUndefined();
    expect(localInputToIso('garbage')).toBeUndefined();
    const iso = localInputToIso('2026-11-07T09:05');
    expect(iso).toBe(new Date('2026-11-07T09:05').toISOString());
    expect(isoToLocalInput(iso)).toBe('2026-11-07T09:05');
    expect(isoToLocalInput(null)).toBe('');
    expect(isoToLocalInput('garbage')).toBe('');
  });
});

describe('durations', () => {
  it('writes seconds compactly', () => {
    expect(formatDuration(null)).toBe('-');
    expect(formatDuration(undefined)).toBe('-');
    expect(formatDuration(Number.NaN)).toBe('-');
    expect(formatDuration(-5)).toBe('0s');
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(252)).toBe('4m 12s');
    expect(formatDuration(3 * 3600 + 5 * 60)).toBe('3h 05m');
    expect(formatDuration(2 * 86400 + 4 * 3600)).toBe('2d 4h');
  });

  it('counts down to a deadline, and says by how much it is overdue', () => {
    expect(formatCountdown(null, NOW)).toEqual({ text: 'No SLA', overdue: false, seconds: null });
    expect(formatCountdown('never', NOW)).toEqual({ text: 'No SLA', overdue: false, seconds: null });
    expect(formatCountdown(at(723), NOW)).toEqual({ text: '12m 03s left', overdue: false, seconds: 723 });
    expect(formatCountdown(at(0), NOW)).toEqual({ text: '0s left', overdue: false, seconds: 0 });
    expect(formatCountdown(at(-250), NOW)).toEqual({ text: 'overdue by 4m 10s', overdue: true, seconds: -250 });
  });
});

describe('numbers', () => {
  const digits = (s: string) => s.replace(/[^\d]/g, '');

  it('formats counts and dollars, with a dash for what is not a number', () => {
    expect(formatInt(null)).toBe('-');
    expect(formatInt(undefined)).toBe('-');
    expect(formatInt(Number.POSITIVE_INFINITY)).toBe('-');
    expect(digits(formatInt(12345.6))).toBe('12346');
    expect(formatUsd(null)).toBe('-');
    expect(formatUsd(undefined)).toBe('-');
    expect(formatUsd('abc')).toBe('-');
    expect(digits(formatUsd(3.5))).toBe('350');
    expect(digits(formatUsd('0.0042'))).toBe('00042');
  });

  it('labels a chart axis with two decimals from a dollar up and up to four below', () => {
    expect(formatUsdAxis(Number.NaN)).toBe('-');
    expect(digits(formatUsdAxis(370.371))).toBe('37037');
    expect(digits(formatUsdAxis(0))).toBe('0');
    expect(digits(formatUsdAxis(0.0042))).toBe('00042');
    expect(digits(formatUsdAxis(-0.5))).toBe('05');
  });
});

describe('words and ids', () => {
  it('turns a code into words', () => {
    expect(humanize(null)).toBe('-');
    expect(humanize('')).toBe('-');
    expect(humanize('waiting_human')).toBe('Waiting human');
    expect(humanize('alert.created')).toBe('Alert created');
  });

  it('shortens a long id and leaves a short one', () => {
    expect(shortId(null)).toBe('-');
    expect(shortId('abc')).toBe('abc');
    expect(shortId('0123456789')).toBe('0123456789');
    expect(shortId('0123456789abcdef')).toBe('01234567...');
    expect(shortId('0123456789abcdef', 4)).toBe('0123...');
  });
});
