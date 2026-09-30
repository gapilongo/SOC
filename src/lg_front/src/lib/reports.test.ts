import { describe, expect, it } from 'vitest';

import { defaultRange, formatHours, formatPct, formatRange, monthOf, rangeError } from './reports';

describe('report helpers', () => {
  it('defaults to the 30 days ending today (UTC)', () => {
    expect(defaultRange(new Date('2026-09-30T23:00:00Z'))).toEqual({ from: '2026-09-01', to: '2026-09-30' });
  });

  it('validates windows like the API', () => {
    expect(rangeError('2026-09-01', '2026-09-30')).toBeNull();
    expect(rangeError('2025-10-01', '2026-10-01')).toBeNull();
    expect(rangeError('2025-09-30', '2026-10-01')).toMatch(/366/);
    expect(rangeError('2026-09-02', '2026-09-01')).toMatch(/before/);
    expect(rangeError('', '2026-09-01')).toMatch(/Choose/);
  });

  it('formats rates without inventing zeros', () => {
    expect(formatPct(null)).toBe('-');
    expect(formatPct(undefined)).toBe('-');
    expect(formatPct(0)).toBe('0.0%');
    expect(formatPct(5 / 9)).toBe('55.6%');
    expect(formatPct(0.5, 0)).toBe('50%');
    expect(formatRange(null)).toBe('');
    expect(formatRange([0.1, 0.25])).toBe('95% range 10.0% to 25.0%');
    expect(formatHours(null)).toBe('-');
    expect(formatHours(1.25)).toMatch(/^1\.3 h$|^1,3 h$/);
  });

  it('picks the monthly report of the range end', () => {
    expect(monthOf('2026-09-30')).toBe('2026-09');
  });
});
