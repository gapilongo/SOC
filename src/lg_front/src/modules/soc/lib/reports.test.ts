import { describe, expect, it } from 'vitest';

import { defaultRange, feedbackInterval, formatHours, formatInterval, formatPct, formatRate, monthOf, notEnoughData, rangeError, rateDetail } from './reports';

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
    expect(formatHours(null)).toBe('-');
    expect(formatHours(1.25)).toMatch(/^1\.3 h$|^1,3 h$/);
  });

  it('renders every rate with n and its 95% Wilson interval, in the API wording', () => {
    const r = { rate: 14 / 15, n: 15, ci_low: 0.7018, ci_high: 0.9881 };
    expect(formatRate(r)).toBe('93.3% (14 of 15; 95% CI 70.2% to 98.8%)');
    expect(rateDetail(r)).toBe('14 of 15; 95% CI 70.2% to 98.8%');
    expect(formatInterval(r)).toBe('95% CI 70.2% to 98.8%');
    expect(formatRate({ rate: 1, n: 12, ci_low: 0.757, ci_high: 1 }, null, 0)).toBe('100% (12 of 12; 95% CI 75.7% to 100.0%)');
    // No sample: the shared small-sample wording, never "0%".
    expect(formatRate({ rate: null, n: 0, ci_low: null, ci_high: null })).toBe('Not enough data (n=0)');
    expect(formatInterval({ rate: null, n: 0, ci_low: null, ci_high: null })).toBe('');
    expect(formatInterval(undefined)).toBe('');
    // An API without the interval: the bare rate.
    expect(formatRate(undefined, 0.5)).toBe('50.0%');
    expect(formatRate(null, null)).toBe('-');
  });

  it('words small samples one way', () => {
    expect(notEnoughData(0)).toBe('Not enough data (n=0)');
    expect(notEnoughData(4, 10)).toBe('Not enough data (n=4; at least 10 needed)');
  });

  it('reads a feedback rate as an interval when the API sends one', () => {
    expect(feedbackInterval({ rate: 0.5, samples: 4, status: 'insufficient_data', n: 4, ci_low: 0.15, ci_high: 0.85 })).toEqual({
      rate: 0.5,
      n: 4,
      ci_low: 0.15,
      ci_high: 0.85,
    });
    expect(feedbackInterval({ rate: 0.5, samples: 4, status: 'insufficient_data' })).toBeNull();
  });

  it('picks the monthly report of the range end', () => {
    expect(monthOf('2026-09-30')).toBe('2026-09');
  });
});
