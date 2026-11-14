/**
 * Times of an investigation, as a 24-hour clock with seconds ("09:44:28"):
 * observations and steps happen seconds apart, and the column is narrow.
 */

const clock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const day = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit' });

/** The time and the day of `value` apart; null when it is not a date. */
export function clockOf(value: string | null | undefined): { time: string; day: string } | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : { time: clock.format(d), day: day.format(d) };
}
