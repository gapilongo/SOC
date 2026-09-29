const dateTime = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '-';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : dateTime.format(d);
}

export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  if (!value) return '-';
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return value;
  const diff = Math.round((t - now) / 1000);
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (abs < 60) return rtf.format(diff, 'second');
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  return rtf.format(Math.round(diff / 86400), 'day');
}

/** Seconds as a compact duration: 45s, 4m 12s, 3h 05m, 2d 4h. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '-';
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, '0')}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** Signed countdown to a deadline: "12m 03s left" or "overdue by 4m 10s". */
export function formatCountdown(deadline: string | null | undefined, now: number): { text: string; overdue: boolean; seconds: number | null } {
  if (!deadline) return { text: 'No SLA', overdue: false, seconds: null };
  const t = new Date(deadline).getTime();
  if (Number.isNaN(t)) return { text: 'No SLA', overdue: false, seconds: null };
  const seconds = Math.round((t - now) / 1000);
  if (seconds >= 0) return { text: `${formatDuration(seconds)} left`, overdue: false, seconds };
  return { text: `overdue by ${formatDuration(-seconds)}`, overdue: true, seconds };
}

const integer = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const usd = new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 4 });

export function formatInt(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value) ? '-' : integer.format(value);
}

export function formatUsd(value: number | string | null | undefined): string {
  const n = typeof value === 'string' ? Number(value) : value;
  return n === null || n === undefined || !Number.isFinite(n) ? '-' : usd.format(n);
}

export function humanize(value: string | null | undefined): string {
  if (!value) return '-';
  return value.replace(/[_.]/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

export function shortId(id: string | null | undefined, size = 8): string {
  if (!id) return '-';
  return id.length > size + 2 ? `${id.slice(0, size)}...` : id;
}

/** `datetime-local` input value (local time) to an ISO string with offset, or undefined. */
export function localInputToIso(value: string): string | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function isoToLocalInput(value: string | null | undefined): string {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
