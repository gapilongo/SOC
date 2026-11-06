import type { ReactNode } from 'react';

import { cx } from './cx';
import { VisuallyHidden } from './VisuallyHidden';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

const SEV_SQUARE: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

export function isSeverity(value: string | null | undefined): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value ?? '');
}

/**
 * Severity: a coloured square plus the word, never colour alone and never a
 * filled badge. Unknown values get the neutral (info) square.
 */
export function SeverityTag({ value, suffix, className }: { value: string | null | undefined; suffix?: string; className?: string }) {
  if (!value) return <span className="text-muted">-</span>;
  const square = SEV_SQUARE[isSeverity(value) ? value : 'info'];
  return (
    <span className={cx('inline-flex items-center gap-1.5 whitespace-nowrap text-ctl capitalize text-body', className)} data-severity={value}>
      <span className={cx('h-2 w-2 flex-none rounded-[2px]', square)} aria-hidden="true" />
      {value}
      {suffix && <> {suffix}</>}
    </span>
  );
}

export type StateTone = 'waiting' | 'approval' | 'processing' | 'ok' | 'bad' | 'neutral';

const STATE_DOT: Record<StateTone, string> = {
  waiting: 'bg-state-waiting',
  approval: 'bg-state-approval',
  processing: 'bg-state-processing',
  ok: 'bg-state-ok',
  bad: 'bg-state-bad',
  neutral: 'bg-muted',
};

/** A workflow state: neutral pill, coloured dot, the state in words. */
export function StatePill({ tone = 'neutral', children, title, className }: { tone?: StateTone; children: ReactNode; title?: string; className?: string }) {
  return (
    <span
      title={title}
      data-tone={tone}
      className={cx('inline-flex items-center gap-1.5 whitespace-nowrap rounded-tag bg-raised-2 px-2 py-0.5 text-xs font-medium text-body', className)}
    >
      <span className={cx('h-1.5 w-1.5 flex-none rounded-full', STATE_DOT[tone])} aria-hidden="true" />
      {children}
    </span>
  );
}

export type CountTone = 'neutral' | 'warn' | 'approval';

const COUNT_TEXT: Record<CountTone, string> = {
  neutral: 'text-body',
  warn: 'text-warn',
  approval: 'text-state-approval',
};

/**
 * A small count (nav items, tabs). `meaning` is read by screen readers after
 * the number (" unassigned escalations breaching SLA"), so the count is never
 * a bare number.
 */
export function CountChip({ count, meaning, tone = 'neutral', className }: { count: number; meaning: string; tone?: CountTone; className?: string }) {
  return (
    <span
      data-tone={tone}
      className={cx(
        'inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-raised-2 px-1.5 text-2xs font-semibold tabular-nums',
        COUNT_TEXT[tone],
        className,
      )}
    >
      {count}
      <VisuallyHidden> {meaning.trim()}</VisuallyHidden>
    </span>
  );
}
