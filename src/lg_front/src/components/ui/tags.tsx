import type { ReactNode } from 'react';

import { humanize } from '../../lib/format';
import { cx } from './cx';
import { Glyph, type GlyphName } from './glyphs';
import { VisuallyHidden } from './VisuallyHidden';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Bars filled and their colour: critical four, high three, medium two, low one, info none. */
const SEV_LEVEL: Record<Severity, { bars: number; fill: string }> = {
  critical: { bars: 4, fill: 'fill-sev-critical' },
  high: { bars: 3, fill: 'fill-sev-high' },
  medium: { bars: 2, fill: 'fill-sev-medium' },
  low: { bars: 1, fill: 'fill-sev-low' },
  info: { bars: 0, fill: 'fill-sev-info' },
};

/** The four bars of the 15 by 12 mark: x, and the height each rises to. */
const BARS = [
  { x: 0, h: 4 },
  { x: 4, h: 6.5 },
  { x: 8, h: 9 },
  { x: 12, h: 12 },
];

export function isSeverity(value: string | null | undefined): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value ?? '');
}

/**
 * Severity (or the risk of an action): four bars and the word, never colour
 * alone and never a filled badge. The word carries the meaning; the bars and
 * their colour repeat it. Critical and high are bold. Unknown values get no
 * bar (the neutral, info mark).
 */
export function SeverityTag({ value, suffix, className }: { value: string | null | undefined; suffix?: string; className?: string }) {
  if (!value) return <span className="text-muted">-</span>;
  const level = SEV_LEVEL[isSeverity(value) ? value : 'info'];
  return (
    <span
      data-severity={value}
      className={cx('inline-flex items-center gap-1.5 whitespace-nowrap text-ctl', level.bars >= 3 ? 'font-semibold text-fg' : 'text-body', className)}
    >
      <svg viewBox="0 0 15 12" width="15" height="12" aria-hidden="true" focusable="false" data-bars={level.bars} className="flex-none forced-color-adjust-none">
        {BARS.map((b, i) => (
          <rect key={b.x} x={b.x} y={12 - b.h} width="3" height={b.h} className={i < level.bars ? level.fill : 'fill-strong'} />
        ))}
      </svg>
      {humanize(value)}
      {suffix && <> {suffix}</>}
    </span>
  );
}

export type StateTone = 'waiting' | 'approval' | 'processing' | 'ok' | 'bad' | 'neutral';

/** A state's mark: its shape says what kind of state it is, its colour repeats that. */
const STATE_MARK: Record<StateTone, { glyph: GlyphName; colour: string }> = {
  waiting: { glyph: 'review', colour: 'text-state-waiting' },
  approval: { glyph: 'approval', colour: 'text-state-approval' },
  processing: { glyph: 'run', colour: 'text-state-processing' },
  ok: { glyph: 'backed', colour: 'text-state-ok' },
  bad: { glyph: 'threat', colour: 'text-state-bad' },
  neutral: { glyph: 'empty', colour: 'text-control' },
};

/** A workflow state: a mark and the state in words, flat on the sheet. */
export function StatePill({ tone = 'neutral', children, title, className }: { tone?: StateTone; children: ReactNode; title?: string; className?: string }) {
  const mark = STATE_MARK[tone];
  return (
    <span title={title} data-tone={tone} className={cx('inline-flex items-center gap-1.5 whitespace-nowrap text-ctl text-body', className)}>
      <Glyph name={mark.glyph} className={mark.colour} />
      {children}
    </span>
  );
}

export type CountTone = 'neutral' | 'warn' | 'approval';

const COUNT_TEXT: Record<CountTone, string> = {
  neutral: 'text-fg',
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
      className={cx('inline-flex items-center justify-center rounded-tag bg-raised-2 px-1 py-0.5 font-mono text-2xs font-medium tabular-nums', COUNT_TEXT[tone], className)}
    >
      {count}
      <VisuallyHidden> {meaning.trim()}</VisuallyHidden>
    </span>
  );
}
