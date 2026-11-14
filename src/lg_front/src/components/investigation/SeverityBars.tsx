/**
 * Severity (or the risk of an action) as four bars and the word: critical
 * fills four, high three, medium two, low one, info none. The word carries
 * the meaning; the bars and their colour repeat it. Critical and high are
 * bold.
 */

import { cx } from '../ui';

const LEVELS: Record<string, { bars: number; colour: string }> = {
  critical: { bars: 4, colour: 'bg-sev-critical' },
  high: { bars: 3, colour: 'bg-sev-high' },
  medium: { bars: 2, colour: 'bg-sev-medium' },
  low: { bars: 1, colour: 'bg-sev-low' },
  info: { bars: 0, colour: 'bg-sev-info' },
};

const HEIGHTS = ['h-1', 'h-[6.5px]', 'h-[9px]', 'h-3'];

export function SeverityBars({ value, suffix, className }: { value: string | null | undefined; suffix?: string; className?: string }) {
  if (!value) return <span className="text-muted">-</span>;
  const level = LEVELS[value] ?? LEVELS.info;
  const word = value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, ' ');
  return (
    <span data-severity={value} className={cx('inline-flex items-center gap-1.5 whitespace-nowrap text-[12.5px]', level.bars >= 3 ? 'font-semibold text-fg' : 'text-body', className)}>
      <span aria-hidden="true" className="flex h-3 flex-none items-end gap-px forced-color-adjust-none">
        {HEIGHTS.map((h, i) => (
          <span key={h} className={cx('w-[3px]', h, i < level.bars ? level.colour : 'bg-strong')} />
        ))}
      </span>
      {word}
      {suffix && <> {suffix}</>}
    </span>
  );
}
