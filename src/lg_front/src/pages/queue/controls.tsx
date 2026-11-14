/** The queue's small controls, drawn as the console v2 design draws them: 28 px high, 3 px corners, hairline borders. */

import { Loader2 } from 'lucide-react';
import type { ButtonHTMLAttributes } from 'react';

import { cx } from '../../components/ui';
import { DENSITIES, DENSITY_LABELS, type QueueDensity } from './model';

export type QButtonVariant = 'default' | 'primary' | 'quiet';

const VARIANT: Record<QButtonVariant, string> = {
  default: 'border-control bg-raised text-fg hover:bg-raised-2',
  primary: 'border-accent bg-accent text-on-accent hover:bg-accent-hover hover:text-on-accent',
  quiet: 'border-transparent bg-transparent text-secondary hover:bg-raised-2 hover:text-fg',
};

/** The classes of a queue button, for a link that looks like one. */
export function qbuttonClass(variant: QButtonVariant = 'default', className?: string): string {
  return cx(
    'inline-flex h-7 flex-none items-center gap-1.5 whitespace-nowrap rounded-[3px] border px-2.5 text-ctl font-medium',
    'disabled:cursor-not-allowed disabled:opacity-55 touch:min-h-11',
    VARIANT[variant],
    className,
  );
}

export function QButton({
  variant = 'default',
  busy = false,
  className,
  children,
  disabled,
  type = 'button',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: QButtonVariant; busy?: boolean }) {
  return (
    <button type={type} disabled={disabled || busy} aria-busy={busy || undefined} className={qbuttonClass(variant, className)} {...rest}>
      {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={1.75} aria-hidden="true" />}
      {children}
    </button>
  );
}

/** A filter that is fixed for now, shown as the design's chip: the name, then its value. */
export function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex h-[22px] items-center gap-[5px] whitespace-nowrap rounded-sm bg-raised-2 px-[7px] text-xs text-secondary">
      {label} <b className="font-semibold text-fg">{value}</b>
    </span>
  );
}

/** Dense (24 px rows), Compact (28) or Two lines (44). */
export function DensityControl({ value, onChange }: { value: QueueDensity; onChange: (d: QueueDensity) => void }) {
  return (
    <div role="group" aria-label="Row density" className="inline-flex overflow-hidden rounded-[3px] border border-control">
      {DENSITIES.map((d, i) => (
        <button
          key={d}
          type="button"
          aria-pressed={value === d}
          onClick={() => onChange(d)}
          className={cx(
            'h-[26px] px-[9px] text-xs font-medium focus-visible:-outline-offset-2 touch:min-h-11',
            i > 0 && 'border-l border-strong',
            value === d ? 'bg-fg text-canvas' : 'bg-raised text-secondary hover:bg-raised-2',
          )}
        >
          {DENSITY_LABELS[d]}
        </button>
      ))}
    </div>
  );
}

/** The keys the queue answers to, under the list. */
export function Keys({ canAct }: { canAct: boolean }) {
  const item = 'inline-flex items-center gap-[5px]';
  return (
    <div role="note" aria-label="Keyboard" className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted">
      <span className={item}>
        <kbd>J</kbd>
        <kbd>K</kbd> move
      </span>
      <span className={item}>
        <kbd>Enter</kbd> open
      </span>
      <span className={item}>
        <kbd>Space</kbd> preview
      </span>
      {canAct && (
        <>
          <span className={item}>
            <kbd>X</kbd> select
          </span>
          <span className={item}>
            <kbd>C</kbd> claim
          </span>
        </>
      )}
    </div>
  );
}

/** Rows standing in for the list while it loads. */
export function SkeletonRows() {
  return (
    <div role="status" className="py-1">
      <span className="sr-only">Loading the queue</span>
      {Array.from({ length: 12 }, (_, i) => (
        <div key={i} aria-hidden="true" className="flex h-7 items-center gap-3 border-b border-subtle px-3">
          <span className="h-2.5 w-14 rounded-sm bg-raised-2" />
          <span className="h-2.5 w-16 rounded-sm bg-raised-2" />
          <span className={cx('h-2.5 rounded-sm bg-raised-2', i % 3 === 0 ? 'w-2/3' : i % 3 === 1 ? 'w-1/2' : 'w-3/5')} />
        </div>
      ))}
    </div>
  );
}
