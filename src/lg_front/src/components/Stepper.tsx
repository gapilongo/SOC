/** The steps of a wizard, in order: done ones ticked, the current one marked `aria-current="step"`. */

import { Check } from 'lucide-react';

import { cx } from './ui';

export function Stepper({ steps, current, label }: { steps: readonly string[]; current: number; label: string }) {
  return (
    <ol aria-label={label} className="mb-4 flex flex-wrap gap-1.5">
      {steps.map((step, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li
            key={step}
            aria-current={active ? 'step' : undefined}
            className={cx(
              'flex min-h-ctl items-center gap-2 rounded-control border px-2 text-xs',
              active ? 'border-fg bg-raised font-semibold text-fg' : 'border-strong text-secondary',
            )}
          >
            <span
              className={cx(
                'flex h-4 w-4 flex-none items-center justify-center rounded-tag border font-mono text-2xs tabular-nums',
                done ? 'border-ok-fg text-ok-fg' : active ? 'border-fg bg-fg text-canvas' : 'border-control',
              )}
              aria-hidden="true"
            >
              {done ? <Check className="h-3 w-3" strokeWidth={2.5} /> : i + 1}
            </span>
            {/* Phones show the current step's name only; the others keep theirs for screen readers. */}
            <span className={active ? undefined : 'sr-only sm:not-sr-only'}>
              {step}
              {done && <span className="sr-only"> (done)</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
