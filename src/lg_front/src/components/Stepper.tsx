/** The steps of a wizard, in order: done ones ticked, the current one marked `aria-current="step"`. */

import { Check } from 'lucide-react';

import { cx } from './ui';

export function Stepper({ steps, current, label }: { steps: readonly string[]; current: number; label: string }) {
  return (
    <ol aria-label={label} className="mb-5 flex flex-wrap gap-2">
      {steps.map((step, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li
            key={step}
            aria-current={active ? 'step' : undefined}
            className={cx(
              'flex items-center gap-2 rounded-control border px-2.5 py-1 text-xs',
              active ? 'border-focus bg-raised font-semibold text-fg' : 'border-subtle text-secondary',
            )}
          >
            <span
              className={cx(
                'flex h-5 w-5 flex-none items-center justify-center rounded-full border text-xs tabular-nums',
                done ? 'border-ok-fg text-ok-fg' : 'border-control',
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
