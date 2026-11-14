import { useId, type ReactNode } from 'react';

import { humanize } from '../../lib/format';
import { cx } from './cx';

export interface SegmentedOption<T extends string | number> {
  value: T;
  label: string;
  /** Read by screen readers and shown as a tooltip ("Last 7 days" for "7d"). */
  title?: string;
}

/**
 * A single choice among a few options (a time window): native radios, so the
 * arrow keys move between them; the chosen one is inverted.
 */
export function Segmented<T extends string | number>({
  label,
  options,
  value,
  onChange,
  className,
}: {
  label: string;
  options: ReadonlyArray<SegmentedOption<T>>;
  value: T;
  onChange: (next: T) => void;
  className?: string;
}) {
  const name = useId();
  return (
    <fieldset className={cx('inline-flex items-stretch overflow-hidden rounded-control border border-control bg-raised', className)}>
      <legend className="sr-only">{label}</legend>
      {options.map((opt) => (
        <label key={String(opt.value)} title={opt.title} className="relative cursor-pointer border-l border-strong first-of-type:border-l-0">
          <input
            type="radio"
            name={name}
            value={String(opt.value)}
            checked={opt.value === value}
            onChange={() => onChange(opt.value)}
            className="peer sr-only"
          />
          <span
            className={cx(
              'flex h-full min-h-ctl-sm items-center px-2.5 text-xs font-medium text-secondary touch:min-h-ctl-touch',
              'hover:bg-raised-2 hover:text-fg peer-checked:bg-fg peer-checked:text-canvas',
              'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:-outline-offset-2 peer-focus-visible:outline-focus',
            )}
          >
            <span aria-hidden={opt.title ? true : undefined}>{opt.label}</span>
            {opt.title && <span className="sr-only">{opt.title}</span>}
          </span>
        </label>
      ))}
    </fieldset>
  );
}

/** A group of toggle buttons for multi-valued filters (`?status=a&status=b`). */
export function ToggleGroup({
  label,
  options,
  value,
  onChange,
  format = humanize,
}: {
  label: string;
  options: readonly string[];
  value: string[];
  onChange: (next: string[]) => void;
  format?: (v: string) => string;
}) {
  return (
    <fieldset>
      <legend className="mb-1 text-ctl font-medium text-fg">{label}</legend>
      <div className="flex flex-wrap gap-1">
        {options.map((opt) => {
          const on = value.includes(opt);
          return (
            <button
              key={opt}
              type="button"
              aria-pressed={on}
              onClick={() => onChange(on ? value.filter((v) => v !== opt) : [...value, opt])}
              className={cx(
                'min-h-ctl-sm rounded-control border px-2 text-xs font-medium touch:min-h-ctl-touch',
                on ? 'border-fg bg-fg text-canvas' : 'border-control bg-raised text-secondary hover:bg-raised-2 hover:text-fg',
              )}
            >
              {format(opt)}
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}

export function JsonBlock({ value, label }: { value: unknown; label: string }) {
  return (
    <pre
      role="region"
      aria-label={label}
      // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={0}
      className="max-h-80 overflow-auto border-l-3 border-double border-control bg-observed px-2.5 py-2 font-mono text-xs text-fg"
    >
      {JSON.stringify(value ?? null, null, 2)}
    </pre>
  );
}

/**
 * A long value (an id, an address, a message id) kept on one line and cut
 * with an ellipsis; the full value is the tooltip and stays in the DOM, so
 * it is still found, read by screen readers and copied whole.
 */
export function Truncated({ value, mono = false, className }: { value: string; mono?: boolean; className?: string }) {
  return (
    <span title={value} className={cx('block min-w-0 truncate', mono && 'font-mono', className)}>
      {value}
    </span>
  );
}

export function DefinitionList({ items }: { items: Array<[ReactNode, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-3.5 gap-y-1.5 text-ctl sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words text-fg">{v ?? '-'}</dd>
        </div>
      ))}
    </dl>
  );
}
