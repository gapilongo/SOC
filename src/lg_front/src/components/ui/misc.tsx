import { useId, type ReactNode } from 'react';

import { cx } from './cx';

export interface SegmentedOption<T extends string | number> {
  value: T;
  label: string;
  /** Read by screen readers and shown as a tooltip ("Last 7 days" for "7d"). */
  title?: string;
}

/**
 * A single choice among a few options (a time window): native radios, so the
 * arrow keys move between them; the chosen one is raised with an underline.
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
    <fieldset className={cx('inline-flex items-center rounded-control border border-strong bg-raised p-[3px]', className)}>
      <legend className="sr-only">{label}</legend>
      {options.map((opt) => (
        <label key={String(opt.value)} title={opt.title} className="relative cursor-pointer">
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
              'flex h-[30px] items-center rounded-tag border-b-2 border-transparent px-3 text-ctl text-secondary touch:min-h-11',
              'hover:text-fg peer-checked:rounded-b-none peer-checked:border-link peer-checked:bg-raised-2 peer-checked:font-semibold peer-checked:text-fg',
              'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-focus',
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
  format = (v) => v.replace(/_/g, ' '),
}: {
  label: string;
  options: readonly string[];
  value: string[];
  onChange: (next: string[]) => void;
  format?: (v: string) => string;
}) {
  return (
    <fieldset>
      <legend className="mb-1.5 text-ctl font-semibold text-fg">{label}</legend>
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
                'rounded-full border px-2.5 py-0.5 text-xs capitalize touch:min-h-11',
                on ? 'border-link bg-selected text-fg' : 'border-control text-secondary hover:bg-raised-2',
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
      className="max-h-80 overflow-auto rounded-control border border-subtle bg-canvas p-3 font-mono text-xs text-body"
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
    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-secondary">{k}</dt>
          <dd className="min-w-0 break-words text-fg">{v ?? '-'}</dd>
        </div>
      ))}
    </dl>
  );
}
