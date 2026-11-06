import type { ReactNode } from 'react';

import { cx } from './cx';

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
