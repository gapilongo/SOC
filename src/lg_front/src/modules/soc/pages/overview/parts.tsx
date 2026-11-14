/**
 * The Overview's small parts, after the console v2 prototype
 * (docs/design/console-v2, `#overview`): content sits on the page, hairlines
 * and type carry the structure, no cards.
 */

import type { ReactNode } from 'react';

import { cx } from '../../../../components/ui';

/** A section's heading with, beside it, what its figures count and over which window. */
export function SectionHead({ id, title, note, children }: { id: string; title: string; note?: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-1 flex flex-wrap items-baseline gap-x-3.5 gap-y-1.5">
      <h2 id={id} className="text-base font-semibold text-fg">
        {title}
      </h2>
      {note && <p className="min-w-0 text-ctl text-muted">{note}</p>}
      {children && <div className="ml-auto text-ctl">{children}</div>}
    </div>
  );
}

/** The small warning chip of a figure that is withheld: "too few for a rate", "not measured yet". */
export function Withheld({ children }: { children: ReactNode }) {
  return <span className="whitespace-nowrap rounded-tag bg-tint-warn px-1 py-0.5 font-mono text-2xs font-medium leading-none text-warn-fg">{children}</span>;
}

/** The mono, upper-case label of a column or of a figure. */
export const LABEL = 'font-mono text-2xs font-medium uppercase tracking-label text-muted';

// Tables: hairlines only. Under the `lg` breakpoint a table becomes stacked records (each cell on
// its own line behind its column name), so a phone never scrolls sideways.
export const TABLE = 'w-full border-collapse text-left max-lg:block';
export const THEAD = 'max-lg:sr-only';
export const TBODY = 'max-lg:block';
export const TR = 'max-lg:block max-lg:border-b max-lg:border-strong max-lg:py-2.5';
export const TH = cx(LABEL, 'whitespace-nowrap border-b border-strong px-2.5 py-1.5');
const TD = 'break-words border-b border-subtle px-2.5 py-1.5 align-middle text-ctl max-lg:block max-lg:border-0 max-lg:px-0 max-lg:py-0.5';
/** A count column: right-aligned figures on a wide screen. */
export const NUM = 'font-semibold tabular-nums text-fg lg:w-[70px] lg:text-right';

/** A table cell; `label` is its column's name, shown before the value once the table is stacked. */
export function Cell({ label, className, colSpan, children }: { label?: string; className?: string; colSpan?: number; children: ReactNode }) {
  return (
    <td colSpan={colSpan} className={cx(TD, className)}>
      {label && <span className={cx(LABEL, 'mr-2 inline-block min-w-[92px] lg:hidden')}>{label}</span>}
      {children}
    </td>
  );
}

/** Three figures side by side with a rule between them; one under the other on a phone. */
export function FigureRow({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('grid grid-cols-[minmax(0,1fr)] border-b border-t border-b-subtle border-t-strong lg:grid-cols-3', className)}>{children}</div>;
}

/** One figure of a FigureRow: its label, the figure, what it counts and the small print. */
export function Figure({ label, big, muted = false, children, small, state }: { label: string; big: ReactNode; muted?: boolean; children?: ReactNode; small?: ReactNode; state?: string }) {
  return (
    <div data-figure={state} className="min-w-0 border-subtle py-3 pb-3.5 max-lg:[&:not(:first-child)]:border-t lg:pr-5 lg:[&:not(:first-child)]:border-l lg:[&:not(:first-child)]:pl-5">
      <h3 className={LABEL}>{label}</h3>
      <p className={cx('mb-1 mt-1.5 text-2xl font-semibold leading-tight tabular-nums', muted ? 'text-secondary' : 'text-fg')}>{big}</p>
      {children && <p className="text-ctl text-body">{children}</p>}
      {small && <div className="mt-1 text-xs text-muted [&>p+p]:mt-1">{small}</div>}
    </div>
  );
}
