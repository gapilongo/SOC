import { Fragment, type ReactNode } from 'react';

import { cx } from './cx';

/** One entity value (a host, a user, an address, a hash): monospace, breaks anywhere, never wider than its container. */
export function EntityChip({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx('max-w-full break-all rounded-tag bg-raised-2 px-1.5 py-0.5 font-mono text-xs text-fg', className)}>{children}</code>;
}

/** The values of one kind of entity. */
export interface EntityGroup {
  /** The kind as the data names it (`hosts`, `users`, `ips`); passed back to `after`. */
  kind: string;
  /** The kind in words. */
  label: string;
  values: readonly string[];
}

/**
 * How kinds and values are laid out:
 * - `stacked`: each kind above its values, for narrow panels;
 * - `columns`: kinds in a left column from the `sm` breakpoint, for wide pages.
 */
export type EntityListLayout = 'stacked' | 'columns';

/**
 * Entities grouped by kind, each value a chip. `after(kind, value)` renders
 * next to a value: the place for a cross-link from another service ("3 open
 * findings on this host").
 */
export function EntityList({
  groups,
  layout = 'stacked',
  after,
  className,
}: {
  groups: readonly EntityGroup[];
  layout?: EntityListLayout;
  after?: (kind: string, value: string) => ReactNode;
  className?: string;
}) {
  const columns = layout === 'columns';
  return (
    <dl className={cx(columns ? 'grid grid-cols-1 gap-x-3 gap-y-2 text-ctl sm:grid-cols-[140px_1fr]' : 'space-y-3', className)}>
      {groups.map((g) => (
        <div key={g.kind} className={columns ? 'contents' : undefined}>
          <dt className={columns ? 'text-secondary' : 'mb-1 text-xs font-medium text-muted'}>{g.label}</dt>
          <dd className={cx('flex flex-wrap gap-1.5', columns && 'min-w-0')}>
            {g.values.map((v, i) => (
              <Fragment key={`${v}-${i}`}>
                <EntityChip>{v}</EntityChip>
                {after?.(g.kind, v)}
              </Fragment>
            ))}
          </dd>
        </div>
      ))}
    </dl>
  );
}
