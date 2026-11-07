import { useVirtualizer } from '@tanstack/react-virtual';
import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

import { ROW_HEIGHT, useDensity } from '../theme/density';
import { Button, cx } from './ui';

export interface Column<T> {
  key: string;
  header: string;
  /** CSS grid track, e.g. `minmax(12rem, 3fr)` or `8rem`. */
  width: string;
  render: (row: T) => ReactNode;
  className?: string;
}

/**
 * A windowed table for long keyset-paginated lists. Only visible rows are
 * rendered. Keyboard: Up/Down/Home/End/PageUp/PageDown move between rows,
 * Enter or Space opens the focused row. More pages load when the end comes
 * into view, and a "Load more" button offers the same explicitly.
 */
export function VirtualTable<T>({
  label,
  columns,
  rows,
  rowKey,
  rowLabel,
  onOpen,
  selectedKey,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
  autoLoad = true,
  rowHeight: rowHeightProp,
  maxHeight = 'calc(100vh - 20rem)',
  minWidth = '900px',
}: {
  label: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  rowLabel: (row: T) => string;
  onOpen?: (row: T) => void;
  selectedKey?: string | null;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  /** Load the next page automatically near the end (off after a failed page load). */
  autoLoad?: boolean;
  /** Fixed row height (px); by default it follows the table density preference. */
  rowHeight?: number;
  maxHeight?: string;
  /** Narrowest the grid gets before it scrolls sideways. */
  minWidth?: string;
}) {
  const { density } = useDensity();
  const rowHeight = rowHeightProp ?? ROW_HEIGHT[density];
  const scrollRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(0);
  const template = columns.map((c) => c.width).join(' ');

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 10,
    initialRect: { width: 1024, height: 600 },
  });
  // A density change resizes every row.
  useEffect(() => virtualizer.measure(), [virtualizer, rowHeight]);
  const items = virtualizer.getVirtualItems();
  const lastIndex = items.length ? items[items.length - 1].index : -1;

  useEffect(() => {
    if (autoLoad && hasMore && !loadingMore && onLoadMore && lastIndex >= rows.length - 10 && rows.length > 0) onLoadMore();
  }, [autoLoad, hasMore, loadingMore, onLoadMore, lastIndex, rows.length]);

  useEffect(() => {
    if (active >= rows.length && rows.length > 0) setActive(rows.length - 1);
  }, [active, rows.length]);

  const focusRow = useCallback(
    (index: number) => {
      const clamped = Math.max(0, Math.min(rows.length - 1, index));
      setActive(clamped);
      virtualizer.scrollToIndex(clamped, { align: 'auto' });
      requestAnimationFrame(() => {
        scrollRef.current?.querySelector<HTMLElement>(`[data-row-index="${clamped}"]`)?.focus();
      });
    },
    [rows.length, virtualizer],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>, index: number, row: T) => {
    const page = Math.max(1, Math.floor((scrollRef.current?.clientHeight ?? 400) / rowHeight) - 1);
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusRow(index + 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusRow(index - 1);
        break;
      case 'PageDown':
        e.preventDefault();
        focusRow(index + page);
        break;
      case 'PageUp':
        e.preventDefault();
        focusRow(index - page);
        break;
      case 'Home':
        e.preventDefault();
        focusRow(0);
        break;
      case 'End':
        e.preventDefault();
        focusRow(rows.length - 1);
        break;
      case 'Enter':
      case ' ':
        if (onOpen) {
          e.preventDefault();
          onOpen(row);
        }
        break;
      default:
    }
  };

  return (
    <div className="overflow-hidden rounded-card border border-subtle bg-raised">
      <div className="overflow-x-auto">
        <div role="grid" aria-readonly="true" aria-label={label} aria-rowcount={rows.length + 1} style={{ minWidth }}>
          <div role="rowgroup">
            <div
              role="row"
              aria-rowindex={1}
              className="table-grid grid border-b border-subtle bg-raised text-xs font-semibold uppercase tracking-wide text-muted"
              style={{ gridTemplateColumns: template }}
            >
              {columns.map((c) => (
                <div role="columnheader" key={c.key} className="px-3 py-2">
                  {c.header}
                </div>
              ))}
            </div>
          </div>
          <div ref={scrollRef} className="overflow-y-auto" style={{ maxHeight }} data-testid="virtual-scroll">
            <div role="rowgroup" className="relative" style={{ height: virtualizer.getTotalSize() }}>
              {items.map((vi) => {
                const row = rows[vi.index];
                const key = rowKey(row);
                return (
                  <div
                    role="row"
                    key={key}
                    aria-rowindex={vi.index + 2}
                    aria-selected={selectedKey === key || undefined}
                    aria-label={rowLabel(row)}
                    data-row-index={vi.index}
                    tabIndex={vi.index === active ? 0 : -1}
                    onFocus={() => setActive(vi.index)}
                    onClick={() => onOpen?.(row)}
                    onKeyDown={(e) => onKeyDown(e, vi.index, row)}
                    className={cx(
                      'table-grid absolute left-0 top-0 grid w-full cursor-pointer items-center border-b border-subtle text-sm',
                      'hover:bg-raised-2 focus:bg-raised-2 focus:outline focus:outline-2 focus:-outline-offset-2 focus:outline-focus',
                      selectedKey === key && 'bg-raised-2',
                    )}
                    style={{ gridTemplateColumns: template, height: vi.size, transform: `translateY(${vi.start}px)` }}
                  >
                    {columns.map((c) => (
                      <div role="gridcell" key={c.key} className={cx('min-w-0 truncate px-3', c.className)}>
                        {c.render(row)}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between border-t border-subtle px-3 py-2 text-xs text-muted">
        <span aria-live="polite">
          {rows.length} {rows.length === 1 ? 'row' : 'rows'} loaded{hasMore ? ', more available' : ''}
        </span>
        {hasMore && onLoadMore && (
          <Button size="sm" onClick={onLoadMore} busy={loadingMore}>
            Load more
          </Button>
        )}
      </div>
    </div>
  );
}
