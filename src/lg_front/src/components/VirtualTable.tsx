import { useVirtualizer } from '@tanstack/react-virtual';
import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type MutableRefObject, type ReactNode } from 'react';

import { ROW_HEIGHT, useDensity } from '../theme/density';
import { Button, cx } from './ui';

export interface Column<T> {
  key: string;
  /** The column's name, or a control standing in for it (a select-all checkbox). */
  header: ReactNode;
  /** CSS grid track, e.g. `minmax(12rem, 3fr)` or `8rem`. */
  width: string;
  render: (row: T) => ReactNode;
  className?: string;
}

/** What a page may ask of the table from outside its rows (a page-wide shortcut). */
export interface VirtualTableApi {
  /** Move the cursor to this row (clamped), scroll it into view and focus it. */
  focusRow: (index: number) => void;
}

/** How a row stands, for `rowClassName`. */
export interface RowState {
  /** The cursor is on this row. */
  active: boolean;
  selected: boolean;
}

const ROW_STATE = 'hover:bg-raised-2 focus:bg-raised-2 focus:outline focus:outline-2 focus:-outline-offset-2 focus:outline-focus';

/**
 * A windowed table for long keyset-paginated lists. Only visible rows are
 * rendered. Keyboard: Up/Down/Home/End/PageUp/PageDown move between rows,
 * Enter or Space opens the focused row. More pages load when the end comes
 * into view, and a "Load more" button offers the same explicitly.
 *
 * A page that needs more (the work queue) adds its own keys with
 * `onRowKeyDown`, follows the cursor with `onActiveChange`, moves it with
 * `apiRef`, marks several rows selected with `isRowSelected`, styles row
 * states with `rowClassName`, and draws its own frame with `plain`.
 */
export function VirtualTable<T>({
  label,
  columns,
  rows,
  rowKey,
  rowLabel,
  onOpen,
  selectedKey,
  isRowSelected,
  onActiveChange,
  onRowKeyDown,
  openOnClick = true,
  rowClassName,
  headerClassName,
  apiRef,
  plain = false,
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
  /** Rows marked selected (several may be); with it every row says whether it is selected. */
  isRowSelected?: (row: T) => boolean;
  /** The cursor moved to this row (by key, click or focus). */
  onActiveChange?: (index: number) => void;
  /** Runs before the table's own keys; return true when the key was handled (the table then does nothing). */
  onRowKeyDown?: (e: KeyboardEvent<HTMLDivElement>, row: T, index: number, api: VirtualTableApi) => boolean;
  /** A click opens the row (default); false: it only moves the cursor there. */
  openOnClick?: boolean;
  /** Classes for a row's states, replacing the default hover, focus and selected look. */
  rowClassName?: (row: T, state: RowState) => string;
  /** Classes of the header row, replacing the default look. */
  headerClassName?: string;
  /** Filled with the table's API while it is mounted. */
  apiRef?: MutableRefObject<VirtualTableApi | null>;
  /** No card frame and no footer line: the page draws its own. */
  plain?: boolean;
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

  useEffect(() => {
    onActiveChange?.(active);
    // A cursor move is reported, not a new callback identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

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

  useEffect(() => {
    if (!apiRef) return;
    apiRef.current = { focusRow };
    return () => {
      apiRef.current = null;
    };
  }, [apiRef, focusRow]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>, index: number, row: T) => {
    if (onRowKeyDown?.(e, row, index, { focusRow })) return;
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
    <div className={plain ? undefined : 'overflow-hidden rounded-card border border-subtle bg-raised'}>
      <div className="relative overflow-x-auto">
        <div role="grid" aria-readonly="true" aria-label={label} aria-rowcount={rows.length + 1} style={{ minWidth }}>
          <div role="rowgroup">
            <div
              role="row"
              aria-rowindex={1}
              className={cx('table-grid grid', headerClassName ?? 'border-b border-subtle bg-raised text-xs font-semibold uppercase tracking-wide text-muted')}
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
                const selected = isRowSelected ? isRowSelected(row) : selectedKey === key;
                return (
                  <div
                    role="row"
                    key={key}
                    aria-rowindex={vi.index + 2}
                    aria-selected={isRowSelected ? selected : selected || undefined}
                    aria-label={rowLabel(row)}
                    data-row-index={vi.index}
                    tabIndex={vi.index === active ? 0 : -1}
                    onFocus={() => setActive(vi.index)}
                    onClick={openOnClick ? () => onOpen?.(row) : undefined}
                    onKeyDown={(e) => onKeyDown(e, vi.index, row)}
                    className={cx(
                      'table-grid absolute left-0 top-0 grid w-full items-center border-b border-subtle text-sm',
                      openOnClick && 'cursor-pointer',
                      rowClassName ? rowClassName(row, { active: vi.index === active, selected }) : cx(ROW_STATE, selected && 'bg-raised-2'),
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
      {!plain && (
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
      )}
    </div>
  );
}
