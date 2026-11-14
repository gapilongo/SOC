/**
 * The queue's dense table, on the windowed VirtualTable: one line per item
 * at 24, 28 or 44 px. The columns follow the room the table has: with the
 * preview beside it the list keeps its essential columns (deadline,
 * severity, what and why, the outcome mark), and on a narrow screen each
 * item becomes a stacked record so nothing scrolls sideways.
 */

import { useEffect, useRef, type KeyboardEvent, type MutableRefObject } from 'react';
import { Link } from 'react-router-dom';

import { escalationOwner, escalationSeverity, escalationTitle, formatEntities } from '../../api/fields';
import type { EscalationOut } from '../../api/types';
import { VirtualTable, type Column, type RowState, type VirtualTableApi } from '../../components/VirtualTable';
import { cx } from '../../components/ui';
import { escalationHref } from '../../lib/links';
import { DueIn, OutcomeMark, SeverityBars } from './marks';
import { ROW_HEIGHT, STACKED_ROW_HEIGHT, dueIn, lookAlike, rowOutcome, rowWhy, type QueueDensity } from './model';

/** Below this width (px) the table shows stacked records. */
export const STACKED_BELOW = 640;
/** From this width the entity column and the outcome in words are shown. */
const ROOMY_FROM = 900;
/** From this width the owner column is shown. */
const OWNER_FROM = 1000;

export interface QueueSelection {
  /** Viewers cannot act in bulk: no checkboxes. */
  enabled: boolean;
  isSelected: (id: string) => boolean;
  toggle: (row: EscalationOut) => void;
  /** Select the rows shown (up to the bulk maximum), or clear them. */
  setAll: (rows: readonly EscalationOut[], on: boolean) => void;
}

const HEADER = 'border-b border-strong bg-canvas font-mono text-2xs font-medium uppercase tracking-[0.05em] text-muted';

function rowClass(_row: EscalationOut, { active, selected }: RowState): string {
  return cx(
    'focus-visible:-outline-offset-2',
    selected ? 'bg-selected' : 'hover:bg-raised-2',
    // The cursor: a bar on the left, whether or not the row has keyboard focus.
    active && 'shadow-[inset_2px_0_0_rgb(var(--c-accent))]',
  );
}

function LookAlikeCount({ e }: { e: EscalationOut }) {
  const group = lookAlike(e);
  if (!group) return null;
  return (
    <span title={`${group.size} look-alike alerts`} className="ml-1.5 inline-block rounded-sm bg-fg px-[5px] align-[1px] font-mono text-2xs font-semibold text-canvas">
      ×{group.size}
      <span className="sr-only"> look-alikes</span>
    </span>
  );
}

function TitleLink({ e }: { e: EscalationOut }) {
  // Not a tab stop: the row is, and Enter opens it. The link serves the mouse (and "open in a new tab").
  return (
    <Link to={escalationHref(e)} tabIndex={-1} className="font-medium text-fg hover:underline">
      {escalationTitle(e)}
    </Link>
  );
}

function SelectAll({ rows, selection }: { rows: readonly EscalationOut[]; selection: QueueSelection }) {
  const box = useRef<HTMLInputElement>(null);
  const picked = rows.filter((e) => selection.isSelected(e.id)).length;
  const all = rows.length > 0 && picked === rows.length;
  useEffect(() => {
    if (box.current) box.current.indeterminate = picked > 0 && !all;
  }, [picked, all]);
  return (
    <input
      ref={box}
      type="checkbox"
      // A block, so the box does not make the header row taller than its text.
      className="block h-4 w-4 accent-accent"
      aria-label="Select all rows"
      checked={all}
      disabled={rows.length === 0}
      onChange={(ev) => selection.setAll(rows, ev.target.checked)}
    />
  );
}

function selectColumn(rows: readonly EscalationOut[], selection: QueueSelection): Column<EscalationOut> {
  return {
    key: 'select',
    header: <SelectAll rows={rows} selection={selection} />,
    width: '34px',
    className: '!pr-0',
    render: (e) => (
      <input
        type="checkbox"
        tabIndex={-1}
        className="h-4 w-4 align-middle accent-accent"
        aria-label={`Select ${escalationTitle(e)}`}
        checked={selection.isSelected(e.id)}
        onChange={() => selection.toggle(e)}
      />
    ),
  };
}

export function QueueTable({
  rows,
  now,
  density,
  width,
  userId,
  selection,
  onOpen,
  onActiveChange,
  onRowKeyDown,
  apiRef,
  maxHeight,
  autoLoad,
  hasMore,
  loadingMore,
  onLoadMore,
}: {
  rows: EscalationOut[];
  now: number;
  density: QueueDensity;
  /** The room the table has (px): it decides the columns. */
  width: number;
  userId: string | null;
  selection: QueueSelection;
  onOpen: (row: EscalationOut) => void;
  onActiveChange: (index: number) => void;
  onRowKeyDown: (e: KeyboardEvent<HTMLDivElement>, row: EscalationOut, index: number, api: VirtualTableApi) => boolean;
  apiRef: MutableRefObject<VirtualTableApi | null>;
  maxHeight: string;
  /** Load the next page when the end of the list comes into view. */
  autoLoad: boolean;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
}) {
  const stacked = width < STACKED_BELOW;
  const roomy = width >= ROOMY_FROM;
  const text = density === 'dense' ? 'text-[12.5px] leading-[18px]' : 'text-ctl';
  const select = selection.enabled ? [selectColumn(rows, selection)] : [];

  const columns: Column<EscalationOut>[] = stacked
    ? [
        ...select,
        {
          key: 'item',
          header: 'What needs you, and why',
          width: 'minmax(0, 1fr)',
          className: 'text-ctl',
          render: (e) => (
            <span className="flex flex-col gap-px">
              <span className="line-clamp-2 whitespace-normal">
                <TitleLink e={e} />
                <LookAlikeCount e={e} />
              </span>
              <span className="truncate text-muted">{rowWhy(e)}</span>
              <span className="flex items-center justify-between gap-2 text-[12.5px]">
                <SeverityBars value={escalationSeverity(e)} />
                <DueIn due={dueIn(e.sla_deadline, now)} />
              </span>
            </span>
          ),
        },
      ]
    : [
        ...select,
        {
          key: 'due',
          header: (
            <>
              Due in <span aria-hidden="true">↑</span>
              <span className="sr-only">, soonest first</span>
            </>
          ),
          width: '104px',
          className: 'text-[12.5px]',
          render: (e) => <DueIn due={dueIn(e.sla_deadline, now)} />,
        },
        { key: 'severity', header: 'Severity', width: '94px', className: 'text-[12.5px]', render: (e) => <SeverityBars value={escalationSeverity(e)} /> },
        {
          key: 'item',
          header: 'What needs you, and why',
          width: 'minmax(0, 1fr)',
          className: text,
          render: (e) =>
            density === 'relaxed' ? (
              <span className="flex flex-col">
                <span className="truncate">
                  <TitleLink e={e} />
                  <LookAlikeCount e={e} />
                </span>
                <span className="truncate text-muted">{rowWhy(e)}</span>
              </span>
            ) : (
              <>
                <TitleLink e={e} />
                <LookAlikeCount e={e} />
                <span className="ml-2 text-muted">{rowWhy(e)}</span>
              </>
            ),
        },
        ...(roomy
          ? [
              {
                key: 'entity',
                header: 'Entity',
                width: '150px',
                className: 'font-mono text-xs text-body',
                render: (e: EscalationOut) => {
                  const entities = formatEntities(e.entities_preview, 1);
                  return entities ? <span title={formatEntities(e.entities_preview, 6)}>{entities}</span> : <span className="text-muted">-</span>;
                },
              },
            ]
          : []),
        {
          key: 'outcome',
          header: roomy ? 'Outcome so far' : <span className="sr-only">Outcome so far</span>,
          width: roomy ? '176px' : '34px',
          className: cx('text-[12.5px]', !roomy && '!px-0 text-center'),
          render: (e) => <OutcomeMark outcome={rowOutcome(e)} text={roomy ? 'short' : 'none'} />,
        },
        ...(width >= OWNER_FROM
          ? [
              {
                key: 'owner',
                header: 'Owner',
                width: '128px',
                className: text,
                render: (e: EscalationOut) => {
                  const owner = escalationOwner(e, userId);
                  return (
                    <span title={owner.label} className={owner.kind === 'none' ? 'text-muted' : owner.kind === 'you' ? 'font-medium text-fg' : 'text-body'}>
                      {owner.label}
                    </span>
                  );
                },
              },
            ]
          : []),
      ];

  return (
    <VirtualTable
      // Records and table rows differ in height and in how the list scrolls: start the window afresh between them.
      key={stacked ? 'records' : 'table'}
      label="Work queue. J and K move, Enter opens, Space previews, X selects."
      columns={columns}
      rows={rows}
      rowKey={(e) => e.id}
      rowLabel={(e) => {
        const owner = escalationOwner(e, userId).label;
        return [escalationTitle(e), escalationSeverity(e), dueIn(e.sla_deadline, now).label, owner].filter(Boolean).join(', ');
      }}
      onOpen={onOpen}
      openOnClick={false}
      isRowSelected={selection.enabled ? (e) => selection.isSelected(e.id) : undefined}
      onActiveChange={onActiveChange}
      onRowKeyDown={onRowKeyDown}
      apiRef={apiRef}
      rowClassName={rowClass}
      headerClassName={HEADER}
      plain
      rowHeight={stacked ? STACKED_ROW_HEIGHT : ROW_HEIGHT[density]}
      // Stacked records flow with the page (no list inside the page to scroll on a phone), so more rows load on request.
      maxHeight={stacked ? 'none' : maxHeight}
      minWidth="0px"
      autoLoad={autoLoad && !stacked}
      hasMore={hasMore}
      loadingMore={loadingMore}
      onLoadMore={onLoadMore}
    />
  );
}
