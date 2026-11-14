/**
 * The work queue (console v2, docs/design/console-v2): one dense,
 * keyboard-first list of what needs a person, soonest deadline first.
 *
 * It reads today's escalation list (the request and the query keys of the
 * Escalations page, so live events and polling refresh both), for the
 * acting tenant. Views are tabs with counts, three row densities and the
 * saved views are kept per user in the browser, and a preview beside the
 * list shows the highlighted row. Keys: J and K (or the arrows) move, Enter
 * opens, Space shows or hides the preview, X selects, C claims.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import { escalationTitle, readQueueFigures, toBulkItems } from '../../api/fields';
import { useBulkClaim, useDashboardSummary, useEscalationList, useLivePollInterval, useTenantLabel } from '../../api/hooks';
import { BULK_MAX_ITEMS, type EscalationOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { ListNotice } from '../../components/ListNotice';
import type { VirtualTableApi } from '../../components/VirtualTable';
import { ErrorMessage, FilterChip, SEVERITIES, cx } from '../../components/ui';
import { humanize } from '../../lib/format';
import { escalationHref } from '../../lib/links';
import { readUserPref, writeUserPref } from '../../lib/prefs';
import { useNow } from '../../lib/useNow';
import { BulkResultPanel, type BulkResult } from '../escalations/BulkActions';
import { QUEUE_PAGE_SIZE } from '../escalations/QueueTable';
import { BatchBar } from './BatchBar';
import { Chip, DensityControl, Keys, QButton, SkeletonRows } from './controls';
import { useElementWidth, useMedia, useQueueLayout } from './hooks';
import {
  BASE_FILTERS,
  OUTCOMES,
  OUTCOME_TEXT,
  SAVED_VIEWS_MAX,
  VIEW_ASSIGNED,
  VIEW_IDS,
  VIEW_LABELS,
  activeView,
  assignedFilters,
  inView,
  leadSentence,
  matchesFilters,
  parseQueueDensity,
  parseSavedViews,
  viewCounts,
  viewSearch,
  type QueueDensity,
  type RowFilters,
  type SavedView,
} from './model';
import { PreviewPane, useClaim } from './PreviewPane';
import { QueueTable, STACKED_BELOW, type QueueSelection } from './QueueTable';
import { ViewTabs, tabDomId, type ViewTab } from './ViewTabs';

/** The preview is shown from this window width (px); below it the list has the whole page. */
const PREVIEW_FROM = 1180;
/** What the page keeps under the queue (px): the shell's bottom padding, and a pixel for rounding. */
const PAGE_BOTTOM = 25;

const SEVERITY_OPTIONS = SEVERITIES.map((s) => ({ value: s, label: humanize(s) }));
const OUTCOME_OPTIONS = OUTCOMES.map((o) => ({ value: o, label: OUTCOME_TEXT[o].short }));

function isTyping(el: HTMLElement): boolean {
  if (el.isContentEditable) return true;
  if (el instanceof HTMLInputElement) return el.type !== 'checkbox' && el.type !== 'radio';
  return el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement;
}

/** A single-letter key in lower case; named keys ("Enter", " ") as they are. */
const keyOf = (key: string) => (key.length === 1 ? key.toLowerCase() : key);

export default function QueuePage() {
  const { principal } = useAuth();
  const userId = principal?.userId ?? null;
  const canAct = can.claim(principal);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tenant = useTenantLabel();
  const interval = useLivePollInterval();
  const now = useNow(1_000);
  const ids = useId();
  const panelId = `${ids}-panel`;

  const [density, setDensityState] = useState<QueueDensity>(() => parseQueueDensity(readUserPref('queue-density', userId)));
  const [saved, setSavedState] = useState<SavedView[]>(() => parseSavedViews(readUserPref('queue-views', userId)));
  const [previewOpen, setPreviewOpen] = useState(true);
  const [active, setActive] = useState(0);
  const [picked, setPickedState] = useState<ReadonlySet<string>>(new Set());
  const [capped, setCapped] = useState(false);
  // The selection as of the last key: X then C may arrive before the page has rendered the X.
  const pickedNow = useRef<ReadonlySet<string>>(picked);
  const setPicked = useCallback((next: ReadonlySet<string>) => {
    pickedNow.current = next;
    setPickedState(next);
  }, []);
  const [result, setResult] = useState<BulkResult | null>(null);

  const setDensity = useCallback(
    (next: QueueDensity) => {
      setDensityState(next);
      writeUserPref('queue-density', userId, next);
    },
    [userId],
  );
  const setSaved = (next: SavedView[]) => {
    setSavedState(next);
    writeUserPref('queue-views', userId, JSON.stringify(next));
  };

  // Rows: the whole waiting list (also what the tabs count), or the API's own narrowing for Mine and Unassigned.
  const view = useMemo(() => activeView(params, saved), [params, saved]);
  const assigned = VIEW_ASSIGNED[view.base];
  const base = useEscalationList(BASE_FILTERS, { refetchInterval: interval, limit: QUEUE_PAGE_SIZE });
  const narrowed = useEscalationList(assigned ? assignedFilters(assigned) : BASE_FILTERS, { enabled: Boolean(assigned), refetchInterval: interval, limit: QUEUE_PAGE_SIZE });
  const list = assigned ? narrowed : base;
  const complete = base.isSuccess && !base.hasNextPage;
  // The dashboard's figures are needed only while the tabs cannot count the whole queue themselves.
  const summary = useDashboardSummary(24, { enabled: base.isSuccess && !complete, refetchInterval: interval });
  const counts = viewCounts(base.items, complete, readQueueFigures(summary.data), { userId, now });

  const filtered = !assigned && view.base !== 'all';
  const chips = view.filters.severity.length > 0 || view.filters.outcome.length > 0;
  const rows = useMemo(
    () => list.items.filter((e) => (!filtered || inView(view.base, e, { userId, now })) && matchesFilters(e, view.filters)),
    [list.items, filtered, view, userId, now],
  );
  const current = rows[Math.min(active, rows.length - 1)] ?? null;
  const selected = useMemo(() => rows.filter((e) => picked.has(e.id)), [rows, picked]);

  // A selection belongs to the view it was made in.
  const viewKey = `${view.tab}|${view.filters.severity.join()}|${view.filters.outcome.join()}`;
  useEffect(() => {
    setPicked(new Set());
    setCapped(false);
  }, [viewKey, setPicked]);

  // The saved view's density applies when the view is opened.
  const savedDensity = view.saved?.density;
  const savedId = view.saved?.id;
  useEffect(() => {
    if (savedDensity) setDensity(savedDensity);
  }, [savedId, savedDensity, setDensity]);

  const selection: QueueSelection = {
    enabled: canAct,
    isSelected: (id) => picked.has(id),
    toggle: (row) => {
      const next = new Set(pickedNow.current);
      if (next.has(row.id)) next.delete(row.id);
      else if (next.size < BULK_MAX_ITEMS) next.add(row.id);
      setCapped(!next.has(row.id) && next.size >= BULK_MAX_ITEMS);
      setPicked(next);
    },
    setAll: (all, on) => {
      const next = new Set(pickedNow.current);
      for (const e of all) {
        if (!on) next.delete(e.id);
        else if (next.size < BULK_MAX_ITEMS) next.add(e.id);
      }
      setCapped(on && all.some((e) => !next.has(e.id)));
      setPicked(next);
    },
  };
  const clearSelection = () => {
    setPicked(new Set());
    setCapped(false);
  };

  const { claim, busy: claiming } = useClaim();
  const bulkClaim = useBulkClaim();
  const selectedNow = () => rows.filter((e) => pickedNow.current.has(e.id));
  const claimSelected = () => {
    const items = selectedNow();
    bulkClaim.mutate(toBulkItems(items), {
      onSuccess: (out) => {
        setResult({ kind: 'claim', out, titles: Object.fromEntries(items.map((e) => [e.id, escalationTitle(e)])) });
        clearSelection();
      },
    });
  };

  const open = (row: EscalationOut) => navigate(escalationHref(row));

  // Keys. The same letters work on a focused row and anywhere on the page outside a field, a menu or a dialog.
  // They act on the cursor row as the table has it now: focus (and this page's render) follow the cursor a
  // frame later, and a key that arrives within that frame must not act on the row left behind.
  const table = useRef<VirtualTableApi | null>(null);
  const cursorRow = (): EscalationOut | null => rows[table.current?.activeIndex() ?? 0] ?? null;
  const onKey = (key: string): boolean => {
    const index = table.current?.activeIndex() ?? 0;
    const row = cursorRow();
    switch (key) {
      case 'j':
      case 'ArrowDown':
        table.current?.focusRow(index + 1);
        return true;
      case 'k':
      case 'ArrowUp':
        table.current?.focusRow(index - 1);
        return true;
      case 'x':
        if (row && canAct) selection.toggle(row);
        return true;
      case 'c':
        if (canAct && selectedNow().length) claimSelected();
        else if (canAct && row) void claim(row);
        return true;
      case ' ':
        setPreviewOpen((on) => !on);
        return true;
      case 'Enter':
        if (row) open(row);
        return true;
      default:
        return false;
    }
  };
  const onRowKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>): boolean => {
    if (e.ctrlKey || e.metaKey || e.altKey) return false;
    // Space and Enter on the row's own checkbox or link do what they do there.
    if (e.target !== e.currentTarget && (e.key === ' ' || e.key === 'Enter')) return true;
    if (!onKey(keyOf(e.key))) return false;
    e.preventDefault();
    return true;
  };
  const pageKeys = useRef<(e: KeyboardEvent) => void>(() => undefined);
  pageKeys.current = (e) => {
    // A focused row has already handled its keys (the table's own and the letters above).
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
    const target = e.target instanceof HTMLElement ? e.target : null;
    if (target && (isTyping(target) || target.closest('[role="dialog"], [role="menu"], [role="listbox"]'))) return;
    const key = keyOf(e.key);
    // Keys a control uses itself stay with it (Enter and Space on a button, the arrows on tabs and radios).
    if (key.length !== 1 || key === ' ') {
      if (target?.closest('a, button, input, summary, [role="row"]')) return;
    }
    if (onKey(key)) e.preventDefault();
  };
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => pageKeys.current(e);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Layout: the list fills the window under what precedes it; the preview needs a wide window.
  const split = useRef<HTMLDivElement>(null);
  const tableBox = useRef<HTMLDivElement>(null);
  const footer = useRef<HTMLDivElement>(null);
  const layout = useQueueLayout(split, footer);
  const width = useElementWidth(tableBox, 1200);
  const wide = useMedia(`(min-width: ${PREVIEW_FROM}px)`, true);
  const previewShown = previewOpen && wide;
  const stacked = width < STACKED_BELOW;
  const listHeight = `max(260px, calc(100vh - ${layout.listTop + layout.footer + PAGE_BOTTOM}px))`;

  const select = (id: string) => setParams(viewSearch(id));
  const setFilters = (next: RowFilters) => setParams(viewSearch(view.base, next), { replace: true });
  const tabs: ViewTab[] = [
    // Look-alikes need grouping the API does not send yet: the tab appears with the first grouped row.
    ...VIEW_IDS.filter((id) => id !== 'alike' || counts.alike.n > 0 || view.base === 'alike').map((id) => ({ id, label: VIEW_LABELS[id], count: counts[id], saved: false })),
    ...saved.map((s) => ({ id: s.id, label: s.name, count: null, saved: true })),
  ];
  const saveView = (name: string) => {
    const s: SavedView = { id: `s-${Date.now().toString(36)}`, name, base: view.base, severity: [...view.filters.severity], outcome: [...view.filters.outcome], density };
    setSaved([...saved, s]);
    setParams(viewSearch(s.id));
  };
  const removeView = (id: string) => {
    setSaved(saved.filter((s) => s.id !== id));
    setParams(viewSearch('all'));
  };

  const more = Boolean(list.hasNextPage);
  return (
    <section aria-labelledby={`${ids}-title`} className="flex flex-col">
      <div className="mb-1.5 flex flex-wrap items-end gap-x-4 gap-y-2">
        <h1 id={`${ids}-title`} className="text-xl font-semibold leading-tight tracking-[-0.01em] text-fg">
          Queue
        </h1>
        <p className="min-w-0 flex-[1_1_320px] text-[13.5px] text-secondary">
          {base.isSuccess ? leadSentence(base.items, counts.all, now) : base.isError ? 'The queue could not be loaded.' : 'Loading what needs a person.'}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {!stacked && <DensityControl value={density} onChange={setDensity} />}
          {wide && (
            <QButton aria-pressed={previewOpen} onClick={() => setPreviewOpen(!previewOpen)}>
              Preview <kbd>Space</kbd>
            </QButton>
          )}
        </div>
      </div>

      <ViewTabs idBase={ids} panelId={panelId} tabs={tabs} value={view.tab} onChange={select} onSave={saveView} onRemove={removeView} canSave={saved.length < SAVED_VIEWS_MAX} />

      {selected.length > 0 ? (
        <BatchBar selected={selected} capped={capped} claiming={bulkClaim.isPending} claimError={bulkClaim.error} onClaim={claimSelected} onClear={clearSelection} onResult={setResult} />
      ) : (
        <section aria-label="Filters" className="flex min-h-[38px] flex-wrap items-center gap-2 py-0.5">
          <Chip label="Sort" value="Deadline, soonest first" />
          <FilterChip label="Severity" options={SEVERITY_OPTIONS} value={view.filters.severity} anyLabel="any" onChange={(v) => setFilters({ ...view.filters, severity: v })} />
          <FilterChip label="Outcome" options={OUTCOME_OPTIONS} value={view.filters.outcome} anyLabel="any" onChange={(v) => setFilters({ ...view.filters, outcome: v })} />
          <Chip label="Scope" value={tenant} />
          <span className="flex-1" />
          {list.isSuccess && (
            <span role="status" className="text-xs text-muted">
              {rows.length} {rows.length === 1 ? 'row' : 'rows'}
              {more && (filtered || chips) && `, of the first ${list.items.length} by deadline`}
            </span>
          )}
        </section>
      )}
      {result && <BulkResultPanel result={result} onDismiss={() => setResult(null)} />}
      <ListNotice list={list} noun="items" />

      <div
        ref={split}
        role="tabpanel"
        id={panelId}
        aria-labelledby={tabDomId(ids, view.tab)}
        className={cx('grid items-start border-t border-strong', previewShown ? 'grid-cols-[minmax(0,1fr)_372px]' : 'grid-cols-[minmax(0,1fr)]')}
      >
        <div ref={tableBox} className="min-w-0">
          {list.isPending && <SkeletonRows />}
          {list.isError && (
            <div className="py-4">
              <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />
            </div>
          )}
          {list.isSuccess && rows.length === 0 && (
            <p className="max-w-2xl py-6 text-ctl text-muted">
              Nothing in this view needs a person in {tenant}.{' '}
              {more ? (
                `Only the first ${list.items.length} items by deadline are loaded; load more to look further.`
              ) : (
                <>
                  The AI closed or is still investigating the rest; see the{' '}
                  <Link to="/" className="text-link hover:text-link-hover hover:underline">
                    Overview
                  </Link>{' '}
                  for how those closes are checked.
                </>
              )}
            </p>
          )}
          {list.isSuccess && rows.length > 0 && (
            <QueueTable
              key={viewKey}
              rows={rows}
              now={now}
              density={density}
              width={width}
              userId={userId}
              selection={selection}
              onOpen={open}
              onActiveChange={setActive}
              onRowKeyDown={onRowKeyDown}
              apiRef={table}
              maxHeight={listHeight}
              // A filtered view loads further pages on request only: loading them pauses the live refresh.
              autoLoad={!filtered && !chips}
              hasMore={more}
              loadingMore={list.isFetchingNextPage}
              onLoadMore={() => void list.fetchNextPage()}
            />
          )}
          <div ref={footer} className="flex min-h-7 flex-wrap items-center justify-between gap-x-4 gap-y-1.5 pt-1.5">
            {!stacked && <Keys canAct={canAct} />}
            {list.isSuccess && more && (
              <span className="flex items-center gap-3 text-xs text-muted">
                The first {list.items.length} items by deadline are loaded.
                <QButton busy={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
                  Load more
                </QButton>
              </span>
            )}
          </div>
        </div>
        {previewShown && <PreviewPane row={current} now={now} maxHeight={`max(260px, calc(100vh - ${layout.top + PAGE_BOTTOM}px))`} onClaim={(row) => void claim(row)} claiming={claiming} />}
      </div>
    </section>
  );
}
