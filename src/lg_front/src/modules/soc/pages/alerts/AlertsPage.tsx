import { useQuery } from '@tanstack/react-query';
import { Download, Search } from 'lucide-react';
import { useCallback, useMemo, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';

import { endpoints, type AlertFilters } from '../../api/endpoints';
import { formatEntities } from '../../api/fields';
import { useAlertCounts, useLivePollInterval } from '../../api/hooks';
import { qk } from '../../api/queryKeys';
import { ALERT_STATUSES, DISPOSITIONS, type AlertOut, type LiveEvent } from '../../api/types';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { statusTone } from '../../components/Badge';
import { ListNotice } from '../../../../components/ListNotice';
import {
  Button,
  CountChip,
  EmptyState,
  ErrorMessage,
  FIELD_CLASS,
  FilterChip,
  LoadingState,
  PageHeader,
  SEVERITIES,
  SeverityTag,
  StatePill,
  TabLinks,
  cx,
  type FilterOption,
} from '../../../../components/ui';
import { VirtualTable, type Column } from '../../../../components/VirtualTable';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../../../../lib/csv';
import { formatDateTime, humanize, isoToLocalInput, localInputToIso } from '../../../../lib/format';
import { useKeysetList } from '../../../../lib/pagination';
import { useDensity, type Density } from '../../../../theme/density';
import { AlertSidePanel } from './AlertPanel';
import { aiVerdict, statusShort, statusWords } from './alertSummary';
import { NewAlertsPill, useListLoadedAt, useNewAlertCount } from './NewAlertsPill';
import {
  ALERT_VIEWS,
  FILTER_PARAMS,
  closedWindow,
  isTodayWindow,
  viewCount,
  viewFilters,
  viewFromParams,
  viewHref,
  viewLabel,
  type AlertView,
} from './views';

export function filtersFromParams(params: URLSearchParams): AlertFilters {
  const multi = (k: string) => params.getAll(k).filter(Boolean);
  const f: AlertFilters = {};
  if (multi('status').length) f.status = multi('status');
  if (multi('severity').length) f.severity = multi('severity');
  if (multi('disposition').length) f.disposition = multi('disposition');
  // The API filters on a single source id; a URL with several keeps the first.
  const source = params.get('source_id')?.trim();
  if (source) f.source_id = source;
  if (params.get('q')) f.q = params.get('q') as string;
  if (params.get('from')) f.from = params.get('from') as string;
  if (params.get('to')) f.to = params.get('to') as string;
  if (params.get('closed_from')) f.closed_from = params.get('closed_from') as string;
  if (params.get('closed_to')) f.closed_to = params.get('closed_to') as string;
  return f;
}

/** The entities line under (compact: beside) the title, e.g. "j.moreau@acme.example · 185.220.101.4 · +3 more". */
function AlertCell({ alert, density }: { alert: AlertOut; density: Density }) {
  const entities = formatEntities(alert.entities_preview);
  if (density === 'comfortable') {
    return (
      <div className="min-w-0 leading-tight">
        <div className="truncate font-medium text-fg" title={alert.title}>
          {alert.title}
        </div>
        {entities && <div className="mt-0.5 truncate text-xs text-muted">{entities}</div>}
      </div>
    );
  }
  return (
    <span className="block truncate" title={entities ? `${alert.title}: ${entities}` : alert.title}>
      <span className="font-medium text-fg">{alert.title}</span>
      {entities && <span className="ml-2 text-xs text-muted">{entities}</span>}
    </span>
  );
}

function VerdictCell({ alert }: { alert: AlertOut }) {
  const { verdict, confidence } = aiVerdict(alert);
  if (!verdict && confidence === null) return <span className="text-muted">-</span>;
  return (
    <span className="whitespace-nowrap">
      {verdict && <span className="text-body">{humanize(verdict)}</span>}
      {confidence !== null && <span className={cx('font-mono text-xs text-secondary', verdict && 'ml-1.5')}>{confidence}%</span>}
    </span>
  );
}

/** A short age for the table: "now", "12 min ago", "3 h ago", "5 d ago". */
export function formatAge(value: string, now: number = Date.now()): string {
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return '-';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return 'now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function alertColumns(density: Density, besidePanel = false): Column<AlertOut>[] {
  const columns: Column<AlertOut>[] = [
    { key: 'severity', header: 'Severity', width: '6rem', render: (a) => <SeverityTag value={a.severity} /> },
    { key: 'alert', header: 'Alert', width: 'minmax(10rem, 1fr)', render: (a) => <AlertCell alert={a} density={density} /> },
    { key: 'source', header: 'Source', width: '7rem', className: 'text-secondary', render: (a) => <span title={a.source_name ?? a.source_id}>{a.source_name ?? a.source_id}</span> },
    { key: 'verdict', header: 'AI verdict', width: '8.5rem', render: (a) => <VerdictCell alert={a} /> },
    {
      key: 'status',
      header: 'Status',
      width: '10.25rem',
      render: (a) => (
        <StatePill tone={statusTone(a.status)} title={statusWords(a.status)}>
          {statusShort(a.status)}
        </StatePill>
      ),
    },
    {
      key: 'age',
      header: 'Age',
      width: '6.25rem',
      className: 'tabular-nums text-secondary',
      render: (a) => (
        <time dateTime={a.ingested_at} title={`Ingested ${formatDateTime(a.ingested_at)}`}>
          {formatAge(a.ingested_at)}
        </time>
      ),
    },
  ];
  return besidePanel ? columns.filter((c) => c.key !== 'source' && c.key !== 'age') : columns;
}

export const ALERT_CSV: CsvColumn<AlertOut>[] = [
  { header: 'id', value: (a) => a.id },
  { header: 'title', value: (a) => a.title },
  { header: 'severity', value: (a) => a.severity },
  { header: 'status', value: (a) => a.status },
  { header: 'disposition', value: (a) => a.disposition },
  { header: 'confidence', value: (a) => a.confidence },
  { header: 'threat_score', value: (a) => a.threat_score },
  { header: 'priority', value: (a) => a.priority },
  { header: 'category', value: (a) => a.category },
  { header: 'source_id', value: (a) => a.source_id },
  { header: 'source_name', value: (a) => a.source_name },
  { header: 'source_alert_id', value: (a) => a.source_alert_id },
  { header: 'occurred_at', value: (a) => a.occurred_at },
  { header: 'ingested_at', value: (a) => a.ingested_at },
  { header: 'closed_at', value: (a) => a.closed_at },
];

const SEVERITY_OPTIONS: FilterOption[] = SEVERITIES.map((s) => ({ value: s, label: humanize(s) }));
const VERDICT_OPTIONS: FilterOption[] = DISPOSITIONS.map((d) => ({ value: d, label: humanize(d) }));
const STATUS_OPTIONS: FilterOption[] = ALERT_STATUSES.map((s) => ({ value: s, label: statusWords(s) }));

/** The view tabs, each with its count (one cached `GET /alerts/counts` for all of them). */
function ViewTabs({ view, params, byStatus }: { view: AlertView; params: URLSearchParams; byStatus: Record<string, number> | undefined }) {
  const today = isTodayWindow(params);
  const tabs = ALERT_VIEWS.map((v) => {
    const n = viewCount(v, byStatus);
    return {
      id: v,
      to: viewHref(v, params),
      label: viewLabel(v, today),
      trailing: n !== null && <CountChip count={n} meaning={n === 1 ? 'alert' : 'alerts'} />,
    };
  });
  return <TabLinks label="Alert views" tabs={tabs} current={view} />;
}

function DateField({ label, value, onChange }: { label: string; value: string | undefined; onChange: (iso: string | undefined) => void }) {
  return (
    <label className="inline-flex items-center gap-1.5 text-ctl text-secondary">
      {label}
      <input
        type="datetime-local"
        value={isoToLocalInput(value)}
        onChange={(e) => onChange(localInputToIso(e.target.value))}
        className={cx(FIELD_CLASS, 'h-[34px] w-auto px-2 touch:min-h-11')}
      />
    </label>
  );
}

export default function AlertsPage() {
  const api = useApi();
  const { principal } = useAuth();
  const { density } = useDensity();
  const [params, setParams] = useSearchParams();
  const view = viewFromParams(params);
  const urlFilters = useMemo(() => filtersFromParams(params), [params]);
  const closed = useMemo(() => closedWindow(params), [params]);
  const filters = useMemo(() => viewFilters(view, urlFilters, closed), [view, urlFilters, closed]);
  const selected = params.get('alert');
  const [search, setSearch] = useState(urlFilters.q ?? '');
  const poll = useLivePollInterval();

  const update = useCallback(
    (mutate: (p: URLSearchParams) => void) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          // Pin the view, so adding a filter does not turn the default view into All.
          next.set('view', viewFromParams(prev));
          mutate(next);
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  const setMulti = (key: string, values: string[]) =>
    update((p) => {
      p.delete(key);
      for (const v of values) p.append(key, v);
    });
  const setSingle = (key: string, value: string | undefined) =>
    update((p) => {
      if (value) p.set(key, value);
      else p.delete(key);
    });
  const select = useCallback(
    (id: string | null) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (id) next.set('alert', id);
          else next.delete('alert');
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const counts = useAlertCounts(closed, { refetchInterval: poll });
  const list = useKeysetList({
    queryKey: qk.alerts.list(filters),
    fetchPage: (cursor, signal) => endpoints.alerts(api, filters, cursor, signal),
    itemKey: (a: AlertOut) => a.id,
  });

  const sources = useQuery({
    queryKey: qk.sources.all,
    queryFn: ({ signal }) => endpoints.sources(api, signal),
    enabled: can.admin(principal),
    staleTime: 5 * 60_000,
  });
  // Admins pick from every source; others from the sources of the rows loaded (the API is admin-only).
  const sourceOptions = useMemo(() => {
    const names = new Map<string, string>();
    for (const s of sources.data ?? []) names.set(s.id, s.name);
    for (const a of list.items) if (!names.has(a.source_id)) names.set(a.source_id, a.source_name ?? a.source_id);
    if (urlFilters.source_id && !names.has(urlFilters.source_id)) names.set(urlFilters.source_id, urlFilters.source_id);
    return [...names].map(([value, label]) => ({ value, label })).sort((x, y) => x.label.localeCompare(y.label));
  }, [sources.data, list.items, urlFilters.source_id]);

  const loadedAt = useListLoadedAt(list.dataUpdatedAt, list.pages);
  const severities = filters.severity;
  const matchesFilters = useCallback(
    (e: LiveEvent) => !severities?.length || severities.includes(String(e.data?.severity ?? '')),
    [severities],
  );
  const newCount = useNewAlertCount(loadedAt, matchesFilters);

  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    setSingle('q', search.trim() || undefined);
  };
  const hasFilters = FILTER_PARAMS.some((k) => k !== 'status' && params.getAll(k).some(Boolean)) || (view === 'all' && Boolean(urlFilters.status));
  const clearAll = () => {
    setSearch('');
    update((p) => {
      for (const k of FILTER_PARAMS) p.delete(k);
    });
  };

  // Back to the row the panel was opened from, so the keyboard user carries on down the list.
  const closePanel = () => {
    const row = document.querySelector<HTMLElement>('[role="grid"][aria-label="Alerts"] [role="row"][aria-selected="true"]');
    select(null);
    row?.focus();
  };

  const exportCsv = () => downloadCsv(csvFilename('alerts'), toCsv(ALERT_CSV, list.items));
  const { fetchNextPage } = list;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);
  // With the alert panel beside the list, the source and the age move to the panel's header: the list keeps the title readable.
  const columns = useMemo(() => alertColumns(density, Boolean(selected)), [density, selected]);

  return (
    <div className="xl:flex xl:items-start xl:gap-4">
      <div className="min-w-0 flex-1 space-y-3.5">
        <PageHeader
          title="Alerts"
          actions={
            <Button onClick={exportCsv} disabled={list.items.length === 0} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
              Export loaded rows (CSV)
            </Button>
          }
        />
        <ViewTabs view={view} params={params} byStatus={counts.data?.by_status} />

        <div role="group" aria-label="Filter alerts" className="flex flex-wrap items-center gap-2">
          <form role="search" aria-label="Search alert titles" onSubmit={submitSearch} className="min-w-[13rem] max-w-xs flex-1">
            <label className="relative block">
              <span className="sr-only">Search titles</span>
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-secondary" strokeWidth={1.75} aria-hidden="true" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search titles"
                aria-describedby="alert-search-hint"
                className={cx(FIELD_CLASS, 'h-[34px] pl-8 touch:min-h-11')}
              />
            </label>
            <span id="alert-search-hint" className="sr-only">
              Press Enter to search. Searches at most 93 days (default: the 30 days before To).
            </span>
          </form>
          <FilterChip label="Severity" options={SEVERITY_OPTIONS} value={urlFilters.severity ?? []} onChange={(v) => setMulti('severity', v)} />
          <FilterChip label="Verdict" options={VERDICT_OPTIONS} value={urlFilters.disposition ?? []} onChange={(v) => setMulti('disposition', v)} />
          <FilterChip
            label="Source"
            multiple={false}
            options={sourceOptions}
            value={urlFilters.source_id ? [urlFilters.source_id] : []}
            onChange={(v) => setSingle('source_id', v[0])}
          />
          {view === 'all' && (
            <FilterChip label="Status" options={STATUS_OPTIONS} value={urlFilters.status ?? []} onChange={(v) => setMulti('status', v)} />
          )}
          <DateField label="From" value={urlFilters.from} onChange={(v) => setSingle('from', v)} />
          <DateField label="To" value={urlFilters.to} onChange={(v) => setSingle('to', v)} />
          {hasFilters && (
            <Button variant="quiet" size="sm" onClick={clearAll}>
              Clear filters
            </Button>
          )}
          <span className="ml-auto">
            <NewAlertsPill count={newCount} busy={list.isFetching} onRefresh={() => void list.reloadFromTop()} />
          </span>
        </div>

        <ListNotice list={list} noun="alerts" />
        {list.isPending && <LoadingState label="Loading alerts" />}
        {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
        {list.isSuccess && list.items.length === 0 && (
          <EmptyState title={hasFilters ? 'No alerts match these filters' : `No alerts in ${viewLabel(view, isTodayWindow(params))}`}>
            {hasFilters
              ? 'Widen the time window or clear some filters.'
              : view === 'all'
                ? 'Alerts appear here once a source is connected or alerts are sent to the ingest API.'
                : 'Nothing is waiting here right now.'}
          </EmptyState>
        )}
        {list.items.length > 0 && (
          <VirtualTable
            label="Alerts"
            columns={columns}
            rows={list.items}
            rowKey={(a) => a.id}
            rowLabel={(a) => `${a.severity} alert: ${a.title}, status ${a.status.replace(/_/g, ' ')}`}
            selectedKey={selected}
            onOpen={(a) => select(a.id)}
            hasMore={Boolean(list.hasNextPage)}
            loadingMore={list.isFetchingNextPage}
            onLoadMore={loadMore}
            autoLoad={!list.isFetchNextPageError}
            minWidth={selected ? '30rem' : '46rem'}
            maxHeight="calc(100vh - 17rem)"
          />
        )}
        {list.isFetchNextPageError && <ErrorMessage error={list.error} onRetry={loadMore} compact />}
      </div>
      {selected && <AlertSidePanel key={selected} alertId={selected} onClose={closePanel} />}
    </div>
  );
}
