import { Download, Search, X } from 'lucide-react';
import { useCallback, useMemo, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';

import { endpoints, type AlertFilters } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { ALERT_STATUSES, DISPOSITIONS, SEVERITIES, type AlertOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { DispositionBadge, SeverityBadge, StatusBadge } from '../../components/Badge';
import { Button, EmptyState, ErrorMessage, LoadingState, PageHeader, TextField, ToggleGroup } from '../../components/ui';
import { VirtualTable, type Column } from '../../components/VirtualTable';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../../lib/csv';
import { formatDateTime, formatRelative, isoToLocalInput, localInputToIso } from '../../lib/format';
import { ListNotice } from '../../components/ListNotice';
import { useKeysetList } from '../../lib/pagination';
import { AlertDrawer } from './AlertDrawer';

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
  return f;
}

const COLUMNS: Column<AlertOut>[] = [
  { key: 'severity', header: 'Severity', width: '6.5rem', render: (a) => <SeverityBadge value={a.severity} /> },
  { key: 'title', header: 'Title', width: 'minmax(16rem, 4fr)', render: (a) => <span title={a.title} className="text-slate-100">{a.title}</span> },
  { key: 'status', header: 'Status', width: '9.5rem', render: (a) => <StatusBadge value={a.status} /> },
  { key: 'disposition', header: 'Disposition', width: '7.5rem', render: (a) => <DispositionBadge value={a.disposition} /> },
  { key: 'score', header: 'Threat', width: '4.5rem', className: 'tabular-nums text-slate-200', render: (a) => a.threat_score ?? '-' },
  { key: 'source', header: 'Source', width: 'minmax(7rem, 1fr)', className: 'text-slate-300', render: (a) => a.source_id },
  {
    key: 'ingested',
    header: 'Ingested',
    width: '9rem',
    className: 'text-slate-300',
    render: (a) => (
      <time dateTime={a.ingested_at} title={formatDateTime(a.ingested_at)}>
        {formatRelative(a.ingested_at)}
      </time>
    ),
  },
];

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
  { header: 'source_alert_id', value: (a) => a.source_alert_id },
  { header: 'occurred_at', value: (a) => a.occurred_at },
  { header: 'ingested_at', value: (a) => a.ingested_at },
  { header: 'closed_at', value: (a) => a.closed_at },
];

export default function AlertsPage() {
  const api = useApi();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(params), [params]);
  const selected = params.get('alert');
  const [search, setSearch] = useState(filters.q ?? '');
  const [sourceText, setSourceText] = useState(filters.source_id ?? '');

  const update = useCallback(
    (mutate: (p: URLSearchParams) => void) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
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

  const list = useKeysetList({
    queryKey: qk.alerts.list(filters),
    fetchPage: (cursor, signal) => endpoints.alerts(api, filters, cursor, signal),
    itemKey: (a: AlertOut) => a.id,
  });

  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    update((p) => {
      if (search.trim()) p.set('q', search.trim());
      else p.delete('q');
      if (sourceText.trim()) p.set('source_id', sourceText.trim());
      else p.delete('source_id');
    });
  };

  const clearAll = () => {
    setSearch('');
    setSourceText('');
    update((p) => {
      for (const k of ['status', 'severity', 'disposition', 'source_id', 'q', 'from', 'to']) p.delete(k);
    });
  };

  const exportCsv = () => downloadCsv(csvFilename('alerts'), toCsv(ALERT_CSV, list.items));
  const { fetchNextPage } = list;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);
  const hasFilters = Object.keys(filters).length > 0;

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Every alert ingested for this tenant, newest first. Filters are applied by the API; rows load as you scroll."
        actions={
          <Button onClick={exportCsv} disabled={list.items.length === 0} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
            Export loaded rows (CSV)
          </Button>
        }
      />
      <section aria-label="Filters" className="mb-4 space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <form onSubmit={submitSearch} className="grid gap-3 md:grid-cols-[2fr_1fr_1fr_1fr_auto]">
          <TextField
            label="Title contains"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            hint="Searches at most 93 days (default: the 30 days before 'To')."
          />
          <TextField label="Source id" value={sourceText} onChange={(e) => setSourceText(e.target.value)} maxLength={128} hint="One source, exact match" />
          <TextField
            label="From"
            type="datetime-local"
            value={isoToLocalInput(filters.from)}
            onChange={(e) => setSingle('from', localInputToIso(e.target.value))}
          />
          <TextField
            label="To"
            type="datetime-local"
            value={isoToLocalInput(filters.to)}
            onChange={(e) => setSingle('to', localInputToIso(e.target.value))}
          />
          <div className="flex items-start gap-2 pt-5">
            <Button type="submit" variant="primary" icon={<Search className="h-4 w-4" aria-hidden="true" />}>
              Apply
            </Button>
            {hasFilters && (
              <Button onClick={clearAll} icon={<X className="h-4 w-4" aria-hidden="true" />}>
                Clear
              </Button>
            )}
          </div>
        </form>
        <div className="flex flex-wrap gap-x-6 gap-y-3">
          <ToggleGroup label="Severity" options={SEVERITIES} value={filters.severity ?? []} onChange={(v) => setMulti('severity', v)} />
          <ToggleGroup label="Status" options={ALERT_STATUSES} value={filters.status ?? []} onChange={(v) => setMulti('status', v)} />
          <ToggleGroup label="Disposition" options={DISPOSITIONS} value={filters.disposition ?? []} onChange={(v) => setMulti('disposition', v)} />
        </div>
      </section>

      <ListNotice list={list} noun="alerts" />
      {list.isPending && <LoadingState label="Loading alerts" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {list.isSuccess && list.items.length === 0 && (
        <EmptyState title={hasFilters ? 'No alerts match these filters' : 'No alerts yet'}>
          {hasFilters ? 'Widen the time window or clear some filters.' : 'Alerts appear here once a source is connected or alerts are sent to the ingest API.'}
        </EmptyState>
      )}
      {list.items.length > 0 && (
        <VirtualTable
          label="Alerts"
          columns={COLUMNS}
          rows={list.items}
          rowKey={(a) => a.id}
          rowLabel={(a) => `${a.severity} alert: ${a.title}, status ${a.status.replace(/_/g, ' ')}`}
          selectedKey={selected}
          onOpen={(a) => setSingle('alert', a.id)}
          hasMore={Boolean(list.hasNextPage)}
          loadingMore={list.isFetchingNextPage}
          onLoadMore={loadMore}
          autoLoad={!list.isFetchNextPageError}
        />
      )}
      {list.isFetchNextPageError && (
        <div className="mt-3">
          <ErrorMessage error={list.error} onRetry={loadMore} compact />
        </div>
      )}
      <AlertDrawer alertId={selected} onClose={() => setSingle('alert', undefined)} />
    </>
  );
}
