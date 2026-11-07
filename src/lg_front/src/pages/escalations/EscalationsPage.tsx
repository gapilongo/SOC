/**
 * The escalation queue: SLA order by default (overdue first, then the
 * soonest deadline), filters in the URL with the API's parameter names,
 * per-row claim, bulk claim / close / suppression proposal on up to 50
 * selected escalations, and an optional grouping by detection rule.
 */

import { Download, ListTree, X } from 'lucide-react';
import { useCallback, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { readQueueFigures } from '../../api/fields';
import { useDashboardSummary, useEscalationGroups, useEscalationList, useLivePollInterval } from '../../api/hooks';
import { BULK_MAX_ITEMS, ESCALATION_LEVELS, ESCALATION_STATUSES, type EscalationOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { ListNotice } from '../../components/ListNotice';
import { Button, CountChip, DensityToggle, EmptyState, ErrorMessage, FilterChip, LoadingState, PageHeader, Segmented, Spinner, cx } from '../../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../../lib/csv';
import { humanize } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { BulkBar, BulkResultPanel, type BulkResult } from './BulkActions';
import { GroupRows, MessageRow, QUEUE_PAGE_SIZE, QueueRow, QueueTable, type Selection } from './QueueTable';
import { VIEWS, currentView, filtersFromParams, groupedFromParams, viewParams, withParams } from './queueParams';

const CSV: CsvColumn<EscalationOut>[] = [
  { header: 'id', value: (e) => e.id },
  { header: 'alert_id', value: (e) => e.alert_id },
  { header: 'level', value: (e) => e.level },
  { header: 'status', value: (e) => e.status },
  { header: 'severity', value: (e) => e.alert_severity ?? e.summary?.severity },
  { header: 'title', value: (e) => e.summary?.title ?? e.rule },
  { header: 'rule', value: (e) => e.rule },
  { header: 'reason', value: (e) => e.reason },
  { header: 'ai_reason', value: (e) => e.ai_reason },
  { header: 'routing_code', value: (e) => e.routing?.code },
  { header: 'routing_confidence', value: (e) => e.routing?.confidence },
  { header: 'assigned_to', value: (e) => e.assigned_to_email ?? e.assigned_to },
  { header: 'sla_deadline', value: (e) => e.sla_deadline },
  { header: 'decision', value: (e) => e.decision },
  { header: 'decided_by', value: (e) => e.decided_by_email ?? e.decided_by },
  { header: 'decided_at', value: (e) => e.decided_at },
  { header: 'created_at', value: (e) => e.created_at },
];

const ORDER_OPTIONS = [
  { value: 'sla_deadline', label: 'SLA', title: 'Overdue first, then the soonest deadline' },
  { value: 'created_at', label: 'Newest', title: 'Newest first' },
] as const;

/** Selected escalations, valid for one set of filters (they are cleared when the filters change). */
function useSelection(scope: string, enabled: boolean) {
  const [state, setState] = useState<{ scope: string; rows: Map<string, EscalationOut>; capped: boolean }>({ scope, rows: new Map(), capped: false });
  const current = state.scope === scope ? state : { scope, rows: new Map<string, EscalationOut>(), capped: false };
  const set = useCallback(
    (rows: readonly EscalationOut[], on: boolean) =>
      setState((prev) => {
        const next = new Map(prev.scope === scope ? prev.rows : []);
        let capped = false;
        for (const e of rows) {
          if (!on) next.delete(e.id);
          else if (next.has(e.id)) next.set(e.id, e);
          else if (next.size < BULK_MAX_ITEMS) next.set(e.id, e);
          else capped = true;
        }
        return { scope, rows: next, capped };
      }),
    [scope],
  );
  const clear = useCallback(() => setState({ scope, rows: new Map(), capped: false }), [scope]);
  const selection: Selection = {
    isSelected: (id) => current.rows.has(id),
    set,
    full: current.rows.size >= BULK_MAX_ITEMS,
    enabled,
  };
  return { selection, rows: current.rows, capped: current.capped, clear };
}

function Views({ params, breaching }: { params: URLSearchParams; breaching: number | null }) {
  const current = currentView(params);
  return (
    <nav aria-label="Escalation views" className="relative overflow-x-auto border-b border-subtle">
      <ul className="flex gap-1">
        {VIEWS.map((v) => {
          const on = current?.id === v.id;
          const search = viewParams(params, v).toString();
          return (
            <li key={v.id}>
              <Link
                to={{ pathname: '/escalations', search: search ? `?${search}` : '' }}
                aria-current={on ? 'page' : undefined}
                className={cx(
                  '-mb-px inline-flex h-[38px] items-center gap-2 whitespace-nowrap border-b-2 px-3 text-ctl font-medium touch:min-h-11',
                  on ? 'border-accent text-fg' : 'border-transparent text-secondary hover:text-fg',
                )}
              >
                {v.label}
                {v.id === 'breaching' && breaching !== null && breaching > 0 && <CountChip count={breaching} meaning="past their deadline" tone="warn" />}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export default function EscalationsPage() {
  const { principal } = useAuth();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(params), [params]);
  const grouped = groupedFromParams(params);
  const interval = useLivePollInterval();
  const [result, setResult] = useState<BulkResult | null>(null);
  const bulkEnabled = can.claim(principal);

  const list = useEscalationList(filters, { refetchInterval: interval, limit: QUEUE_PAGE_SIZE });
  const groups = useEscalationGroups(filters.assigned_to ? { assigned_to: filters.assigned_to } : {}, { enabled: grouped, refetchInterval: interval });
  const summary = useDashboardSummary(24, { refetchInterval: interval });
  const figures = readQueueFigures(summary.data);
  const now = useNow(1_000);

  const scope = useMemo(() => {
    const p = withParams(params, { group: undefined });
    p.sort();
    return `${p.toString()}|${grouped}`;
  }, [params, grouped]);
  const { selection, rows: selectedRows, capped, clear } = useSelection(scope, bulkEnabled);

  // Rows of a group are shown under the group, not again on their own.
  const groupItems = grouped && groups.data && Array.isArray(groups.data.items) ? groups.data.items : [];
  const groupKeys = new Set(groupItems.map((g) => `${g.source_id}\u0000${g.rule}`));
  const rows = grouped ? list.items.filter((e) => !groupKeys.has(`${e.source_id ?? ''}\u0000${e.rule ?? ''}`)) : list.items;
  // The latest version of each selected escalation (a live refresh may have moved it on).
  const latest = new Map(list.items.map((e) => [e.id, e]));
  const selected = [...selectedRows.values()].map((e) => latest.get(e.id) ?? e);

  const update = (changes: Record<string, string | string[] | boolean | undefined>) => setParams((prev) => withParams(prev, changes), { replace: true });
  const status = params.has('status') ? params.getAll('status').filter(Boolean) : [];
  const groupFilter = filters.source_id || filters.rule;
  const sla = filters.order === 'sla_deadline';

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Escalations"
        description={sla ? 'Overdue first, then by time left on the SLA.' : 'Newest first.'}
        actions={
          <>
            <Button size="sm" aria-pressed={grouped} onClick={() => update({ group: grouped ? undefined : 'rule' })} icon={<ListTree className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />}>
              Group by rule: {grouped ? 'on' : 'off'}
            </Button>
            <DensityToggle />
            <Button
              size="sm"
              onClick={() => downloadCsv(csvFilename('escalations'), toCsv(CSV, list.items))}
              disabled={list.items.length === 0}
              icon={<Download className="h-4 w-4" aria-hidden="true" />}
            >
              Export CSV
            </Button>
          </>
        }
      />
      <Views params={params} breaching={figures?.overdue ?? null} />
      <section aria-label="Filters" className="flex flex-wrap items-center gap-2">
        <FilterChip
          label="Status"
          options={ESCALATION_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
          value={status}
          anyLabel="Waiting (open, claimed, expired)"
          onChange={(v) => update({ status: v })}
        />
        <FilterChip label="Level" options={ESCALATION_LEVELS.map((l) => ({ value: l, label: l }))} value={filters.level ?? []} onChange={(v) => update({ level: v })} />
        {groupFilter && (
          <span className="inline-flex h-[34px] items-center gap-1.5 rounded-control border border-link bg-raised pl-2.5 pr-1 text-ctl text-secondary">
            Rule: <span className="max-w-[18rem] truncate font-medium text-fg">{filters.rule ?? 'any'}</span>
            <Button size="sm" variant="quiet" className="min-h-7 px-1.5" aria-label="Remove the rule filter" onClick={() => update({ source_id: undefined, rule: undefined })} icon={<X className="h-3.5 w-3.5" aria-hidden="true" />} />
          </span>
        )}
        <span className="flex-1" />
        <Segmented label="Order" options={ORDER_OPTIONS} value={filters.order ?? 'sla_deadline'} onChange={(v) => update({ order: v })} />
      </section>

      {bulkEnabled && <BulkBar selected={selected} capped={capped} onClear={clear} onResult={setResult} />}
      {result && <BulkResultPanel result={result} onDismiss={() => setResult(null)} />}

      <ListNotice list={list} noun="escalations" />
      <div className="overflow-hidden rounded-card border border-subtle bg-raised">
        {list.isPending && <LoadingState label="Loading escalations" />}
        {list.isError && (
          <div className="p-4">
            <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />
          </div>
        )}
        {list.isSuccess && list.items.length === 0 && groupItems.length === 0 && (
          <EmptyState title="Nothing in this view">
            No escalation matches these filters.{' '}
            {filters.assigned_to === 'none' && (
              <Link to="/escalations?assigned_to=me" className="text-link hover:text-link-hover hover:underline">
                Show my claimed escalations
              </Link>
            )}
          </EmptyState>
        )}
        {list.isSuccess && (list.items.length > 0 || groupItems.length > 0) && (
          <QueueTable caption={`Escalations, ${sla ? 'overdue first' : 'newest first'}`} rows={rows} selection={selection}>
            {grouped && groups.isPending && <MessageRow>{<Spinner label="Loading groups" />}</MessageRow>}
            {grouped && groups.isError && (
              <MessageRow>
                <ErrorMessage error={groups.error} compact onRetry={() => void groups.refetch()} />
              </MessageRow>
            )}
            {groupItems.map((g) => (
              <GroupRows key={`${g.source_id}-${g.rule}`} g={g} now={now} selection={selection} assignedTo={filters.assigned_to} />
            ))}
            {grouped && groups.data?.truncated && <MessageRow>More groups matched than are shown (the 100 largest are).</MessageRow>}
            {rows.map((e) => (
              <QueueRow key={e.id} e={e} now={now} selection={selection} />
            ))}
          </QueueTable>
        )}
        {list.isSuccess && list.items.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-subtle px-3.5 py-2.5 text-xs text-secondary">
            <span>
              Loaded {list.items.length} escalation{list.items.length === 1 ? '' : 's'}
              {grouped && rows.length !== list.items.length && ` (${list.items.length - rows.length} shown in their groups)`}
            </span>
            {list.hasNextPage && (
              <Button size="sm" onClick={() => void list.fetchNextPage()} busy={list.isFetchingNextPage}>
                Load more
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
