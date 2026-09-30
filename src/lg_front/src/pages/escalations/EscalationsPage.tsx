import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Clock, Download, Hand, Gavel } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { endpoints, type EscalationFilters } from '../../api/endpoints';
import { ESCALATION_LEVELS, ESCALATION_STATUSES, type EscalationOut, type TicketOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can, escalationDecisionBlockedReason } from '../../auth/roles';
import { Badge, SeverityBadge, StatusBadge } from '../../components/Badge';
import { useToast } from '../../components/Toast';
import { Button, EmptyState, ErrorMessage, LoadingState, PageHeader, ToggleGroup, cx } from '../../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../../lib/csv';
import { formatCountdown, formatDateTime, shortId } from '../../lib/format';
import { ListNotice } from '../../components/ListNotice';
import { TicketLinks } from '../../components/TicketLinks';
import { useKeysetList } from '../../lib/pagination';
import { useNow } from '../../lib/useNow';
import { usePollInterval } from '../../lib/visibility';
import { AlertDrawer } from '../alerts/AlertDrawer';
import { DecisionDialog } from './DecisionDialog';

const DEFAULT_STATUS = ['open', 'claimed', 'expired'];

const CSV: CsvColumn<EscalationOut>[] = [
  { header: 'id', value: (e) => e.id },
  { header: 'alert_id', value: (e) => e.alert_id },
  { header: 'level', value: (e) => e.level },
  { header: 'status', value: (e) => e.status },
  { header: 'priority', value: (e) => e.priority },
  { header: 'reason', value: (e) => e.reason },
  { header: 'title', value: (e) => e.summary?.title },
  { header: 'assigned_to', value: (e) => e.assigned_to },
  { header: 'sla_deadline', value: (e) => e.sla_deadline },
  { header: 'decision', value: (e) => e.decision },
  { header: 'decided_by', value: (e) => e.decided_by },
  { header: 'decided_at', value: (e) => e.decided_at },
  { header: 'created_at', value: (e) => e.created_at },
];

function SlaCountdown({ e, now }: { e: EscalationOut; now: number }) {
  if (e.status === 'decided' || e.status === 'cancelled') return <span className="text-slate-400">closed</span>;
  const c = formatCountdown(e.sla_deadline, now);
  const soon = c.seconds !== null && c.seconds >= 0 && c.seconds < 15 * 60;
  return (
    <span
      className={cx('inline-flex items-center gap-1 tabular-nums', c.overdue ? 'text-red-300' : soon ? 'text-amber-300' : 'text-slate-200')}
      title={e.sla_deadline ? `SLA deadline ${formatDateTime(e.sla_deadline)}` : undefined}
    >
      <Clock className="h-3.5 w-3.5" aria-hidden="true" />
      {c.text}
    </span>
  );
}

function EscalationCard({
  e,
  now,
  onOpenAlert,
  onDecide,
  tickets = [],
}: {
  e: EscalationOut;
  now: number;
  onOpenAlert: (id: string) => void;
  onDecide: (e: EscalationOut) => void;
  tickets?: TicketOut[];
}) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [claiming, setClaiming] = useState(false);
  const s = e.summary ?? {};
  const blocked = escalationDecisionBlockedReason(principal, e);
  const active = e.status === 'open' || e.status === 'claimed' || e.status === 'expired';
  const mine = Boolean(principal?.userId && e.assigned_to === principal.userId);
  const recommended = Array.isArray(s.recommended_actions) ? (s.recommended_actions as unknown[]).map(String) : [];
  const related = e.related_alert_ids ?? [];

  const claim = async () => {
    setClaiming(true);
    try {
      await endpoints.claim(api, e.id, e.version);
      toast.success(e.status === 'claimed' ? 'Escalation taken over.' : 'Escalation claimed.');
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) toast.info('Someone else changed this escalation first; the list has been refreshed.');
      else toast.error(err, 'Claim failed');
    } finally {
      setClaiming(false);
      void client.invalidateQueries({ queryKey: ['escalations'] });
    }
  };

  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex flex-wrap items-center gap-1.5">
            <Badge tone={e.level === 'L3' ? 'critical' : e.level === 'L2' ? 'bad' : 'warn'}>{e.level}</Badge>
            <StatusBadge value={e.status} />
            {typeof s.severity === 'string' && <SeverityBadge value={s.severity} />}
            <span className="text-xs text-slate-400">priority {e.priority}</span>
          </div>
          <h2 className="break-words text-sm font-semibold text-white">{String(s.title ?? 'Untitled alert')}</h2>
          <p className="mt-0.5 text-sm text-slate-300">{e.reason}</p>
        </div>
        <div className="text-right text-sm">
          <SlaCountdown e={e} now={now} />
          <div className="mt-1 text-xs text-slate-400">
            {e.assigned_to ? (mine ? 'Assigned to you' : `Assigned to ${shortId(e.assigned_to)}`) : 'Unassigned'}
          </div>
        </div>
      </div>
      {(typeof s.conclusion === 'string' && s.conclusion) || s.verdict ? (
        <div className="mt-3 rounded-md bg-slate-950 p-3 text-sm text-slate-200">
          {s.verdict ? <span className="mr-2 text-slate-400">Automated verdict: {String(s.verdict)}.</span> : null}
          {typeof s.conclusion === 'string' ? s.conclusion : null}
          {s.simulated_evidence ? <p className="mt-1 text-amber-200">Some evidence was simulated; verify before acting.</p> : null}
        </div>
      ) : null}
      {recommended.length > 0 && <p className="mt-2 text-xs text-slate-300">Recommended: {recommended.join(', ')}</p>}
      {e.decision && (
        <p className="mt-2 text-sm text-slate-200">
          Decision: <strong>{e.decision.replace(/_/g, ' ')}</strong>
          {e.decided_at ? ` on ${formatDateTime(e.decided_at)}` : ''}
          {e.decision_notes ? `: ${e.decision_notes}` : ''}
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="ghost" onClick={() => onOpenAlert(e.alert_id)}>
          View alert {shortId(e.alert_id)}
        </Button>
        <TicketLinks tickets={tickets} />
        {related.length > 0 && (
          <details className="text-xs text-slate-300">
            <summary className="cursor-pointer rounded px-2 py-1 hover:bg-slate-800">{related.length} related alert(s)</summary>
            <ul className="mt-1 flex flex-wrap gap-1">
              {related.map((id) => (
                <li key={id}>
                  <Button size="sm" variant="ghost" onClick={() => onOpenAlert(id)}>
                    {shortId(id)}
                  </Button>
                </li>
              ))}
            </ul>
          </details>
        )}
        <div className="ml-auto flex gap-2">
          {can.claimEscalation(principal, e) && (
            <Button size="sm" onClick={claim} busy={claiming} icon={<Hand className="h-3.5 w-3.5" aria-hidden="true" />}>
              {e.status === 'claimed' && e.assigned_to && !mine ? 'Take over' : 'Claim'}
            </Button>
          )}
          {active && (
            <Button
              size="sm"
              variant="primary"
              onClick={() => onDecide(e)}
              disabled={!can.decideEscalation(principal, e)}
              title={blocked ?? undefined}
              icon={<Gavel className="h-3.5 w-3.5" aria-hidden="true" />}
            >
              Decide
            </Button>
          )}
        </div>
      </div>
      {active && blocked && <p className="mt-2 text-xs text-slate-400">{blocked}</p>}
    </li>
  );
}

export default function EscalationsPage() {
  const api = useApi();
  const [params, setParams] = useSearchParams();
  const status = params.has('status') ? params.getAll('status').filter(Boolean) : DEFAULT_STATUS;
  const level = params.getAll('level').filter(Boolean);
  const filters: EscalationFilters = { status: status.length ? status : undefined, level: level.length ? level : undefined };
  const [alertId, setAlertId] = useState<string | null>(null);
  const [deciding, setDeciding] = useState<EscalationOut | null>(null);
  const now = useNow(1_000);
  const interval = usePollInterval(30_000);

  const list = useKeysetList({
    queryKey: ['escalations', filters],
    fetchPage: (cursor, signal) => endpoints.escalations(api, filters, cursor, signal),
    itemKey: (e: EscalationOut) => e.id,
    refetchInterval: interval,
  });

  // Linked Jira/ServiceNow tickets of the listed escalations, in one request.
  const escalationIds = list.items.map((e) => e.id).slice(0, 200);
  const tickets = useQuery({
    queryKey: ['tickets', 'escalations', escalationIds],
    queryFn: ({ signal }) => endpoints.tickets(api, { escalation_id: escalationIds }, signal),
    enabled: escalationIds.length > 0,
    refetchInterval: interval,
  });
  const ticketsByEscalation = new Map<string, TicketOut[]>();
  for (const t of Array.isArray(tickets.data) ? tickets.data : []) {
    if (t.escalation_id) ticketsByEscalation.set(t.escalation_id, [...(ticketsByEscalation.get(t.escalation_id) ?? []), t]);
  }

  const setMulti = (key: string, values: string[]) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(key);
        for (const v of values) next.append(key, v);
        if (key === 'status' && values.length === 0) next.append('status', '');
        return next;
      },
      { replace: true },
    );

  return (
    <>
      <PageHeader
        title="Escalations"
        description="Alerts waiting for an analyst. Claim one to take ownership, then record a decision; the workflow resumes every attached alert."
        actions={
          <Button
            onClick={() => downloadCsv(csvFilename('escalations'), toCsv(CSV, list.items))}
            disabled={list.items.length === 0}
            icon={<Download className="h-4 w-4" aria-hidden="true" />}
          >
            Export CSV
          </Button>
        }
      />
      <section aria-label="Filters" className="mb-4 flex flex-wrap gap-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ToggleGroup label="Status" options={ESCALATION_STATUSES} value={status} onChange={(v) => setMulti('status', v)} />
        <ToggleGroup label="Level" options={ESCALATION_LEVELS} value={level} onChange={(v) => setMulti('level', v)} format={(v) => v} />
      </section>
      <ListNotice list={list} noun="escalations" />
      {list.isPending && <LoadingState label="Loading escalations" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {list.isSuccess && list.items.length === 0 && <EmptyState title="The queue is empty">No escalations match these filters.</EmptyState>}
      <ul className="space-y-3" aria-label="Escalation queue">
        {list.items.map((e) => (
          <EscalationCard
            key={e.id}
            e={e}
            now={now}
            onOpenAlert={setAlertId}
            onDecide={setDeciding}
            tickets={ticketsByEscalation.get(e.id)}
          />
        ))}
      </ul>
      {list.hasNextPage && (
        <div className="mt-4 flex justify-center">
          <Button onClick={() => void list.fetchNextPage()} busy={list.isFetchingNextPage}>
            Load more
          </Button>
        </div>
      )}
      <AlertDrawer alertId={alertId} onClose={() => setAlertId(null)} />
      {deciding && <DecisionDialog escalation={deciding} onClose={() => setDeciding(null)} />}
    </>
  );
}
