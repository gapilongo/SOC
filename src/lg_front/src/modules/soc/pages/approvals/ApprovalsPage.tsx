/**
 * Approvals: response actions waiting for a human first (one card each, with
 * the guardrail re-check, blast radius and the caller's Approve / Reject),
 * then the recently executed ones with their verification and follow-ups.
 * The whole ledger, with its filters and CSV export, is the "All actions"
 * view (`?view=all`). `/actions` redirects here (redirect.tsx).
 */

import { CircleCheck } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import type { ActionFilters } from '../../api/endpoints';
import { readQueueFigures } from '../../api/fields';
import { useDashboardSummary } from '../../api/hooks';
import { useAuth } from '../../../../auth/AuthContext';
import { can, roleAtLeast } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import { ApprovalDialog, type PendingDecision } from '../actions/ApprovalDialog';
import { Button, ErrorMessage, LoadingState, PageHeader, Segmented } from '../../../../components/ui';
import { formatInt, humanize } from '../../../../lib/format';
import { usePollInterval } from '../../../../lib/visibility';
import { useNow } from '../../../../lib/useNow';
import { AlertDrawer } from '../alerts/AlertDrawer';
import { AllActions, type ActionFilterKey } from './AllActions';
import { approvalFigures, type ApprovalFigures } from './approvals';
import { PendingCard } from './PendingCard';
import { EXECUTED_STATUSES, RecentlyExecuted } from './RecentlyExecuted';
import { useActionList } from './useActionList';

type View = 'approvals' | 'all';

const VIEWS = [
  { value: 'approvals' as const, label: 'Pending and recent' },
  { value: 'all' as const, label: 'All actions' },
];

const PENDING_FILTERS: ActionFilters = { status: ['awaiting_approval'] };
const EXECUTED_FILTERS: ActionFilters = { status: EXECUTED_STATUSES };
const RISK_ORDER = ['critical', 'high', 'medium', 'low'];
/** The dashboard window the header reads its "right now" queue figures from (the overview's default, so the cache is shared). */
const SUMMARY_WINDOW_HOURS = 24;

function roleLine(p: Principal | null): string {
  if (can.admin(p)) return "You are an admin: you can approve and reject at any risk the tenant's autonomy policy allows.";
  if (roleAtLeast(p?.role, 'analyst')) return 'You are an analyst: you can approve low and medium risk; high and critical need an admin. You can reject at any risk.';
  return 'You can follow them here; approving and rejecting need the analyst role.';
}

function Figures({ figures }: { figures: ApprovalFigures }) {
  const risks = [...RISK_ORDER, ...Object.keys(figures.byRisk).filter((r) => !RISK_ORDER.includes(r))].filter((r) => figures.byRisk[r]);
  const approx = figures.exact ? '' : '+';
  return (
    <dl className="grid grid-cols-2 gap-3 sm:grid-cols-[repeat(3,minmax(0,max-content))] sm:gap-x-10">
      <div>
        <dt className="text-xs text-secondary">You can approve</dt>
        <dd className="text-2xl font-semibold tabular-nums text-fg">
          {formatInt(figures.mine)}
          {approx}
        </dd>
      </div>
      <div>
        <dt className="text-xs text-secondary">Pending in total</dt>
        <dd className="text-2xl font-semibold tabular-nums text-fg">
          {formatInt(figures.total)}
          {approx}
        </dd>
      </div>
      <div className="col-span-2 sm:col-span-1">
        <dt className="text-xs text-secondary">By risk</dt>
        <dd className="mt-1.5 text-ctl text-body">
          {risks.length ? (
            <ul className="flex flex-wrap gap-x-4 gap-y-1" aria-label="Pending approvals by risk">
              {risks.map((r) => (
                <li key={r}>
                  <span className="text-secondary">{humanize(r)}</span> <span className="font-semibold tabular-nums text-fg">{formatInt(figures.byRisk[r])}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span className="text-secondary">None pending</span>
          )}
        </dd>
      </div>
    </dl>
  );
}

function ApprovalsView({
  interval,
  onDecide,
  onOpenAlert,
  onShowExecuted,
}: {
  interval: number | false;
  onDecide: (d: PendingDecision) => void;
  onOpenAlert: (alertId: string) => void;
  onShowExecuted: () => void;
}) {
  const { principal } = useAuth();
  const now = useNow(30_000);
  const pending = useActionList(PENDING_FILTERS, interval);
  const executed = useActionList(EXECUTED_FILTERS, interval);
  const summary = useDashboardSummary(SUMMARY_WINDOW_HOURS, { refetchInterval: interval });
  const queue = readQueueFigures(summary.data);
  const loadedAll = pending.isSuccess && !pending.hasNextPage;
  const figures = queue || pending.isSuccess ? approvalFigures(queue, pending.items, principal, loadedAll) : null;
  const perAlert = new Map<string, number>();
  for (const a of pending.items) perAlert.set(a.alert_id, (perAlert.get(a.alert_id) ?? 0) + 1);
  const shown = `${formatInt(pending.items.length)}${pending.hasNextPage ? '+' : ''}`;

  return (
    <div className="flex flex-col gap-6">
      {figures && (
        <section aria-label="Approval queue" className="rounded-card border border-subtle bg-raised px-4 py-3.5">
          <Figures figures={figures} />
        </section>
      )}

      <section aria-labelledby="ap-pending" className="flex flex-col gap-3">
        <h2 id="ap-pending" className="text-sm font-semibold text-fg">
          Pending{pending.isSuccess && <span className="font-normal text-secondary"> · {shown}</span>}
        </h2>
        {pending.isPending && <LoadingState label="Loading pending actions" />}
        {pending.isError && <ErrorMessage error={pending.error} onRetry={() => void pending.refetch()} />}
        {pending.isSuccess && pending.items.length === 0 && (
          <p className="flex items-center gap-1.5 rounded-card border border-subtle bg-raised px-4 py-3 text-ctl text-body">
            <CircleCheck className="h-4 w-4 text-state-ok" strokeWidth={1.75} aria-hidden="true" />
            Nothing is waiting for approval.
          </p>
        )}
        {pending.items.length > 0 && (
          <ol className="flex flex-col gap-3" aria-label="Pending actions">
            {pending.items.map((a) => (
              <PendingCard
                key={a.id}
                action={a}
                now={now}
                siblings={(perAlert.get(a.alert_id) ?? 1) - 1}
                onDecide={onDecide}
                onOpenAlert={onOpenAlert}
              />
            ))}
          </ol>
        )}
        {pending.hasNextPage && (
          <div className="flex justify-center">
            <Button onClick={() => void pending.fetchNextPage()} busy={pending.isFetchingNextPage}>
              Load more
            </Button>
          </div>
        )}
      </section>

      <RecentlyExecuted list={executed} now={now} onOpenAlert={onOpenAlert} onShowAll={onShowExecuted} />
    </div>
  );
}

export default function ApprovalsPage() {
  const { principal } = useAuth();
  const [params, setParams] = useSearchParams();
  const view: View = params.get('view') === 'all' ? 'all' : 'approvals';
  const [decision, setDecision] = useState<PendingDecision | null>(null);
  const [alertId, setAlertId] = useState<string | null>(null);
  const interval = usePollInterval(30_000);

  const status = params.getAll('status').filter(Boolean);
  const risk = params.getAll('risk_level').filter(Boolean);
  const verification = params.getAll('verification').filter(Boolean);
  const filters: ActionFilters = {
    status: status.length ? status : undefined,
    risk_level: risk.length ? risk : undefined,
    verification: verification.length ? verification : undefined,
  };

  const update = (change: (next: URLSearchParams) => void) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        change(next);
        return next;
      },
      { replace: true },
    );
  const setView = (v: View) => update((next) => (v === 'all' ? next.set('view', 'all') : next.delete('view')));
  const setFilter = (key: ActionFilterKey, values: string[]) =>
    update((next) => {
      next.delete(key);
      for (const v of values) next.append(key, v);
    });
  const showExecuted = () =>
    update((next) => {
      next.set('view', 'all');
      next.delete('status');
      for (const s of EXECUTED_STATUSES) next.append('status', s);
    });

  return (
    <>
      <PageHeader
        title="Approvals"
        description={
          view === 'approvals' ? (
            <>
              Response actions waiting for a human, newest first. {roleLine(principal)} Guardrails are checked again now for each pending action,
              and once more when it executes.
            </>
          ) : (
            <>
              Every response action, newest first: what ran, what was blocked and what still waits. {roleLine(principal)} Open a row for its full
              target, outcome and rollback.
            </>
          )
        }
        actions={<Segmented label="View" options={VIEWS} value={view} onChange={setView} />}
      />
      {view === 'approvals' ? (
        <ApprovalsView interval={interval} onDecide={setDecision} onOpenAlert={setAlertId} onShowExecuted={showExecuted} />
      ) : (
        <AllActions filters={filters} interval={interval} onFilter={setFilter} onDecide={setDecision} onOpenAlert={setAlertId} />
      )}
      {decision && <ApprovalDialog pending={decision} onClose={() => setDecision(null)} />}
      <AlertDrawer alertId={alertId} onClose={() => setAlertId(null)} />
    </>
  );
}
