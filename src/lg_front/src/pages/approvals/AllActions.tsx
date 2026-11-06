import { Check, ChevronDown, ChevronRight, Download, X } from 'lucide-react';
import { Fragment, useState } from 'react';

import type { ActionFilters } from '../../api/endpoints';
import { ACTION_STATUSES, RISK_LEVELS, VERIFICATION_STATES, type ActionOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { RiskBadge, StatusBadge } from '../../components/Badge';
import { ListNotice } from '../../components/ListNotice';
import { ActionControls, ActionDetails } from '../../components/actions/ActionDetails';
import type { PendingDecision } from '../../components/actions/ApprovalDialog';
import { VerificationBadge } from '../../components/actions/VerificationBadge';
import { Button, EmptyState, ErrorMessage, FilterChip, LoadingState, type FilterOption } from '../../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../../lib/csv';
import { formatDateTime, humanize, shortId } from '../../lib/format';
import { describeBlockedReason } from '../../lib/guardrails';
import { approvalAccess } from './approvals';
import { useActionList } from './useActionList';

const CSV: CsvColumn<ActionOut>[] = [
  { header: 'id', value: (a) => a.id },
  { header: 'alert_id', value: (a) => a.alert_id },
  { header: 'action_type', value: (a) => a.action_type },
  { header: 'target', value: (a) => a.target },
  { header: 'risk_level', value: (a) => a.risk_level },
  { header: 'status', value: (a) => a.status },
  { header: 'blocked_reason', value: (a) => a.blocked_reason },
  { header: 'approved_by', value: (a) => a.approved_by },
  { header: 'approved_at', value: (a) => a.approved_at },
  { header: 'executed_at', value: (a) => a.executed_at },
  { header: 'connector', value: (a) => a.connector },
  { header: 'created_at', value: (a) => a.created_at },
  { header: 'verification', value: (a) => a.verification },
  { header: 'verified_at', value: (a) => a.verified_at },
  { header: 'rollback_of', value: (a) => a.rollback_of },
  { header: 'execution_owner', value: (a) => a.execution_owner },
  { header: 'attempts', value: (a) => a.attempts },
];

const options = (values: readonly string[]): FilterOption[] => values.map((v) => ({ value: v, label: humanize(v) }));
const STATUS_OPTIONS = options(ACTION_STATUSES);
const RISK_OPTIONS = options(RISK_LEVELS);
const VERIFICATION_OPTIONS = options(VERIFICATION_STATES);

export type ActionFilterKey = 'status' | 'risk_level' | 'verification';

function ApprovalCell({ action, onDecide }: { action: ActionOut; onDecide: (d: PendingDecision) => void }) {
  const { principal } = useAuth();
  if (action.status !== 'awaiting_approval') return <ActionControls action={action} />;
  const access = approvalAccess(principal, action);
  if (!access.approve && !access.reject) return <span className="text-xs text-muted">{access.lock ?? 'Not permitted'}</span>;
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex justify-end gap-1.5">
        {access.approve && (
          <Button size="sm" variant="primary" onClick={() => onDecide({ action, verb: 'approve' })} icon={<Check className="h-3.5 w-3.5" aria-hidden="true" />}>
            Approve
          </Button>
        )}
        {access.reject && (
          <Button size="sm" variant="destructive" onClick={() => onDecide({ action, verb: 'reject' })} icon={<X className="h-3.5 w-3.5" aria-hidden="true" />}>
            Reject
          </Button>
        )}
      </div>
      {access.lock && <span className="whitespace-normal text-xs text-muted">{access.lock}</span>}
    </div>
  );
}

/**
 * The whole response action ledger: filters, CSV export, expandable details
 * (outcome, steps, verification, rollback lineage) and the follow-ups each
 * action allows.
 */
export function AllActions({
  filters,
  interval,
  onFilter,
  onDecide,
  onOpenAlert,
}: {
  filters: ActionFilters;
  interval: number | false;
  onFilter: (key: ActionFilterKey, values: string[]) => void;
  onDecide: (d: PendingDecision) => void;
  onOpenAlert: (alertId: string) => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const list = useActionList(filters, interval);

  return (
    <section aria-labelledby="ap-all" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="ap-all" className="text-sm font-semibold text-fg">
          All actions
        </h2>
        <Button
          size="sm"
          onClick={() => downloadCsv(csvFilename('actions'), toCsv(CSV, list.items))}
          disabled={list.items.length === 0}
          icon={<Download className="h-4 w-4" aria-hidden="true" />}
        >
          Export CSV
        </Button>
      </div>
      <div role="group" aria-label="Filters" className="flex flex-wrap gap-2">
        <FilterChip label="Status" options={STATUS_OPTIONS} value={filters.status ?? []} onChange={(v) => onFilter('status', v)} />
        <FilterChip label="Risk" options={RISK_OPTIONS} value={filters.risk_level ?? []} onChange={(v) => onFilter('risk_level', v)} />
        <FilterChip label="Verification" options={VERIFICATION_OPTIONS} value={filters.verification ?? []} onChange={(v) => onFilter('verification', v)} />
      </div>
      <ListNotice list={list} noun="actions" />
      {list.isPending && <LoadingState label="Loading actions" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {list.isSuccess && list.items.length === 0 && <EmptyState title="No actions match these filters" />}
      {list.items.length > 0 && (
        <div className="relative overflow-x-auto rounded-card border border-subtle bg-raised">
          <table className="w-full min-w-[1100px] text-left text-sm">
            <caption className="sr-only">Response actions</caption>
            <thead className="border-b border-subtle text-xs text-secondary">
              <tr>
                <th scope="col" className="w-8 px-2 py-2">
                  <span className="sr-only">Details</span>
                </th>
                <th scope="col" className="px-3 py-2 font-medium">Created</th>
                <th scope="col" className="px-3 py-2 font-medium">Action</th>
                <th scope="col" className="px-3 py-2 font-medium">Target</th>
                <th scope="col" className="px-3 py-2 font-medium">Risk</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">Executed</th>
                <th scope="col" className="px-3 py-2 font-medium">Verification</th>
                <th scope="col" className="px-3 py-2 font-medium">Details</th>
                <th scope="col" className="px-3 py-2 font-medium">Alert</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Approval</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((a) => {
                const open = expanded === a.id;
                return (
                  <Fragment key={a.id}>
                    <tr className="border-b border-subtle align-top">
                      <td className="px-2 py-2">
                        <Button
                          size="sm"
                          variant="quiet"
                          aria-expanded={open}
                          aria-label={`${open ? 'Hide' : 'Show'} details of ${humanize(a.action_type)} on ${a.target}`}
                          onClick={() => setExpanded(open ? null : a.id)}
                          icon={open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />}
                        />
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-secondary">{formatDateTime(a.created_at)}</td>
                      <td className="px-3 py-2 text-fg">{humanize(a.action_type)}</td>
                      <td className="max-w-[16rem] break-all px-3 py-2 font-mono text-xs text-body">{a.target}</td>
                      <td className="px-3 py-2">
                        <RiskBadge value={a.risk_level} />
                      </td>
                      <td className="px-3 py-2">
                        <StatusBadge value={a.status} />
                        {a.rollback_of && <p className="mt-1 text-xs text-muted">rollback of {shortId(a.rollback_of)}</p>}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-secondary">{a.executed_at ? formatDateTime(a.executed_at) : '-'}</td>
                      <td className="px-3 py-2">
                        <VerificationBadge value={a.verification} detail={a.verification_detail} />
                      </td>
                      <td className="max-w-[18rem] px-3 py-2 text-xs text-secondary">
                        {a.blocked_reason && <p className="text-danger-fg">Blocked: {describeBlockedReason(a.blocked_reason)}</p>}
                        {a.approved_by && (
                          <p>
                            By {shortId(a.approved_by)} {a.approved_at ? formatDateTime(a.approved_at) : ''}
                          </p>
                        )}
                        {a.connector && <p>Connector: {a.connector}</p>}
                        {a.status === 'dry_run' && <p>Recorded only (dry run); nothing was executed.</p>}
                      </td>
                      <td className="px-3 py-2">
                        <Button size="sm" variant="quiet" onClick={() => onOpenAlert(a.alert_id)} aria-label={`Open alert ${a.alert_id}`}>
                          {shortId(a.alert_id)}
                        </Button>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-right">
                        <ApprovalCell action={a} onDecide={onDecide} />
                      </td>
                    </tr>
                    {open && (
                      <tr className="border-b border-subtle bg-canvas/40">
                        <td colSpan={11} className="px-6 py-3">
                          <ActionDetails action={a} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <div className="flex justify-center">
          <Button onClick={() => void list.fetchNextPage()} busy={list.isFetchingNextPage}>
            Load more
          </Button>
        </div>
      )}
    </section>
  );
}
