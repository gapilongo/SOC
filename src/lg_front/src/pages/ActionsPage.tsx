import { useQueryClient } from '@tanstack/react-query';
import { Check, Download, X } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { endpoints, type ActionFilters } from '../api/endpoints';
import { ACTION_STATUSES, RISK_LEVELS, type ActionOut } from '../api/types';
import { useApi, useAuth } from '../auth/AuthContext';
import { approvalRoleFor, can, decisionBlockedReason } from '../auth/roles';
import { RiskBadge, StatusBadge } from '../components/Badge';
import { Modal } from '../components/Dialog';
import { useToast } from '../components/Toast';
import { Button, Checkbox, EmptyState, ErrorMessage, LoadingState, PageHeader, ToggleGroup } from '../components/ui';
import { csvFilename, downloadCsv, toCsv, type CsvColumn } from '../lib/csv';
import { formatDateTime, humanize, shortId } from '../lib/format';
import { describeBlockedReason } from '../lib/guardrails';
import { ListNotice } from '../components/ListNotice';
import { useKeysetList } from '../lib/pagination';
import { usePollInterval } from '../lib/visibility';
import { AlertDrawer } from './alerts/AlertDrawer';

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
];

type Pending = { action: ActionOut; verb: 'approve' | 'reject' };

function ApprovalDialog({ pending, onClose }: { pending: Pending; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [rejectRemaining, setRejectRemaining] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const { action, verb } = pending;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = verb === 'approve' ? await endpoints.approve(api, action.id, rejectRemaining) : await endpoints.reject(api, action.id, rejectRemaining);
      toast.success(`${verb === 'approve' ? 'Approved' : 'Rejected'} ${action.action_type} on ${action.target}.${out.resumes_enqueued ? ' The alert workflow resumed.' : ''}`);
      void client.invalidateQueries({ queryKey: ['actions'] });
      void client.invalidateQueries({ queryKey: ['alerts'] });
      onClose();
    } catch (err) {
      setError(err);
      void client.invalidateQueries({ queryKey: ['actions'] });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      title={`${verb === 'approve' ? 'Approve' : 'Reject'} ${humanize(action.action_type)}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={verb === 'approve' ? 'primary' : 'danger'} onClick={submit} busy={busy}>
            {verb === 'approve' ? 'Approve action' : 'Reject action'}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-slate-200">
        <p>
          <span className="text-slate-400">Target: </span>
          <code className="break-all">{action.target}</code>
        </p>
        <p className="flex items-center gap-2">
          <RiskBadge value={action.risk_level} /> for alert {shortId(action.alert_id)}
        </p>
        {verb === 'approve' && (
          <p className="text-slate-300">
            Approving this action only; the alert's other pending actions stay pending unless you reject them below.
          </p>
        )}
        <Checkbox
          label="Reject the alert's other pending actions"
          checked={rejectRemaining}
          onChange={(e) => setRejectRemaining(e.target.checked)}
        />
        {error !== null && <ErrorMessage error={error} compact />}
      </div>
    </Modal>
  );
}

export default function ActionsPage() {
  const api = useApi();
  const { principal } = useAuth();
  const [params, setParams] = useSearchParams();
  const status = params.getAll('status').filter(Boolean);
  const risk = params.getAll('risk_level').filter(Boolean);
  const filters: ActionFilters = { status: status.length ? status : undefined, risk_level: risk.length ? risk : undefined };
  const [pending, setPending] = useState<Pending | null>(null);
  const [alertId, setAlertId] = useState<string | null>(null);
  const interval = usePollInterval(30_000);
  const blocked = decisionBlockedReason(principal);

  const list = useKeysetList({
    queryKey: ['actions', filters],
    fetchPage: (cursor, signal) => endpoints.actions(api, filters, cursor, signal),
    itemKey: (a: ActionOut) => a.id,
    refetchInterval: interval,
  });

  const setMulti = (key: string, values: string[]) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(key);
        for (const v of values) next.append(key, v);
        return next;
      },
      { replace: true },
    );

  return (
    <>
      <PageHeader
        title="Actions and approvals"
        description="The response action ledger. Analysts approve low and medium risk actions; high and critical risk need an admin to approve, while analysts may reject at any risk. Guardrails can block an action regardless of approval."
        actions={
          <Button onClick={() => downloadCsv(csvFilename('actions'), toCsv(CSV, list.items))} disabled={list.items.length === 0} icon={<Download className="h-4 w-4" aria-hidden="true" />}>
            Export CSV
          </Button>
        }
      />
      <section aria-label="Filters" className="mb-4 flex flex-wrap gap-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ToggleGroup label="Status" options={ACTION_STATUSES} value={status} onChange={(v) => setMulti('status', v)} />
        <ToggleGroup label="Risk" options={RISK_LEVELS} value={risk} onChange={(v) => setMulti('risk_level', v)} />
      </section>
      <ListNotice list={list} noun="actions" />
      {list.isPending && <LoadingState label="Loading actions" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {list.isSuccess && list.items.length === 0 && <EmptyState title="No actions match these filters" />}
      {list.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
          <table className="w-full min-w-[960px] text-left text-sm">
            <caption className="sr-only">Response actions</caption>
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-3 py-2">Created</th>
                <th scope="col" className="px-3 py-2">Action</th>
                <th scope="col" className="px-3 py-2">Target</th>
                <th scope="col" className="px-3 py-2">Risk</th>
                <th scope="col" className="px-3 py-2">Status</th>
                <th scope="col" className="px-3 py-2">Details</th>
                <th scope="col" className="px-3 py-2">Alert</th>
                <th scope="col" className="px-3 py-2 text-right">Approval</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((a) => {
                const waiting = a.status === 'awaiting_approval';
                const allowed = can.approve(principal, a.risk_level);
                const rejectable = can.reject(principal);
                const needed = approvalRoleFor(a.risk_level);
                const why = blocked ?? (needed === 'admin' ? 'Approving high and critical risk actions needs an admin.' : undefined);
                return (
                  <tr key={a.id} className="border-b border-slate-800/70 align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-slate-300">{formatDateTime(a.created_at)}</td>
                    <td className="px-3 py-2 text-slate-100">{humanize(a.action_type)}</td>
                    <td className="max-w-[16rem] break-all px-3 py-2 font-mono text-xs text-slate-200">{a.target}</td>
                    <td className="px-3 py-2">
                      <RiskBadge value={a.risk_level} />
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge value={a.status} />
                    </td>
                    <td className="max-w-[18rem] px-3 py-2 text-xs text-slate-300">
                      {a.blocked_reason && (
                        <p className="text-orange-200">
                          Blocked: {describeBlockedReason(a.blocked_reason)}
                        </p>
                      )}
                      {a.approved_by && <p>By {shortId(a.approved_by)} {a.approved_at ? formatDateTime(a.approved_at) : ''}</p>}
                      {a.connector && <p>Connector: {a.connector}</p>}
                      {a.status === 'dry_run' && <p>Recorded only (dry run); nothing was executed.</p>}
                    </td>
                    <td className="px-3 py-2">
                      <Button size="sm" variant="ghost" onClick={() => setAlertId(a.alert_id)} aria-label={`Open alert ${a.alert_id}`}>
                        {shortId(a.alert_id)}
                      </Button>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      {waiting ? (
                        allowed || rejectable ? (
                          <div className="flex flex-col items-end gap-1">
                            <div className="flex justify-end gap-1.5">
                              {allowed && (
                                <Button size="sm" variant="primary" onClick={() => setPending({ action: a, verb: 'approve' })} icon={<Check className="h-3.5 w-3.5" aria-hidden="true" />}>
                                  Approve
                                </Button>
                              )}
                              {rejectable && (
                                <Button size="sm" variant="danger" onClick={() => setPending({ action: a, verb: 'reject' })} icon={<X className="h-3.5 w-3.5" aria-hidden="true" />}>
                                  Reject
                                </Button>
                              )}
                            </div>
                            {!allowed && why && <span className="text-xs text-slate-400">{why}</span>}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">{why ?? 'Not permitted'}</span>
                        )
                      ) : (
                        <span className="text-xs text-slate-400">-</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <div className="mt-4 flex justify-center">
          <Button onClick={() => void list.fetchNextPage()} busy={list.isFetchingNextPage}>
            Load more
          </Button>
        </div>
      )}
      {pending && <ApprovalDialog pending={pending} onClose={() => setPending(null)} />}
      <AlertDrawer alertId={alertId} onClose={() => setAlertId(null)} />
    </>
  );
}
