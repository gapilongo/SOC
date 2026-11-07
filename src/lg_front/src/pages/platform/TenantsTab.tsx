/** MSSP console, Tenants tab: every tenant with its activity and quotas, suspension and opening a tenant. */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { LogIn, RefreshCw } from 'lucide-react';
import { useMemo, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { endpoints } from '../../api/endpoints';
import { afterTenantChange } from '../../api/invalidate';
import { qk } from '../../api/queryKeys';
import { QUOTA_KEYS, type QuotaKey, type Quotas, type TenantSummaryOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { ConfirmDialog, Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Card, EmptyState, ErrorMessage, LoadingState, TextField, cx } from '../../components/ui';
import { formatInt, formatRelative, formatUsd } from '../../lib/format';
import { usePollInterval } from '../../lib/visibility';
import { filterTenants, usePlatformTenants, useSwitchTenant } from './TenantSwitcher';

const QUOTA_LABELS: Record<QuotaKey, string> = {
  max_alerts_per_day: 'Alerts per day',
  max_sources: 'Sources',
  max_users: 'Active users',
};

/** "12 / 50" style usage against a quota, or just the count when unlimited. */
export function quotaText(used: number, limit: number | null): string {
  return limit === null ? formatInt(used) : `${formatInt(used)} / ${formatInt(limit)}`;
}

/** Usage against one quota in the tenants table; "-" when the API does not report that quota. */
function QuotaCell({ usage }: { usage: { used: number; limit: number | null } | undefined }) {
  return (
    <td className={cx('py-2 pr-3 text-right tabular-nums', usage && quotaTone(usage.used, usage.limit))}>
      {usage ? quotaText(usage.used, usage.limit) : '-'}
    </td>
  );
}

function quotaTone(used: number, limit: number | null): string {
  if (limit === null) return 'text-fg';
  if (used >= limit) return 'text-danger-fg font-medium';
  if (used >= limit * 0.8) return 'text-warn-fg';
  return 'text-fg';
}

/** Quota form values ('' = unlimited) to the API body; an Error names the first invalid field. */
export function quotasFromForm(values: Record<QuotaKey, string>): Quotas | Error {
  const out = {} as Quotas;
  for (const key of QUOTA_KEYS) {
    const text = values[key].trim();
    if (!text) {
      out[key] = null;
      continue;
    }
    const n = Number(text);
    if (!Number.isInteger(n) || n < 0) return new Error(`${QUOTA_LABELS[key]} must be a whole number (empty = unlimited).`);
    out[key] = n;
  }
  return out;
}

function useUpdateTenant(onDone?: () => void) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof endpoints.updateTenant>[2] }) => endpoints.updateTenant(api, id, body),
    onSuccess: (updated) => {
      client.setQueryData<TenantSummaryOut[]>(qk.platformTenants.all, (rows) => rows?.map((r) => (r.id === updated.id ? updated : r)));
      void afterTenantChange(client);
      toast.success(`Tenant ${updated.name} updated.`);
      onDone?.();
    },
  });
}

function QuotaDialog({ tenant, onClose }: { tenant: TenantSummaryOut; onClose: () => void }) {
  const [values, setValues] = useState<Record<QuotaKey, string>>(() => {
    const init = {} as Record<QuotaKey, string>;
    for (const key of QUOTA_KEYS) {
      const limit = tenant.quotas[key];
      init[key] = limit === null || limit === undefined ? '' : String(limit);
    }
    return init;
  });
  const [localError, setLocalError] = useState<Error | null>(null);
  const update = useUpdateTenant(onClose);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    const quotas = quotasFromForm(values);
    if (quotas instanceof Error) {
      setLocalError(quotas);
      return;
    }
    update.mutate({ id: tenant.id, body: { quotas } });
  };
  return (
    <Modal
      open
      onClose={onClose}
      title={`Quotas for ${tenant.name}`}
      description="Empty means unlimited. Ingest over the daily alert quota is refused until 00:00 UTC; creating sources or users over theirs is refused."
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="quota-form" busy={update.isPending}>
            Save quotas
          </Button>
        </>
      }
    >
      <form id="quota-form" onSubmit={submit} className="space-y-3">
        {(localError ?? update.error) ? <ErrorMessage error={localError ?? update.error} compact /> : null}
        {QUOTA_KEYS.map((key) => (
          <TextField
            key={key}
            label={QUOTA_LABELS[key]}
            type="number"
            min={0}
            value={values[key]}
            onChange={(e) => setValues({ ...values, [key]: e.target.value })}
            hint={`In use: ${formatInt(tenant.quota_usage[key]?.used)}${key === 'max_alerts_per_day' ? ' today (UTC)' : ''}`}
          />
        ))}
      </form>
    </Modal>
  );
}

export function TenantsTab() {
  const { principal } = useAuth();
  const navigate = useNavigate();
  const switchTo = useSwitchTenant();
  const interval = usePollInterval(60_000);
  const q = usePlatformTenants({ refetchInterval: interval });
  const [search, setSearch] = useState('');
  const [quotaFor, setQuotaFor] = useState<TenantSummaryOut | null>(null);
  const [statusFor, setStatusFor] = useState<TenantSummaryOut | null>(null);
  const update = useUpdateTenant(() => setStatusFor(null));
  const home = principal?.homeTenantId ?? '';
  const rows = useMemo(() => filterTenants(q.data ?? [], search, home), [q.data, search, home]);
  const now = Date.now();

  const open = (t: TenantSummaryOut) => {
    if (switchTo(t.id, t.name)) navigate('/');
  };
  const suspending = statusFor?.status === 'active';

  return (
    <Card
      title="Tenants"
      actions={
        <>
          <TextField label="Filter" placeholder="Name or id" value={search} onChange={(e) => setSearch(e.target.value)} wrapperClassName="w-56" />
          <Button className="self-end" size="sm" onClick={() => void q.refetch()} busy={q.isFetching} icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />}>
            Refresh
          </Button>
        </>
      }
    >
      {q.isPending && <LoadingState label="Loading tenants" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && rows.length === 0 && <EmptyState title="No tenant matches the filter." />}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1100px] text-sm">
            <caption className="sr-only">Tenants with activity, quotas and status</caption>
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th scope="col" className="py-2 pr-3">Tenant</th>
                <th scope="col" className="py-2 pr-3">Status</th>
                <th scope="col" className="py-2 pr-3 text-right">Alerts 24 h</th>
                <th scope="col" className="py-2 pr-3 text-right">Today / quota</th>
                <th scope="col" className="py-2 pr-3">Last ingest</th>
                <th scope="col" className="py-2 pr-3 text-right">Open escalations</th>
                <th scope="col" className="py-2 pr-3 text-right">SLA breaches 24 h</th>
                <th scope="col" className="py-2 pr-3 text-right">LLM cost (month)</th>
                <th scope="col" className="py-2 pr-3 text-right">Users</th>
                <th scope="col" className="py-2 pr-3 text-right">Sources</th>
                <th scope="col" className="py-2"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-subtle">
              {rows.map((t) => {
                const s = t.stats;
                const u = t.quota_usage;
                return (
                  <tr key={t.id} className="align-top">
                    <th scope="row" className="py-2 pr-3 text-left font-normal">
                      <div className="font-medium text-fg">{t.name}</div>
                      <div className="font-mono text-xs text-muted">
                        {t.id}
                        {t.id === home ? ' (home)' : ''}
                      </div>
                    </th>
                    <td className="py-2 pr-3">
                      <Badge tone={t.status === 'active' ? 'good' : 'bad'}>{t.status}</Badge>
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{formatInt(s.alerts_24h)}</td>
                    <QuotaCell usage={u.max_alerts_per_day} />
                    <td className="py-2 pr-3 text-secondary" title={s.last_ingest_at ?? undefined}>
                      {s.last_ingest_at ? formatRelative(s.last_ingest_at, now) : 'never'}
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">
                      {formatInt(s.open_escalations)}
                      {s.overdue_escalations > 0 && <span className="ml-1 text-danger-fg">({formatInt(s.overdue_escalations)} overdue)</span>}
                    </td>
                    <td className={cx('py-2 pr-3 text-right tabular-nums', s.sla_breaches_24h > 0 && 'text-warn-fg')}>{formatInt(s.sla_breaches_24h)}</td>
                    <td className="py-2 pr-3 text-right tabular-nums">{formatUsd(s.llm_cost_mtd_usd)}</td>
                    <QuotaCell usage={u.max_users} />
                    <QuotaCell usage={u.max_sources} />
                    <td className="py-2">
                      <div className="flex flex-wrap justify-end gap-1">
                        <Button size="sm" variant="quiet" onClick={() => open(t)} icon={<LogIn className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Open tenant ${t.name}`}>
                          Open
                        </Button>
                        <Button size="sm" variant="quiet" onClick={() => setQuotaFor(t)} aria-label={`Edit quotas of ${t.name}`}>
                          Quotas
                        </Button>
                        {t.id !== home && (
                          <Button size="sm" variant={t.status === 'active' ? 'destructive' : 'secondary'} onClick={() => setStatusFor(t)}>
                            {t.status === 'active' ? 'Suspend' : 'Reactivate'}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {quotaFor && <QuotaDialog tenant={quotaFor} onClose={() => setQuotaFor(null)} />}
      <ConfirmDialog
        open={statusFor !== null}
        title={suspending ? `Suspend ${statusFor?.name ?? ''}?` : `Reactivate ${statusFor?.name ?? ''}?`}
        confirmLabel={suspending ? 'Suspend tenant' : 'Reactivate tenant'}
        danger={suspending}
        busy={update.isPending}
        onCancel={() => {
          update.reset();
          setStatusFor(null);
        }}
        onConfirm={() => statusFor && update.mutate({ id: statusFor.id, body: { status: suspending ? 'suspended' : 'active' } })}
      >
        {update.isError && <ErrorMessage error={update.error} compact />}
        {suspending ? (
          <p>
            Its users and API keys are refused at once, ingestion stops (pull sources pause, pushes get 403) and queued alerts wait
            unprocessed. Nothing is deleted; reactivating resumes the queued work.
          </p>
        ) : (
          <p>Its users and API keys work again, sources resume and queued alerts are handed back to the workers.</p>
        )}
      </ConfirmDialog>
    </Card>
  );
}
