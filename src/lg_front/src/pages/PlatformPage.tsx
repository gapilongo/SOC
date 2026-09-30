/**
 * MSSP console (platform admins): every tenant with its activity and quotas,
 * suspension, the cross-tenant escalation queue, monthly usage for invoicing
 * and tenant provisioning. Every read here is audited in the admin's home
 * tenant; opening a tenant switches the acting tenant (X-Tenant-ID).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, LogIn, RefreshCw } from 'lucide-react';
import { useMemo, useState, type FormEvent, type KeyboardEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { endpoints } from '../api/endpoints';
import {
  QUOTA_KEYS,
  TENANT_PROFILES,
  type PlatformEscalationOut,
  type QuotaKey,
  type Quotas,
  type TenantCreatedOut,
  type TenantCreateIn,
  type TenantSummaryOut,
  type TenantUsageOut,
} from '../api/types';
import { useApi, useAuth } from '../auth/AuthContext';
import { Badge, SeverityBadge, StatusBadge } from '../components/Badge';
import { ConfirmDialog, Modal } from '../components/Dialog';
import { ListNotice } from '../components/ListNotice';
import { useToast } from '../components/Toast';
import { PLATFORM_TENANTS_KEY, filterTenants, useSwitchTenant } from '../components/TenantSwitcher';
import { Button, Card, EmptyState, ErrorMessage, LoadingState, PageHeader, SelectField, TextField, cx } from '../components/ui';
import { downloadCsv, toCsv, type CsvColumn } from '../lib/csv';
import { formatCountdown, formatInt, formatRelative, formatUsd } from '../lib/format';
import { useKeysetList } from '../lib/pagination';
import { useNow } from '../lib/useNow';
import { usePollInterval } from '../lib/visibility';
import { TenantDataCard } from './platform/TenantDataCard';

const TABS = [
  { id: 'tenants', label: 'Tenants' },
  { id: 'escalations', label: 'Escalation queue' },
  { id: 'usage', label: 'Usage' },
  { id: 'create', label: 'Create tenant' },
  { id: 'data', label: 'Tenant data' },
] as const;
type TabId = (typeof TABS)[number]['id'];

const QUOTA_LABELS: Record<QuotaKey, string> = {
  max_alerts_per_day: 'Alerts per day',
  max_sources: 'Sources',
  max_users: 'Active users',
};

const PROFILE_HELP: Record<string, string> = {
  conservative: 'every action needs approval; high and critical risk never run',
  balanced: 'low-risk actions run on their own, the rest need approval',
  autonomous: 'low and medium risk run on their own; high and critical need approval',
};

/** "12 / 50" style usage against a quota, or just the count when unlimited. */
export function quotaText(used: number, limit: number | null): string {
  return limit === null ? formatInt(used) : `${formatInt(used)} / ${formatInt(limit)}`;
}

function quotaTone(used: number, limit: number | null): string {
  if (limit === null) return 'text-slate-100';
  if (used >= limit) return 'text-red-300 font-medium';
  if (used >= limit * 0.8) return 'text-amber-300';
  return 'text-slate-100';
}

function currentMonth(now: Date = new Date()): string {
  return now.toISOString().slice(0, 7);
}

// ------------------------------------------------------------------ tenants

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
      client.setQueryData<TenantSummaryOut[]>(PLATFORM_TENANTS_KEY, (rows) => rows?.map((r) => (r.id === updated.id ? updated : r)));
      void client.invalidateQueries({ queryKey: PLATFORM_TENANTS_KEY });
      toast.success(`Tenant ${updated.name} updated.`);
      onDone?.();
    },
  });
}

function QuotaDialog({ tenant, onClose }: { tenant: TenantSummaryOut; onClose: () => void }) {
  const [values, setValues] = useState<Record<QuotaKey, string>>(() => {
    const init = {} as Record<QuotaKey, string>;
    for (const key of QUOTA_KEYS) init[key] = tenant.quotas[key] === null ? '' : String(tenant.quotas[key]);
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
            hint={`In use: ${formatInt(tenant.quota_usage[key].used)}${key === 'max_alerts_per_day' ? ' today (UTC)' : ''}`}
          />
        ))}
      </form>
    </Modal>
  );
}

function TenantsTab() {
  const api = useApi();
  const { principal } = useAuth();
  const navigate = useNavigate();
  const switchTo = useSwitchTenant();
  const interval = usePollInterval(60_000);
  const q = useQuery({ queryKey: PLATFORM_TENANTS_KEY, queryFn: ({ signal }) => endpoints.platformTenants(api, signal), refetchInterval: interval });
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
            <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
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
            <tbody className="divide-y divide-slate-800">
              {rows.map((t) => {
                const s = t.stats;
                const u = t.quota_usage;
                return (
                  <tr key={t.id} className="align-top">
                    <th scope="row" className="py-2 pr-3 text-left font-normal">
                      <div className="font-medium text-white">{t.name}</div>
                      <div className="font-mono text-xs text-slate-400">
                        {t.id}
                        {t.id === home ? ' (home)' : ''}
                      </div>
                    </th>
                    <td className="py-2 pr-3">
                      <Badge tone={t.status === 'active' ? 'good' : 'bad'}>{t.status}</Badge>
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{formatInt(s.alerts_24h)}</td>
                    <td className={cx('py-2 pr-3 text-right tabular-nums', quotaTone(u.max_alerts_per_day.used, u.max_alerts_per_day.limit))}>
                      {quotaText(u.max_alerts_per_day.used, u.max_alerts_per_day.limit)}
                    </td>
                    <td className="py-2 pr-3 text-slate-300" title={s.last_ingest_at ?? undefined}>
                      {s.last_ingest_at ? formatRelative(s.last_ingest_at, now) : 'never'}
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">
                      {formatInt(s.open_escalations)}
                      {s.overdue_escalations > 0 && <span className="ml-1 text-red-300">({formatInt(s.overdue_escalations)} overdue)</span>}
                    </td>
                    <td className={cx('py-2 pr-3 text-right tabular-nums', s.sla_breaches_24h > 0 && 'text-amber-300')}>{formatInt(s.sla_breaches_24h)}</td>
                    <td className="py-2 pr-3 text-right tabular-nums">{formatUsd(s.llm_cost_mtd_usd)}</td>
                    <td className={cx('py-2 pr-3 text-right tabular-nums', quotaTone(u.max_users.used, u.max_users.limit))}>
                      {quotaText(u.max_users.used, u.max_users.limit)}
                    </td>
                    <td className={cx('py-2 pr-3 text-right tabular-nums', quotaTone(u.max_sources.used, u.max_sources.limit))}>
                      {quotaText(u.max_sources.used, u.max_sources.limit)}
                    </td>
                    <td className="py-2">
                      <div className="flex flex-wrap justify-end gap-1">
                        <Button size="sm" variant="ghost" onClick={() => open(t)} icon={<LogIn className="h-3.5 w-3.5" aria-hidden="true" />} aria-label={`Open tenant ${t.name}`}>
                          Open
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setQuotaFor(t)} aria-label={`Edit quotas of ${t.name}`}>
                          Quotas
                        </Button>
                        {t.id !== home && (
                          <Button size="sm" variant={t.status === 'active' ? 'danger' : 'secondary'} onClick={() => setStatusFor(t)}>
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

// -------------------------------------------------------------- escalations

function EscalationsTab() {
  const api = useApi();
  const navigate = useNavigate();
  const switchTo = useSwitchTenant();
  const now = useNow(1_000);
  const interval = usePollInterval(30_000);
  const [tenant, setTenant] = useState('');
  const tenants = useQuery({ queryKey: PLATFORM_TENANTS_KEY, queryFn: ({ signal }) => endpoints.platformTenants(api, signal), staleTime: 60_000 });
  const list = useKeysetList({
    queryKey: ['platform-escalations', tenant],
    fetchPage: (cursor, signal) => endpoints.platformEscalations(api, tenant || undefined, cursor, signal),
    itemKey: (e: PlatformEscalationOut) => `${e.tenant_id}:${e.id}`,
    refetchInterval: interval,
  });
  const open = (e: PlatformEscalationOut) => {
    if (switchTo(e.tenant_id, e.tenant_name)) navigate('/escalations');
  };
  return (
    <Card
      title="Open escalations across tenants"
      actions={
        <SelectField label="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} wrapperClassName="w-56">
          <option value="">All tenants</option>
          {(tenants.data ?? []).map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} ({t.id})
            </option>
          ))}
        </SelectField>
      }
    >
      <p className="mb-3 text-sm text-slate-300">
        Soonest SLA deadline first. Opening one switches to its tenant; deciding it needs an account in that tenant.
      </p>
      <ListNotice list={list} noun="escalations" />
      {list.isPending && <LoadingState label="Loading escalations" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {!list.isPending && list.items.length === 0 && !list.isError && <EmptyState title="No open escalations in any tenant." />}
      {list.items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <caption className="sr-only">Open and claimed escalations of every tenant</caption>
            <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="py-2 pr-3">SLA</th>
                <th scope="col" className="py-2 pr-3">Tenant</th>
                <th scope="col" className="py-2 pr-3">Alert</th>
                <th scope="col" className="py-2 pr-3">Level</th>
                <th scope="col" className="py-2 pr-3">Status</th>
                <th scope="col" className="py-2 pr-3">Reason</th>
                <th scope="col" className="py-2"><span className="sr-only">Open</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {list.items.map((e) => {
                const due = formatCountdown(e.sla_deadline, now);
                return (
                  <tr key={`${e.tenant_id}:${e.id}`} className="hover:bg-slate-800/40">
                    <td className={cx('py-2 pr-3 whitespace-nowrap tabular-nums', due.overdue ? 'text-red-300' : 'text-slate-200')}>{due.text}</td>
                    <td className="py-2 pr-3">
                      <div className="text-slate-100">{e.tenant_name}</div>
                      <div className="font-mono text-xs text-slate-400">{e.tenant_id}</div>
                      {e.tenant_status !== 'active' && <Badge tone="bad">{e.tenant_status}</Badge>}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        <SeverityBadge value={e.alert_severity} />
                        <button type="button" className="text-left text-slate-100 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400" onClick={() => open(e)}>
                          {e.alert_title ?? e.alert_id}
                        </button>
                      </div>
                    </td>
                    <td className="py-2 pr-3">{e.level}</td>
                    <td className="py-2 pr-3">
                      <StatusBadge value={e.status} />
                    </td>
                    <td className="max-w-xs truncate py-2 pr-3 text-slate-300" title={e.reason}>
                      {e.reason}
                    </td>
                    <td className="py-2 text-right">
                      <Button size="sm" variant="ghost" onClick={() => open(e)} aria-label={`Open escalation in tenant ${e.tenant_name}`}>
                        Open
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <div className="mt-3 flex justify-center">
          <Button size="sm" busy={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            Load more
          </Button>
        </div>
      )}
    </Card>
  );
}

// -------------------------------------------------------------------- usage

export const USAGE_CSV: CsvColumn<TenantUsageOut>[] = [
  { header: 'tenant_id', value: (r) => r.tenant_id },
  { header: 'tenant_name', value: (r) => r.tenant_name },
  { header: 'tenant_status', value: (r) => r.tenant_status },
  { header: 'alerts_ingested', value: (r) => r.alerts_ingested },
  { header: 'alerts_processed', value: (r) => r.alerts_processed },
  { header: 'alerts_rejected_quota', value: (r) => r.alerts_rejected_quota },
  { header: 'llm_calls', value: (r) => r.llm_calls },
  { header: 'llm_input_tokens', value: (r) => r.llm_input_tokens },
  { header: 'llm_output_tokens', value: (r) => r.llm_output_tokens },
  { header: 'llm_cost_usd', value: (r) => Number(r.llm_cost_usd) },
  { header: 'active_users', value: (r) => r.active_users },
  { header: 'users', value: (r) => r.users },
  { header: 'sources', value: (r) => r.sources },
];

function UsageTab() {
  const api = useApi();
  const [month, setMonth] = useState(currentMonth());
  const valid = /^\d{4}-(0[1-9]|1[0-2])$/.test(month);
  const q = useQuery({ queryKey: ['platform-usage', month], queryFn: ({ signal }) => endpoints.platformUsage(api, month, signal), enabled: valid });
  const rows = q.data?.tenants ?? [];
  return (
    <Card
      title="Usage for invoicing"
      actions={
        <>
          <TextField label="Month (UTC)" type="month" value={month} onChange={(e) => setMonth(e.target.value)} wrapperClassName="w-44" />
          <Button
            className="self-end"
            size="sm"
            disabled={!q.data}
            onClick={() => q.data && downloadCsv(`lg-sotf-usage-${q.data.month}.csv`, toCsv(USAGE_CSV, rows))}
            icon={<Download className="h-3.5 w-3.5" aria-hidden="true" />}
          >
            Export CSV
          </Button>
        </>
      }
    >
      <p className="mb-3 text-sm text-slate-300">
        Alerts stored and triaged per tenant (sample alerts excluded), LLM tokens and cost, and active users (accounts that signed in
        or acted in the month). Counters survive alert retention, so past months stay billable.
      </p>
      {!valid && <p className="text-sm text-red-300">Pick a month.</p>}
      {q.isPending && valid && <LoadingState label="Loading usage" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <caption className="sr-only">Usage per tenant for {q.data.month}</caption>
            <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="py-2 pr-3">Tenant</th>
                <th scope="col" className="py-2 pr-3 text-right">Alerts ingested</th>
                <th scope="col" className="py-2 pr-3 text-right">Alerts processed</th>
                <th scope="col" className="py-2 pr-3 text-right">Refused (quota)</th>
                <th scope="col" className="py-2 pr-3 text-right">LLM tokens</th>
                <th scope="col" className="py-2 pr-3 text-right">LLM cost</th>
                <th scope="col" className="py-2 pr-3 text-right">Active users</th>
                <th scope="col" className="py-2 pr-3 text-right">Users</th>
                <th scope="col" className="py-2 pr-3 text-right">Sources</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {rows.map((r) => (
                <tr key={r.tenant_id}>
                  <th scope="row" className="py-2 pr-3 text-left font-normal">
                    <span className="text-slate-100">{r.tenant_name}</span> <span className="font-mono text-xs text-slate-400">{r.tenant_id}</span>
                  </th>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.alerts_ingested)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.alerts_processed)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.alerts_rejected_quota)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.llm_input_tokens + r.llm_output_tokens)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatUsd(r.llm_cost_usd)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.active_users)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.users)}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{formatInt(r.sources)}</td>
                </tr>
              ))}
            </tbody>
            <tfoot className="border-t border-slate-700 font-medium">
              <tr>
                <th scope="row" className="py-2 pr-3 text-left">Total</th>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_ingested))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_processed))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_rejected_quota))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">
                  {formatInt(Number(q.data.totals.llm_input_tokens) + Number(q.data.totals.llm_output_tokens))}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatUsd(q.data.totals.llm_cost_usd)}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.active_users))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.users))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.sources))}</td>
              </tr>
            </tfoot>
          </table>
        </div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------------- create

/** The template select value ('' | 'profile:<name>' | 'copy:<tenant id>') as request fields. */
export function templateFields(template: string): Pick<TenantCreateIn, 'profile' | 'copy_settings_from'> {
  if (template.startsWith('profile:')) return { profile: template.slice(8) as TenantCreateIn['profile'] };
  if (template.startsWith('copy:')) return { copy_settings_from: template.slice(5) };
  return {};
}

function CreateTenantTab() {
  const api = useApi();
  const client = useQueryClient();
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [template, setTemplate] = useState('profile:balanced');
  const [created, setCreated] = useState<TenantCreatedOut | null>(null);
  const tenants = useQuery({ queryKey: PLATFORM_TENANTS_KEY, queryFn: ({ signal }) => endpoints.platformTenants(api, signal), staleTime: 60_000 });
  const m = useMutation({
    mutationFn: () =>
      endpoints.createTenant(api, {
        id: id.trim(),
        name: name.trim(),
        admin_email: adminEmail.trim() || null,
        admin_password: adminPassword || null,
        ...templateFields(template),
      }),
    onSuccess: (t) => {
      setCreated(t);
      setId('');
      setName('');
      setAdminEmail('');
      setAdminPassword('');
      void client.invalidateQueries({ queryKey: PLATFORM_TENANTS_KEY });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    m.mutate();
  };
  return (
    <Card title="Create tenant" className="max-w-3xl">
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {m.isError && <ErrorMessage error={m.error} compact />}
        {created && (
          <p role="status" className="rounded-md border border-emerald-700 bg-emerald-950 px-3 py-2 text-sm text-emerald-100">
            Tenant {created.name} ({created.id}) created{created.admin ? ` with admin ${created.admin.email}` : ''}
            {created.settings_keys && created.settings_keys.length > 0 ? `; seeded settings: ${created.settings_keys.join(', ')}` : ''}.
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField label="Tenant id" required pattern="[a-z0-9][a-z0-9_-]{1,62}" hint="Lowercase letters, digits, - and _" value={id} onChange={(e) => setId(e.target.value)} />
          <TextField label="Display name" required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <TextField label="First admin email (optional)" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} />
          <TextField
            label="First admin password (optional)"
            type="password"
            autoComplete="new-password"
            value={adminPassword}
            onChange={(e) => setAdminPassword(e.target.value)}
            hint="Leave empty for a single sign-on admin."
          />
          <SelectField
            label="Initial settings"
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            wrapperClassName="sm:col-span-2"
            hint="Profiles seed autonomy, response and review settings; actions stay in dry run until a connector is configured. Copying takes another tenant's policy, never its secrets, destinations or protected assets."
          >
            <option value="">Installation defaults</option>
            {TENANT_PROFILES.map((p) => (
              <option key={p} value={`profile:${p}`}>
                Profile: {p} ({PROFILE_HELP[p]})
              </option>
            ))}
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={`copy:${t.id}`}>
                Copy policy from {t.name} ({t.id})
              </option>
            ))}
          </SelectField>
        </div>
        <Button type="submit" variant="primary" busy={m.isPending}>
          Create tenant
        </Button>
      </form>
    </Card>
  );
}

// --------------------------------------------------------------------- page

export default function PlatformPage() {
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  const tab: TabId = TABS.some((t) => t.id === requested) ? (requested as TabId) : 'tenants';
  const select = (id: TabId) => setParams({ tab: id }, { replace: true });
  const onTabKey = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const next = TABS[(index + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };
  return (
    <>
      <PageHeader
        title="MSSP console"
        description="Every tenant at a glance: activity, SLA risk, quotas and usage. Opening a tenant switches the header's tenant context; every request is recorded in that tenant's audit log."
      />
      <div role="tablist" aria-label="MSSP console" className="mb-4 flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map((t, i) => (
          <button
            key={t.id}
            id={`tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => select(t.id)}
            onKeyDown={(e) => onTabKey(e, i)}
            className={cx(
              '-mb-px border-b-2 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400',
              tab === t.id ? 'border-sky-400 font-medium text-white' : 'border-transparent text-slate-300 hover:text-white',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'tenants' && <TenantsTab />}
        {tab === 'escalations' && <EscalationsTab />}
        {tab === 'usage' && <UsageTab />}
        {tab === 'create' && <CreateTenantTab />}
        {tab === 'data' && <TenantDataCard />}
      </div>
    </>
  );
}
