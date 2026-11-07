/** MSSP console, Usage tab: monthly usage per tenant for invoicing. */

import { useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import type { TenantUsageOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Button, Card, ErrorMessage, LoadingState, TextField } from '../../components/ui';
import { downloadCsv, toCsv, type CsvColumn } from '../../lib/csv';
import { formatInt, formatUsd } from '../../lib/format';

/** The totals are an open document; the cost is a decimal string (or a number). */
function costOf(value: unknown): number | string | null {
  return typeof value === 'number' || typeof value === 'string' ? value : null;
}

function currentMonth(now: Date = new Date()): string {
  return now.toISOString().slice(0, 7);
}

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

export function UsageTab() {
  const api = useApi();
  const [month, setMonth] = useState(currentMonth());
  const valid = /^\d{4}-(0[1-9]|1[0-2])$/.test(month);
  const q = useQuery({ queryKey: qk.platformUsage.month(month), queryFn: ({ signal }) => endpoints.platformUsage(api, month, signal), enabled: valid });
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
      <p className="mb-3 text-sm text-secondary">
        Alerts stored and triaged per tenant (sample alerts excluded), LLM tokens and cost, and active users (accounts that signed in
        or acted in the month). Counters survive alert retention, so past months stay billable.
      </p>
      {!valid && <p className="text-sm text-danger-fg">Pick a month.</p>}
      {q.isPending && valid && <LoadingState label="Loading usage" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <caption className="sr-only">Usage per tenant for {q.data.month}</caption>
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
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
            <tbody className="divide-y divide-subtle">
              {rows.map((r) => (
                <tr key={r.tenant_id}>
                  <th scope="row" className="py-2 pr-3 text-left font-normal">
                    <span className="text-fg">{r.tenant_name}</span> <span className="font-mono text-xs text-muted">{r.tenant_id}</span>
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
            <tfoot className="border-t border-strong font-medium">
              <tr>
                <th scope="row" className="py-2 pr-3 text-left">Total</th>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_ingested))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_processed))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatInt(Number(q.data.totals.alerts_rejected_quota))}</td>
                <td className="py-2 pr-3 text-right tabular-nums">
                  {formatInt(Number(q.data.totals.llm_input_tokens) + Number(q.data.totals.llm_output_tokens))}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums">{formatUsd(costOf(q.data.totals.llm_cost_usd))}</td>
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
