/** MSSP console, Escalation queue tab: open escalations across tenants. */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { endpoints } from '../../../../api/endpoints';
import { qk } from '../../../../api/queryKeys';
import type { PlatformEscalationOut } from '../../../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Badge, SeverityBadge, StatusBadge } from '../../components/Badge';
import { ListNotice } from '../../../../components/ListNotice';
import { Button, Card, EmptyState, ErrorMessage, LoadingState, SelectField, cx } from '../../../../components/ui';
import { formatCountdown } from '../../../../lib/format';
import { useKeysetList } from '../../../../lib/pagination';
import { useNow } from '../../../../lib/useNow';
import { usePollInterval } from '../../../../lib/visibility';
import { usePlatformTenants, useSwitchTenant } from './TenantSwitcher';

export function EscalationsTab() {
  const api = useApi();
  const navigate = useNavigate();
  const switchTo = useSwitchTenant();
  const now = useNow(1_000);
  const interval = usePollInterval(30_000);
  const [tenant, setTenant] = useState('');
  const tenants = usePlatformTenants({ staleTime: 60_000 });
  const list = useKeysetList({
    queryKey: qk.platformEscalations.list(tenant),
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
      <p className="mb-3 text-sm text-secondary">
        Soonest SLA deadline first. Opening one switches to its tenant; deciding it needs an account in that tenant.
      </p>
      <ListNotice list={list} noun="escalations" />
      {list.isPending && <LoadingState label="Loading escalations" />}
      {list.isError && <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />}
      {!list.isPending && list.items.length === 0 && !list.isError && <EmptyState title="No open escalations in any tenant." />}
      {list.items.length > 0 && (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <caption className="sr-only">Open and claimed escalations of every tenant</caption>
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
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
            <tbody className="divide-y divide-subtle">
              {list.items.map((e) => {
                const due = formatCountdown(e.sla_deadline, now);
                return (
                  <tr key={`${e.tenant_id}:${e.id}`} className="hover:bg-raised-2">
                    <td className={cx('py-2 pr-3 whitespace-nowrap tabular-nums', due.overdue ? 'text-danger-fg' : 'text-body')}>{due.text}</td>
                    <td className="py-2 pr-3">
                      <div className="text-fg">{e.tenant_name}</div>
                      <div className="font-mono text-xs text-muted">{e.tenant_id}</div>
                      {e.tenant_status !== 'active' && <Badge tone="bad">{e.tenant_status}</Badge>}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        <SeverityBadge value={e.alert_severity} />
                        <button type="button" className="text-left text-fg hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus" onClick={() => open(e)}>
                          {e.alert_title ?? e.alert_id}
                        </button>
                      </div>
                    </td>
                    <td className="py-2 pr-3">{e.level}</td>
                    <td className="py-2 pr-3">
                      <StatusBadge value={e.status} />
                    </td>
                    <td className="max-w-xs truncate py-2 pr-3 text-secondary" title={e.reason}>
                      {e.reason}
                    </td>
                    <td className="py-2 text-right">
                      <Button size="sm" variant="quiet" onClick={() => open(e)} aria-label={`Open escalation in tenant ${e.tenant_name}`}>
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
