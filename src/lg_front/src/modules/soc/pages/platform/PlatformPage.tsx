/**
 * MSSP console (platform admins): every tenant with its activity and quotas,
 * suspension, the cross-tenant escalation queue, monthly usage for invoicing
 * and tenant provisioning. Every read here is audited in the admin's home
 * tenant; opening a tenant switches the acting tenant (X-Tenant-ID).
 */

import type { KeyboardEvent } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader, cx } from '../../../../components/ui';
import { CreateTenantTab } from './CreateTenantTab';
import { EscalationsTab } from './EscalationsTab';
import { TenantDataCard } from './TenantDataCard';
import { TenantsTab } from './TenantsTab';
import { UsageTab } from './UsageTab';

const TABS = [
  { id: 'tenants', label: 'Tenants' },
  { id: 'escalations', label: 'Escalation queue' },
  { id: 'usage', label: 'Usage' },
  { id: 'create', label: 'Create tenant' },
  { id: 'data', label: 'Tenant data' },
] as const;
type TabId = (typeof TABS)[number]['id'];

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
      <div role="tablist" aria-label="MSSP console" className="mb-4 flex flex-wrap gap-1 border-b border-subtle">
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
              '-mb-px border-b-2 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus',
              tab === t.id ? 'border-link font-medium text-fg' : 'border-transparent text-secondary hover:text-fg',
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
