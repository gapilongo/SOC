/**
 * MSSP console (platform admins): every tenant with its activity and quotas,
 * suspension, the cross-tenant escalation queue, monthly usage for invoicing
 * and tenant provisioning. Every read here is audited in the admin's home
 * tenant; opening a tenant switches the acting tenant (X-Tenant-ID).
 */

import { useSearchParams } from 'react-router-dom';

import { PageHeader, Tabs } from '../../../../components/ui';
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
  return (
    <>
      <PageHeader
        title="MSSP console"
        description="Every tenant at a glance: activity, SLA risk, quotas and usage. Opening a tenant switches the header's tenant context; every request is recorded in that tenant's audit log."
      />
      <Tabs variant="underline" label="MSSP console" tabs={TABS} value={tab} onChange={select}>
        {tab === 'tenants' && <TenantsTab />}
        {tab === 'escalations' && <EscalationsTab />}
        {tab === 'usage' && <UsageTab />}
        {tab === 'create' && <CreateTenantTab />}
        {tab === 'data' && <TenantDataCard />}
      </Tabs>
    </>
  );
}
