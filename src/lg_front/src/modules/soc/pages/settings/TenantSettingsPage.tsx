import { useQuery } from '@tanstack/react-query';

import { endpoints } from '../../../../api/endpoints';
import { qk } from '../../../../api/queryKeys';
import { useApi } from '../../../../auth/AuthContext';
import { Badge } from '../../components/Badge';
import { ErrorMessage, LoadingState, PageHeader } from '../../../../components/ui';
import { formatDateTime } from '../../../../lib/format';
import { LlmTestCard } from './LlmTestCard';
import { PhishingSection } from './PhishingSection';
import { AutonomySection, BudgetSection, ProtectedSection, ResponseSection } from './ResponseSections';
import { ReportingSection, RetentionSection, ReviewSection } from './ReviewSections';
import { RoutingSection } from './RoutingSection';
import { SecuritySection } from './SecuritySection';

export default function TenantSettingsPage() {
  const api = useApi();
  const q = useQuery({ queryKey: qk.tenantSettings.all, queryFn: ({ signal }) => endpoints.tenantSettings(api, signal) });
  const d = q.data;
  return (
    <>
      <PageHeader
        title="Tenant settings"
        description={
          d ? (
            <span className="inline-flex flex-wrap items-center gap-2">
              {d.name} ({d.tenant_id}) <Badge tone={d.status === 'active' ? 'good' : 'bad'}>{d.status}</Badge> last changed {formatDateTime(d.updated_at)}
            </span>
          ) : undefined
        }
      />
      {q.isPending && <LoadingState label="Loading settings" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {d && (
        // Re-mount the sections when the stored settings change so the forms show saved values.
        // Two balanced columns on wide screens: each card keeps its own height (no card is
        // stretched to its neighbour's) and the reading order stays the order below.
        <div key={d.updated_at} className="gap-5 xl:columns-2 [&>*]:mb-5 [&>*]:break-inside-avoid">
          <AutonomySection data={d} />
          <ResponseSection data={d} />
          <RoutingSection data={d} />
          <ProtectedSection data={d} />
          <PhishingSection data={d} />
          <SecuritySection data={d} />
          <BudgetSection data={d} />
          <LlmTestCard />
          <ReviewSection data={d} />
          <RetentionSection data={d} />
          <ReportingSection data={d} />
        </div>
      )}
    </>
  );
}
