import { useQuery } from '@tanstack/react-query';

import { endpoints } from '../../api/endpoints';
import { qk } from '../../api/queryKeys';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { can } from '../../../../auth/roles';
import { Modal } from '../../../../components/Dialog';
import { ErrorMessage, LoadingState, SeverityTag, StatePill } from '../../../../components/ui';
import { statusTone } from '../../components/Badge';
import { statusWords } from './alertSummary';
import { AlertSections, ReprocessButton } from './AlertSections';

export { ResponseActions } from './AlertSections';

/**
 * One alert in a modal drawer, for pages that link to alerts (escalations,
 * actions). The Alerts page shows the same sections in its side panel.
 */
export function AlertDrawer({ alertId, onClose }: { alertId: string | null; onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const q = useQuery({
    queryKey: qk.alert.detail(alertId),
    queryFn: ({ signal }) => endpoints.alert(api, alertId as string, signal),
    enabled: Boolean(alertId),
  });
  const a = q.data;
  return (
    <Modal
      open={Boolean(alertId)}
      onClose={onClose}
      variant="drawer"
      size="lg"
      title={a ? a.title : 'Alert'}
      description={
        a ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityTag value={a.severity} />
            <StatePill tone={statusTone(a.status)}>{statusWords(a.status)}</StatePill>
          </span>
        ) : undefined
      }
      footer={a && can.reprocess(principal) ? <ReprocessButton alertId={a.id} /> : undefined}
    >
      {q.isPending && alertId && <LoadingState label="Loading alert" />}
      {q.isError && <ErrorMessage error={q.error} onRetry={() => void q.refetch()} />}
      {a && <AlertSections alert={a} />}
    </Modal>
  );
}
