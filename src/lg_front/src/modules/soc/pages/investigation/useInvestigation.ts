/**
 * What the investigation view shows for one alert: the alert, its escalation
 * (deadline, owner, the version a decision is recorded against) and the
 * investigation read model.
 *
 * The read model is built here from today's API responses by
 * `adaptInvestigation` (api/investigation.ts). When
 * `GET /alerts/{id}/investigation` (#411) is available, it replaces the
 * adapter in this hook, and the adapter stays as the fallback for an API
 * that answers 404 for it; nothing else on the page changes.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { endpoints } from '../../api/endpoints';
import { useEscalation, useLivePollInterval, useResponsePreview } from '../../api/hooks';
import { adaptInvestigation, type InvestigationOut } from '../../api/investigation';
import { qk } from '../../api/queryKeys';
import type { AlertEventOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { useKeysetList } from '../../../../lib/pagination';
import { escalationIdOf } from '../alerts/alertSummary';

/** The statuses in which an escalation still waits for its decision. */
export const ACTIVE_ESCALATION: ReadonlySet<string> = new Set(['open', 'claimed', 'expired']);

export function useInvestigation(alertId: string) {
  const api = useApi();
  const interval = useLivePollInterval();
  const alert = useQuery({
    queryKey: qk.alert.detail(alertId),
    queryFn: ({ signal }) => endpoints.alert(api, alertId, signal),
    enabled: Boolean(alertId),
  });
  const escalationId = alert.data ? escalationIdOf(alert.data) : null;
  const escalation = useEscalation(escalationId, { refetchInterval: interval });
  const events = useKeysetList<AlertEventOut>({
    queryKey: qk.alert.events(alertId),
    fetchPage: (cursor, signal) => endpoints.alertEvents(api, alertId, cursor, signal),
    itemKey: (e) => e.id,
    enabled: Boolean(alertId),
  });
  const active = Boolean(escalation.data && ACTIVE_ESCALATION.has(escalation.data.status));
  // The plan a true positive would start: only while the decision is still open.
  const preview = useResponsePreview(escalationId, { enabled: active });

  const investigation = useMemo<InvestigationOut | null>(
    () =>
      alert.data
        ? adaptInvestigation({
            alert: alert.data,
            escalation: escalation.data ?? null,
            events: events.items,
            preview: active ? (preview.data ?? null) : null,
          })
        : null,
    [alert.data, escalation.data, events.items, preview.data, active],
  );

  /** The alert has an escalation that is not read yet: what follows from it (the response, the decision) is not known. */
  const escalationLoading = Boolean(escalationId) && escalation.isPending;
  return { alert, escalation, escalationLoading, events, preview, investigation, active };
}
