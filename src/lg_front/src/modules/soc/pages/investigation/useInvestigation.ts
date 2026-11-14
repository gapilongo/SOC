/**
 * What the investigation view shows for one alert: the alert, its escalation
 * (deadline, owner, the version a decision is recorded against) and the
 * investigation read model.
 *
 * The read model comes from `GET /alerts/{id}/investigation`. An API that
 * predates it answers 404 there: the same shape is then built from that
 * API's own responses by `adaptInvestigation` (api/investigation.ts), and
 * the alert's timeline and response preview are fetched for it. `source`
 * says which one the page is showing.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { ApiError } from '../../../../api/client';
import { endpoints } from '../../api/endpoints';
import { useEscalation, useLivePollInterval, useResponsePreview } from '../../api/hooks';
import { adaptInvestigation } from '../../api/investigation';
import { qk } from '../../api/queryKeys';
import type { AlertEventOut, InvestigationOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { useKeysetList } from '../../../../lib/pagination';
import { escalationIdOf } from '../alerts/alertSummary';

/** The statuses in which an escalation still waits for its decision. */
export const ACTIVE_ESCALATION: ReadonlySet<string> = new Set(['open', 'claimed', 'expired']);

const isMissing = (error: unknown) => error instanceof ApiError && error.status === 404;

export function useInvestigation(alertId: string) {
  const api = useApi();
  const interval = useLivePollInterval();
  const alert = useQuery({
    queryKey: qk.alert.detail(alertId),
    queryFn: ({ signal }) => endpoints.alert(api, alertId, signal),
    enabled: Boolean(alertId),
  });
  const model = useQuery({
    queryKey: qk.alert.investigation(alertId),
    queryFn: ({ signal }) => endpoints.investigation(api, alertId, signal),
    enabled: Boolean(alertId),
    // While the alert is still processed there is no outcome yet: look again until there is one.
    refetchInterval: (query) => (query.state.data && query.state.data.outcome === null ? interval : false),
    refetchIntervalInBackground: false,
  });
  /** The API has the alert but not the read model: build it from what the API does give. */
  const adapting = isMissing(model.error) && alert.isSuccess;

  const escalationId = alert.data ? escalationIdOf(alert.data) : null;
  const escalation = useEscalation(escalationId, { refetchInterval: interval });
  const active = Boolean(escalation.data && ACTIVE_ESCALATION.has(escalation.data.status));

  // Only the adapter needs these two: the read model carries the steps and the proposed response.
  const events = useKeysetList<AlertEventOut>({
    queryKey: qk.alert.events(alertId),
    fetchPage: (cursor, signal) => endpoints.alertEvents(api, alertId, cursor, signal),
    itemKey: (e) => e.id,
    enabled: adapting,
  });
  const preview = useResponsePreview(escalationId, { enabled: adapting && active });

  const adapted = useMemo<InvestigationOut | null>(
    () =>
      adapting && alert.data
        ? adaptInvestigation({
            alert: alert.data,
            escalation: escalation.data ?? null,
            events: events.items,
            preview: active ? (preview.data ?? null) : null,
          })
        : null,
    [adapting, alert.data, escalation.data, events.items, preview.data, active],
  );

  /** The alert has an escalation that is not read yet: what follows from it (the decision) is not known. */
  const escalationLoading = Boolean(escalationId) && escalation.isPending;
  return {
    alert,
    model,
    escalation,
    escalationLoading,
    events,
    preview,
    investigation: model.data ?? adapted,
    source: model.data ? ('api' as const) : adapting ? ('adapter' as const) : null,
    active,
  };
}
