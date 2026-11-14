/**
 * What the case page shows: the case read model (`GET /cases/{id}`) and,
 * while the case still waits for its decision, the escalation itself (the
 * version a claim or a decision is recorded against).
 *
 * A case is the escalation with its alerts, so both are kept under the
 * escalation's query keys: whatever changes the escalation makes the case
 * stale too. While the case is open its alerts still move (a run finishes,
 * an approval folds a linked alert in), so the read model is read again on
 * the console's live interval.
 */

import { useQuery } from '@tanstack/react-query';

import { endpoints } from '../../api/endpoints';
import { useEscalation, useLivePollInterval } from '../../api/hooks';
import { qk } from '../../api/queryKeys';
import { useApi } from '../../../../auth/AuthContext';

export function useCase(caseId: string) {
  const api = useApi();
  const interval = useLivePollInterval();
  const model = useQuery({
    queryKey: qk.escalation.caseView(caseId),
    queryFn: ({ signal }) => endpoints.caseView(api, caseId, signal),
    enabled: Boolean(caseId),
    refetchInterval: (query) => (query.state.data?.active ? interval : false),
    refetchIntervalInBackground: false,
  });
  const active = Boolean(model.data?.active);
  // Only an open case is decided here: a decided one needs nothing but the read model.
  const escalation = useEscalation(caseId, { enabled: active, refetchInterval: interval });
  return { model, escalation, active };
}
