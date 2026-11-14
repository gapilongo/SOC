/**
 * Recording a decision on an escalation, for every surface that offers it
 * (the decision form of /escalations/:id, the decision bar of /alerts/:id):
 * one request, one set of rules.
 */

import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { ApiError } from '../../api/client';
import { endpoints } from '../../api/endpoints';
import { afterEscalationChange, afterEscalationDecision } from '../../api/invalidate';
import type { DecisionIn, DecisionOut, EscalationOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { useToast } from '../../components/Toast';
import { humanize } from '../../lib/format';
import { DECISION_LABELS, type Verdict } from './labels';

/** Notes the API stores at most. */
export const MAX_NOTES = 4000;

/** Verdicts for which the record needs a note (the queue's bulk close always does). */
export function notesRequired(verdict: Verdict | null): boolean {
  return verdict === 'true_positive';
}

/** A decision without the version: the hook sends the one the analyst looked at. */
export type DecisionInput = Omit<DecisionIn, 'version'>;

/**
 * Record a decision with optimistic concurrency: the body carries the version
 * the analyst looked at. On 409 the escalation is re-read and `conflict` says
 * what changed; the caller keeps what the analyst entered, and they confirm
 * again against the new state. Any other failure is `error`.
 *
 * `record` resolves true once the decision is stored and `after` (what the
 * page does next, such as opening the next escalation) has finished.
 */
export function useRecordDecision(escalation: EscalationOut) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [error, setError] = useState<unknown>(null);
  const [conflict, setConflict] = useState<string | null>(null);

  const record = async (input: DecisionInput, after?: (out: DecisionOut) => Promise<void> | void): Promise<boolean> => {
    setError(null);
    try {
      const out = await endpoints.decide(api, escalation.id, { ...input, version: escalation.version });
      setConflict(null);
      const resumed = Array.isArray(out.resumed_alert_ids) ? out.resumed_alert_ids.length : 0;
      toast.success(`Decision recorded; ${resumed} alert(s) resumed.`);
      if (out.resumes_failed > 0) toast.info(`${out.resumes_failed} alert(s) could not be resumed yet; the platform retries them.`);
      void afterEscalationDecision(client);
      await after?.(out);
      return true;
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        try {
          const latest = await endpoints.escalation(api, escalation.id);
          void afterEscalationChange(client);
          const owner = latest.assigned_to_email ?? latest.assigned_to;
          setConflict(
            ['open', 'claimed', 'expired'].includes(latest.status)
              ? `This escalation changed while you were reviewing it (now ${latest.status}${owner ? `, assigned to ${owner}` : ''}). Your verdict and notes are kept; check the change, then record again.`
              : `This escalation is now ${latest.status}${latest.decision ? ` (${DECISION_LABELS[latest.decision] ?? humanize(latest.decision)})` : ''} and can no longer be decided.`,
          );
        } catch (reloadErr) {
          setError(reloadErr);
        }
      } else {
        setError(err);
      }
      return false;
    }
  };

  return { record, error, conflict };
}
