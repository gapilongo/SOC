/**
 * What a page needs around the decision bar, shared by the investigation
 * view and the case page: the time left to the deadline, why the caller may
 * not decide here, and the claim a decision needs first.
 */

import { useQueryClient } from '@tanstack/react-query';
import { Clock } from 'lucide-react';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { escalationConflictNotice } from '../../api/fields';
import { afterAlertChange, afterEscalationChange } from '../../api/invalidate';
import type { EscalationOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { can, escalationDecisionBlockedReason } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import { useToast } from '../../../../components/Toast';
import { cx } from '../../../../components/ui';
import { formatDateTime } from '../../../../lib/format';
import { slaLabel, slaStatus } from '../../lib/sla';
import { useNow } from '../../../../lib/useNow';

/** The statuses in which an escalation still waits for its decision. */
export const ACTIVE_ESCALATION: ReadonlySet<string> = new Set(['open', 'claimed', 'expired']);

/** The time left to the deadline of an escalation that still waits (its own clock: the page does not re-render every second). */
export function SlaChip({ e }: { e: Pick<EscalationOut, 'sla_deadline' | 'created_at'> }) {
  const now = useNow(1_000);
  const sla = slaStatus(e.sla_deadline, now, e.created_at);
  if (sla.state === 'none') return null;
  return (
    <span
      className={cx(
        'inline-flex min-h-ctl-sm items-center gap-1 whitespace-nowrap rounded-tag bg-raised-2 px-1.5 text-xs tabular-nums',
        sla.state === 'ok' ? 'text-secondary' : 'font-semibold text-warn',
      )}
      title={e.sla_deadline ? `Deadline ${formatDateTime(e.sla_deadline)}` : undefined}
    >
      <Clock className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
      {slaLabel(sla)}
    </span>
  );
}

/** Why the caller cannot decide this escalation here, or null when they may (after a claim, if it is not theirs yet). */
export function blockedReason(e: EscalationOut, principal: Principal | null): string | null {
  const general = escalationDecisionBlockedReason(principal, e);
  if (general) return general;
  if (e.assigned_to !== principal?.userId && !can.claimEscalation(principal, e)) return 'You cannot claim this escalation.';
  return null;
}

/** Claim (or take over) the escalation; the page shows the outcome as a notice and re-reads what changed. */
export function useClaim(e: EscalationOut | undefined) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!e) return;
    setBusy(true);
    try {
      await endpoints.claim(api, e.id, e.version);
      toast.success(e.assigned_to ? 'Escalation taken over.' : 'Escalation claimed.');
    } catch (err) {
      const notice = escalationConflictNotice(err, 'it has been reloaded');
      if (notice) toast.info(notice);
      else toast.error(err, 'Claim failed');
    } finally {
      setBusy(false);
      void afterEscalationChange(client);
      // The proposed response is computed for the caller: it is theirs to tick once the claim is.
      void afterAlertChange(client, e.alert_id);
    }
  };
  return { busy, run: () => void run() };
}
