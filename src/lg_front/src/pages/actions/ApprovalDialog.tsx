import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { readGuardrail } from '../../api/fields';
import { afterActionChange, afterActionDecision } from '../../api/invalidate';
import type { ActionOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { RiskBadge } from '../../components/Badge';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Banner, Button, Checkbox, ErrorMessage } from '../../components/ui';
import { humanize, shortId } from '../../lib/format';
import { describeBlockedReason } from '../../lib/guardrails';

export type ApprovalVerb = 'approve' | 'reject';

export interface PendingDecision {
  action: ActionOut;
  verb: ApprovalVerb;
  /** Start with "Reject the alert's other pending actions" ticked. */
  rejectRemaining?: boolean;
}

/**
 * Confirm approving or rejecting one pending action. The API re-checks the
 * caller's role and the action's state; its refusal is shown in the dialog.
 */
export function ApprovalDialog({ pending, onClose }: { pending: PendingDecision; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [rejectRemaining, setRejectRemaining] = useState(Boolean(pending.rejectRemaining));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const { action, verb } = pending;
  const guardrail = readGuardrail(action);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = verb === 'approve' ? await endpoints.approve(api, action.id, rejectRemaining) : await endpoints.reject(api, action.id, rejectRemaining);
      toast.success(`${verb === 'approve' ? 'Approved' : 'Rejected'} ${action.action_type} on ${action.target}.${out.resumes_enqueued ? ' The alert workflow resumed.' : ''}`);
      void afterActionDecision(client);
      onClose();
    } catch (err) {
      setError(err);
      void afterActionChange(client);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      title={`${verb === 'approve' ? 'Approve' : 'Reject'} ${humanize(action.action_type)}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={verb === 'approve' ? 'primary' : 'destructive'} onClick={submit} busy={busy}>
            {verb === 'approve' ? 'Approve action' : 'Reject action'}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-body">
        <p>
          <span className="text-muted">Target: </span>
          <code className="break-all">{action.target}</code>
        </p>
        <p className="flex items-center gap-2">
          <RiskBadge value={action.risk_level} /> for alert {shortId(action.alert_id)}
        </p>
        {verb === 'approve' && guardrail?.verdict === 'blocked' && (
          <Banner tone="warning" title="A guardrail blocks it right now">
            {guardrail.code ? describeBlockedReason(guardrail.code) : guardrail.reason} Approved, it is checked again when it executes and is blocked
            unless that changes.
          </Banner>
        )}
        {verb === 'approve' && action.reversible === false && (
          <p className="text-warn-fg">It cannot be undone{action.irreversible_note ? `: ${action.irreversible_note}` : '.'}</p>
        )}
        {verb === 'approve' && (
          <p className="text-secondary">
            Approving this action only; the alert's other pending actions stay pending unless you reject them below.
          </p>
        )}
        <Checkbox
          label="Reject the alert's other pending actions"
          checked={rejectRemaining}
          onChange={(e) => setRejectRemaining(e.target.checked)}
        />
        {error !== null && <ErrorMessage error={error} compact />}
      </div>
    </Modal>
  );
}
