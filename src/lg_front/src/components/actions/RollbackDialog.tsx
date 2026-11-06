import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterActionChange } from '../../api/invalidate';
import type { ActionOut } from '../../api/types';
import { useApi, useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/roles';
import { humanize } from '../../lib/format';
import { RiskBadge } from '../Badge';
import { Modal } from '../Dialog';
import { useToast } from '../Toast';
import { Button, ErrorMessage, TextAreaField } from '../ui';

/**
 * Request the rollback of an executed action: a new action of the inverse
 * type, approved at once when the requester's role may approve its risk,
 * otherwise waiting for an admin.
 */
export function RollbackDialog({ action, onClose }: { action: ActionOut; onClose: () => void }) {
  const api = useApi();
  const { principal } = useAuth();
  const client = useQueryClient();
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inverse = action.rollback?.action_type ?? '';
  const risk = action.rollback?.risk ?? action.risk_level;
  const selfApproved = can.approve(principal, risk);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = await endpoints.rollbackAction(api, action.id, reason.trim(), true);
      const state = out.rollback.status === 'approved' ? 'approved and queued' : humanize(out.rollback.status);
      toast.success(`${out.created ? 'Rollback requested' : 'A rollback already exists'}: ${humanize(out.rollback.action_type)} (${state}).`);
      void afterActionChange(client);
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      title={`Roll back ${humanize(action.action_type)}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => void submit()} busy={busy} disabled={!reason.trim()}>
            Request rollback
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-body">
        <p>
          A new action <strong>{humanize(inverse)}</strong> undoes it on <code className="break-all">{action.target}</code>, through
          the connector that executed it.
        </p>
        <p className="flex flex-wrap items-center gap-2">
          <RiskBadge value={risk} />
          {selfApproved ? (
            <span className="text-ok-fg">Approved by you: it runs within seconds.</span>
          ) : (
            <span className="text-warn-fg">Needs admin approval: it waits in the ledger until an admin approves it.</span>
          )}
        </p>
        <TextAreaField
          label="Reason (required)"
          rows={3}
          maxLength={500}
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="font-sans"
        />
        {error !== null && <ErrorMessage error={error} compact />}
      </div>
    </Modal>
  );
}
