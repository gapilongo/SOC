import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterActionChange } from '../../api/invalidate';
import type { ActionOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, ErrorMessage, TextAreaField } from '../../components/ui';
import { humanize } from '../../lib/format';

/** Run a failed Microsoft action again (guardrails and caps are checked again by the server). */
export function RetryDialog({ action, onClose }: { action: ActionOut; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const failure = typeof action.result?.error === 'string' ? humanize(action.result.error) : 'unknown error';

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await endpoints.retryAction(api, action.id, reason.trim());
      toast.success(`${humanize(action.action_type)} on ${action.target} queued to run again.`);
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
      title={`Retry ${humanize(action.action_type)}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!reason.trim()}>
            Retry action
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-body">
        <p>
          It failed with <strong>{failure}</strong>. The scheduler runs it again with the same integration; it reads the current state
          first, so a partial earlier attempt is completed, never repeated.
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
