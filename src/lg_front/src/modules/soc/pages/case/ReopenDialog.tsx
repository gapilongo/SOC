/**
 * Reopen an alert the AI closed, or flag the close as wrong: both ask for a
 * reason, and neither is sent without one (`POST /alerts/{id}/reopen`,
 * `POST /alerts/{id}/flag`).
 *
 * The reason is the person's own words. It is sent as plain text and shown
 * back as plain text; the API keeps it on the audit entry and the alert's
 * timeline. The API checks the role and the alert's state again, and its
 * refusal is shown in the dialog.
 */

import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { endpoints } from '../../api/endpoints';
import { afterEscalationDecision } from '../../api/invalidate';
import type { CaseAlertOut } from '../../api/types';
import { useApi } from '../../../../auth/AuthContext';
import { Modal } from '../../../../components/Dialog';
import { useToast } from '../../../../components/Toast';
import { Button, ErrorMessage, TextAreaField } from '../../../../components/ui';
import { shortId } from '../../../../lib/format';

export type ReopenVerb = 'reopen' | 'flag';

export interface PendingReopen {
  alert: Pick<CaseAlertOut, 'id' | 'title'>;
  verb: ReopenVerb;
}

/** The API's limit on the reason (`ReopenIn.reason`). */
export const MAX_REASON = 1000;

const WORDS: Record<ReopenVerb, { title: string; label: string; ok: string; note: string; placeholder: string }> = {
  reopen: {
    title: 'Reopen this alert',
    label: 'Why reopen it (required)',
    ok: 'Reopen alert',
    note: 'The alert comes back to a person: it joins this case as open while the case is open, otherwise a new run sends it to an analyst. Nothing closes it again without a person: no model, no suppression rule, no earlier verdict. The original close and its reason stay on record.',
    placeholder: 'For example: this is the attachment that started the attack.',
  },
  flag: {
    title: 'Flag this AI close as wrong',
    label: 'Why the close was wrong (required)',
    ok: 'Flag and reopen',
    note: 'The flag is recorded as a disagreement with the AI’s close and counted in the blind-audit and accuracy reports. The alert is reopened and comes back to a person, as with Reopen. When no open case holds it, the other alerts the AI closed on the same host or user in the last 24 hours are reopened too.',
    placeholder: 'For example: the earlier verdict was for a different host.',
  },
};

export function ReopenDialog({ pending, caseId, onClose }: { pending: PendingReopen; caseId: string; onClose: () => void }) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const { alert, verb } = pending;
  const words = WORDS[verb];
  const given = reason.trim();

  const submit = async () => {
    if (!given) return;
    setBusy(true);
    setError(null);
    try {
      const out = await endpoints.reopenAlert(api, alert.id, { reason: given, case_id: caseId }, verb === 'flag');
      const where = out.mode === 'folded' ? 'It waits for a person in this case.' : 'A new run sends it to an analyst.';
      toast.success(`${verb === 'flag' ? 'Flagged and reopened' : 'Reopened'} ${shortId(alert.id)}. ${where} Nothing closes it again without a person.`);
      void afterEscalationDecision(client);
      onClose();
    } catch (err) {
      setError(err);
      void afterEscalationDecision(client);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      title={words.title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!given}>
            {words.ok}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-body">
        <p className="break-words font-medium text-fg">{alert.title}</p>
        <TextAreaField
          label={words.label}
          rows={3}
          maxLength={MAX_REASON}
          required
          placeholder={words.placeholder}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="font-sans"
        />
        <p className="text-secondary">{words.note}</p>
        {error !== null && <ErrorMessage error={error} compact />}
      </div>
    </Modal>
  );
}
