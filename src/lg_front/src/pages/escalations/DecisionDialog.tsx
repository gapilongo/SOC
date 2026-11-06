import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState, type FormEvent } from 'react';

import { ApiError } from '../../api/client';
import { qk } from '../../api/queryKeys';
import { endpoints } from '../../api/endpoints';
import { DECISIONS, type Decision, type DecisionIn, type DecisionOut, type EscalationOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { Modal } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Button, Checkbox, ErrorMessage, SelectField, TextAreaField, TextField } from '../../components/ui';

export const DECISION_LABELS: Record<Decision, string> = {
  true_positive: 'True positive (malicious)',
  false_positive: 'False positive',
  benign_positive: 'Benign positive (real but expected)',
  needs_more_info: 'Needs more information',
};

export const ACTION_TYPES = [
  'block_ip',
  'block_domain',
  'block_url',
  'isolate_host',
  'terminate_process',
  'quarantine_file',
  'disable_user',
  'reset_password',
  'revoke_sessions',
  'collect_forensics',
  'create_ticket',
  'send_alert',
] as const;

const DECIDABLE = new Set(['open', 'claimed', 'expired']);

type Tri = '' | 'yes' | 'no';
const tri = (v: Tri): boolean | null => (v === '' ? null : v === 'yes');

/**
 * Decide an escalation with optimistic concurrency: the body carries the
 * version the analyst looked at. On 409 the escalation is re-read, the form
 * keeps what the analyst typed, and they confirm again against the new state.
 */
export function DecisionDialog({
  escalation,
  onClose,
  onDecided,
}: {
  escalation: EscalationOut;
  onClose: () => void;
  onDecided?: (out: DecisionOut) => void;
}) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const [current, setCurrent] = useState<EscalationOut>(escalation);
  const [decision, setDecision] = useState<Decision>('true_positive');
  const [notes, setNotes] = useState('');
  const [actions, setActions] = useState('');
  const [confidence, setConfidence] = useState('');
  const [triageCorrect, setTriageCorrect] = useState<Tri>('');
  const [analysisAccurate, setAnalysisAccurate] = useState<Tri>('');
  const [correlationHelpful, setCorrelationHelpful] = useState<Tri>('');
  const [suggestSuppression, setSuggestSuppression] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [conflict, setConflict] = useState<string | null>(null);

  useEffect(() => setCurrent(escalation), [escalation]);

  const decidable = DECIDABLE.has(current.status);

  const build = (): DecisionIn => {
    const approved =
      decision === 'true_positive'
        ? actions
            .split(/[\n,]/)
            .map((a) => a.trim())
            .filter(Boolean)
        : [];
    const feedback = {
      confidence: confidence === '' ? null : Math.max(0, Math.min(100, Number(confidence))),
      triage_correct: tri(triageCorrect),
      analysis_accurate: tri(analysisAccurate),
      correlation_helpful: tri(correlationHelpful),
    };
    const hasFeedback = Object.values(feedback).some((v) => v !== null);
    return {
      decision,
      version: current.version,
      notes: notes.trim() || null,
      approved_actions: approved,
      feedback: hasFeedback ? feedback : null,
      suggest_suppression: decision === 'false_positive' || decision === 'benign_positive' ? suggestSuppression : null,
    };
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const out = await endpoints.decide(api, current.id, build());
      toast.success(`Decision recorded; ${out.resumed_alert_ids.length} alert(s) resumed.`);
      void client.invalidateQueries({ queryKey: qk.escalations.all });
      void client.invalidateQueries({ queryKey: qk.alerts.all });
      onDecided?.(out);
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        try {
          const latest = await endpoints.escalation(api, current.id);
          setCurrent(latest);
          void client.invalidateQueries({ queryKey: qk.escalations.all });
          setConflict(
            DECIDABLE.has(latest.status)
              ? `This escalation changed while you were reviewing it (now ${latest.status}${latest.assigned_to ? `, assigned to ${latest.assigned_to}` : ''}). Your input is kept; review the current state and submit again.`
              : `This escalation is now ${latest.status}${latest.decision ? ` (${latest.decision.replace(/_/g, ' ')})` : ''} and can no longer be decided.`,
          );
        } catch (reloadErr) {
          setError(reloadErr);
        }
      } else {
        setError(err);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title="Record decision"
      description={`Escalation ${current.level}: ${String(current.summary?.title ?? current.reason)}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="decision-form" variant="primary" busy={busy} disabled={!decidable}>
            Submit decision
          </Button>
        </>
      }
    >
      <form id="decision-form" onSubmit={submit} className="space-y-4">
        {conflict && (
          <p role="alert" className="rounded-md border border-amber-600 bg-amber-950 px-3 py-2 text-sm text-amber-100">
            {conflict}
          </p>
        )}
        {error !== null && <ErrorMessage error={error} compact />}
        {current.status === 'expired' && (
          <p className="text-sm text-amber-200">The SLA for this escalation has expired. The decision is still accepted and audited as late.</p>
        )}
        <fieldset>
          <legend className="mb-2 text-sm font-medium text-slate-200">Decision</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {DECISIONS.map((d) => (
              <label key={d} className="flex cursor-pointer items-center gap-2 rounded-md border border-slate-700 px-3 py-2 text-sm text-slate-200 has-[:checked]:border-sky-400 has-[:checked]:bg-sky-950">
                <input type="radio" name="decision" value={d} checked={decision === d} onChange={() => setDecision(d)} data-autofocus={decision === d || undefined} />
                {DECISION_LABELS[d]}
              </label>
            ))}
          </div>
        </fieldset>
        <TextAreaField label="Notes" rows={3} maxLength={4000} value={notes} onChange={(e) => setNotes(e.target.value)} className="font-sans" />
        {decision === 'true_positive' && (
          <TextAreaField
            label="Pre-approve response actions (optional)"
            hint={`One per line, as action_type or action_type:target. Known types: ${ACTION_TYPES.join(', ')}. Actions above your approval authority are refused.`}
            rows={3}
            value={actions}
            onChange={(e) => setActions(e.target.value)}
          />
        )}
        {(decision === 'false_positive' || decision === 'benign_positive') && (
          <Checkbox
            label="Suggest a suppression rule"
            hint="Creates a disabled rule from this alert for an admin to review under Suppressions."
            checked={suggestSuppression}
            onChange={(e) => setSuggestSuppression(e.target.checked)}
          />
        )}
        <fieldset className="rounded-md border border-slate-800 p-3">
          <legend className="px-1 text-sm font-medium text-slate-200">Feedback on the automated triage (optional)</legend>
          <div className="grid gap-3 sm:grid-cols-4">
            <TextField label="Your confidence (0-100)" type="number" min={0} max={100} value={confidence} onChange={(e) => setConfidence(e.target.value)} />
            <SelectField label="Triage correct" value={triageCorrect} onChange={(e) => setTriageCorrect(e.target.value as Tri)}>
              <option value="">No answer</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </SelectField>
            <SelectField label="Analysis accurate" value={analysisAccurate} onChange={(e) => setAnalysisAccurate(e.target.value as Tri)}>
              <option value="">No answer</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </SelectField>
            <SelectField label="Correlation helpful" value={correlationHelpful} onChange={(e) => setCorrelationHelpful(e.target.value as Tri)}>
              <option value="">No answer</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </SelectField>
          </div>
        </fieldset>
      </form>
    </Modal>
  );
}
