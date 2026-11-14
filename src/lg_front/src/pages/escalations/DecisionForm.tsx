/** "Your decision": the verdict form of the decision page. */

import { useQueryClient } from '@tanstack/react-query';
import { Ban, Check, Clock, Lock } from 'lucide-react';
import { useId, useRef, useState, type FormEvent } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { endpoints } from '../../api/endpoints';
import { text } from '../../api/fields';
import { useResponsePreview, useTenantLabel } from '../../api/hooks';
import { afterEscalationChange, afterEscalationDecision } from '../../api/invalidate';
import type { DecisionIn, DecisionOut, EscalationOut, PreviewActionOut } from '../../api/types';
import { useApi } from '../../auth/AuthContext';
import { ActionTarget } from '../../components/ActionTarget';
import { useToast } from '../../components/Toast';
import { Banner, Button, Checkbox, ErrorMessage, SelectField, Spinner, TextField, cx } from '../../components/ui';
import { formatDateTime, humanize } from '../../lib/format';
import { APPROVALS_HREF } from '../../lib/links';
import { DECISION_LABELS, VERDICTS, type Verdict } from './labels';

const HINTS: Record<Verdict, string> = {
  true_positive: 'Malicious. The response plan runs or waits for approval.',
  false_positive: 'Not malicious. Closes the alert and feeds back to triage.',
  benign_positive: 'Real activity, but expected here. Closes the alert.',
};

const VERDICT_BAR: Record<Verdict, string> = {
  true_positive: 'shadow-bar-warning',
  false_positive: 'shadow-[inset_3px_0_0_rgb(var(--c-state-ok))]',
  benign_positive: 'shadow-[inset_3px_0_0_rgb(var(--c-sev-info))]',
};

/** Notes the API stores at most. */
const MAX_NOTES = 4000;

/** Verdicts for which the record needs a note (the queue's bulk close always does). */
export function notesRequired(verdict: Verdict | null): boolean {
  return verdict === 'true_positive';
}

type Tri = '' | 'yes' | 'no';
const tri = (v: Tri): boolean | null => (v === '' ? null : v === 'yes');

const OUTCOME: Record<PreviewActionOut['without_preapproval'], { label: string; Icon: typeof Check }> = {
  automatic: { label: 'Runs automatically', Icon: Check },
  awaiting_approval: { label: 'Waits for approval', Icon: Clock },
  blocked: { label: 'Blocked', Icon: Ban },
};

function actionMeta(a: PreviewActionOut): string {
  const connector = `${a.connector.name}${a.connector.ready ? '' : ' (not ready)'}${a.connector.live === false ? ', dry run' : ''}`;
  const reversible = a.reversible ? (a.inverse_action ? `reversible (${humanize(a.inverse_action)})` : 'reversible') : 'irreversible';
  return `${connector} · ${reversible} · ${a.risk} risk`;
}

function PlanAction({ a, checked, onToggle, disabled }: { a: PreviewActionOut; checked: boolean; onToggle: (on: boolean) => void; disabled: boolean }) {
  const id = useId();
  const outcome = OUTCOME[a.without_preapproval] ?? OUTCOME.awaiting_approval;
  const locked = a.role_lock === 'admin' || a.role_lock === 'disabled';
  const selectable = a.can_preapprove || locked;
  // What the action acts on: always shown, and without it the action cannot be pre-approved here.
  const target = text(a.target);
  const off = disabled || locked || !target;
  const details = (
    <span className="flex flex-col gap-0.5">
      <span className={cx('font-medium', locked ? 'text-secondary' : 'text-fg')}>{a.description || humanize(a.action_type)}</span>
      <span className="text-xs text-secondary">
        Target: {target ? <ActionTarget target={target} /> : <span className="text-warn-fg">not sent</span>}
      </span>
      <span className="text-xs text-secondary">{actionMeta(a)}</span>
      <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-body">
        <span className="inline-flex items-center gap-1">
          <outcome.Icon className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
          {checked ? 'Pre-approved: runs after your decision' : `${outcome.label} without pre-approval`}
        </span>
        <span>
          Guardrail: {a.guardrail.verdict === 'passed' ? 'passed' : 'blocked'}
          {a.guardrail.reason ? ` (${a.guardrail.reason})` : ''}
        </span>
      </span>
      {!a.reversible && a.irreversible_note && <span className="text-xs text-warn-fg">{a.irreversible_note}</span>}
      {a.role_lock === 'admin' && (
        <span className="flex items-start gap-1.5 text-xs text-body">
          <Lock className="mt-px h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" />
          Requires admin approval: an admin pre-approves it here or approves it on the Approvals page.
        </span>
      )}
      {a.role_lock === 'disabled' && (
        <span className="flex items-start gap-1.5 text-xs text-body">
          <Lock className="mt-px h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" />
          The tenant’s autonomy policy disables this action.
        </span>
      )}
      {!target && selectable && (
        <span className="flex items-start gap-1.5 text-xs text-body">
          <Lock className="mt-px h-3.5 w-3.5 flex-none" strokeWidth={2} aria-hidden="true" />
          The plan sent no target for this action, so it cannot be pre-approved here; approve it on the Approvals page.
        </span>
      )}
    </span>
  );
  if (!selectable) {
    return (
      <li className="flex items-start gap-2.5 text-ctl">
        <span className="mt-0.5 h-4 w-4 flex-none" aria-hidden="true" />
        {details}
      </li>
    );
  }
  return (
    <li className="flex items-start gap-2.5 text-ctl">
      <input
        id={id}
        type="checkbox"
        className="mt-0.5 h-4 w-4 flex-none accent-accent disabled:cursor-not-allowed"
        checked={checked}
        disabled={off}
        onChange={(e) => onToggle(e.target.checked)}
      />
      <label htmlFor={id} className={cx(off ? 'cursor-not-allowed' : 'cursor-pointer')}>
        <span className="sr-only">Pre-approve: </span>
        {details}
      </label>
    </li>
  );
}

function ResponsePlan({ escalationId, selected, onChange, disabled }: { escalationId: string; selected: ReadonlySet<string>; onChange: (next: Set<string>) => void; disabled: boolean }) {
  const q = useResponsePreview(escalationId);
  const headingId = useId();
  const actions = Array.isArray(q.data?.actions) ? q.data.actions : [];
  return (
    <section aria-labelledby={headingId} className="flex flex-col gap-2.5 rounded-card border border-strong bg-raised p-4 md:p-5">
      <h2 id={headingId} className="text-base font-semibold text-fg">
        Expected response plan
      </h2>
      <p className="text-xs text-secondary">
        What a true-positive decision would do, computed now as a dry run. The final plan is computed when you record the decision; whatever you do not
        pre-approve waits on the <Link to={APPROVALS_HREF} className="text-link underline hover:text-link-hover">Approvals</Link> page.
      </p>
      {q.isPending && <Spinner label="Computing the expected plan" />}
      {q.isError && <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />}
      {q.data?.dry_run_forced && (
        <Banner tone="info" title="Dry run">
          Response actions are recorded but not executed (the tenant’s dry-run setting or kill switch).
        </Banner>
      )}
      {q.isSuccess && actions.length === 0 && <p className="text-ctl text-secondary">The policy plans no response action for this alert.</p>}
      {actions.length > 0 && (
        <ul aria-label="Planned actions" className="flex flex-col gap-3">
          {actions.map((a) => (
            <PlanAction
              key={a.approval_entry || `${a.action_type}:${a.target}`}
              a={a}
              checked={selected.has(a.approval_entry)}
              disabled={disabled}
              onToggle={(on) => {
                const next = new Set(selected);
                if (on) next.add(a.approval_entry);
                else next.delete(a.approval_entry);
                onChange(next);
              }}
            />
          ))}
        </ul>
      )}
      {q.data?.generated_at && <p className="text-2xs text-muted">Computed {formatDateTime(q.data.generated_at)}</p>}
    </section>
  );
}

const preapprovedText = (n: number) => (n === 0 ? 'No action is pre-approved.' : n === 1 ? '1 action is pre-approved.' : `${n} actions are pre-approved.`);

/**
 * Record a decision with optimistic concurrency: the body carries the version
 * the analyst looked at. On 409 the escalation is re-read, the form keeps
 * what the analyst entered, and they confirm again against the new state.
 *
 * The expected response plan of a true positive is rendered into `planSlot`,
 * in the page's main column, so the form stays short. Its pre-approvals stay
 * state of this form: they are sent with the decision, and they go with the
 * form when the page moves to another escalation.
 */
export function DecisionForm({
  escalation,
  planSlot,
  disabledReason,
  onDecided,
}: {
  escalation: EscalationOut;
  /** Where the page shows the expected response plan; null until the page has rendered it. */
  planSlot: HTMLElement | null;
  /** Why the form cannot be submitted (not claimed by you, read-only role, ...), or null. */
  disabledReason: string | null;
  /** After a recorded decision; `openNext` when "Record and open next" was used. */
  onDecided: (out: DecisionOut, openNext: boolean) => Promise<void> | void;
}) {
  const api = useApi();
  const client = useQueryClient();
  const toast = useToast();
  const tenant = useTenantLabel();
  const notesRef = useRef<HTMLTextAreaElement>(null);
  const notesId = useId();
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [notes, setNotes] = useState('');
  const [preapproved, setPreapproved] = useState<Set<string>>(new Set());
  const [suggestSuppression, setSuggestSuppression] = useState(false);
  const [confidence, setConfidence] = useState('');
  const [triageCorrect, setTriageCorrect] = useState<Tri>('');
  const [analysisAccurate, setAnalysisAccurate] = useState<Tri>('');
  const [correlationHelpful, setCorrelationHelpful] = useState<Tri>('');
  const [notesError, setNotesError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'record' | 'next' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [conflict, setConflict] = useState<string | null>(null);

  const disabled = disabledReason !== null;
  const required = notesRequired(verdict);

  const build = (v: Verdict): DecisionIn => {
    const feedback = {
      confidence: confidence === '' ? null : Math.max(0, Math.min(100, Number(confidence))),
      triage_correct: tri(triageCorrect),
      analysis_accurate: tri(analysisAccurate),
      correlation_helpful: tri(correlationHelpful),
    };
    return {
      decision: v,
      version: escalation.version,
      notes: notes.trim() || null,
      approved_actions: v === 'true_positive' ? [...preapproved] : [],
      feedback: Object.values(feedback).some((x) => x !== null) ? feedback : null,
      suggest_suppression: v === 'false_positive' || v === 'benign_positive' ? suggestSuppression : null,
    };
  };

  const record = async (openNext: boolean) => {
    if (!verdict || disabled) return;
    if (notesRequired(verdict) && !notes.trim()) {
      setNotesError('Notes are required for a true positive: say what you checked.');
      notesRef.current?.focus();
      return;
    }
    setNotesError(null);
    setError(null);
    setBusy(openNext ? 'next' : 'record');
    try {
      const out = await endpoints.decide(api, escalation.id, build(verdict));
      setConflict(null);
      const resumed = Array.isArray(out.resumed_alert_ids) ? out.resumed_alert_ids.length : 0;
      toast.success(`Decision recorded; ${resumed} alert(s) resumed.`);
      if (out.resumes_failed > 0) toast.info(`${out.resumes_failed} alert(s) could not be resumed yet; the platform retries them.`);
      void afterEscalationDecision(client);
      await onDecided(out, openNext);
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
    } finally {
      setBusy(null);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void record(false);
  };

  const hint = disabledReason ?? (!verdict ? 'Choose a verdict to continue.' : 'Record and open next opens the next escalation by SLA that you may decide.');

  return (
    <form
      aria-labelledby="decision-h"
      onSubmit={submit}
      noValidate
      className="flex w-full flex-col gap-4 rounded-card border border-strong bg-raised p-4 md:p-5"
    >
      <h2 id="decision-h" className="text-base font-semibold text-fg">
        Your decision
      </h2>
      {conflict && (
        <Banner tone="warning" role="alert" title="This escalation changed">
          {conflict}
        </Banner>
      )}
      {error !== null && <ErrorMessage error={error} compact />}
      {escalation.status === 'expired' && (
        <p className="text-ctl text-warn-fg">The SLA of this escalation has expired. A decision is still accepted and audited as late.</p>
      )}
      <fieldset disabled={disabled} className="flex flex-col gap-2">
        <legend className="mb-2 text-ctl font-semibold text-fg">
          Verdict <span className="font-normal text-secondary">(choose one)</span>
        </legend>
        {VERDICTS.map((v) => {
          const on = verdict === v;
          return (
            <label
              key={v}
              className={cx(
                'flex cursor-pointer items-start gap-3 rounded-control border p-3',
                on ? cx('border-link bg-selected', VERDICT_BAR[v]) : 'border-strong bg-canvas hover:bg-raised-2',
                disabled && 'cursor-not-allowed opacity-60',
              )}
            >
              <input
                type="radio"
                name="verdict"
                value={v}
                checked={on}
                onChange={() => setVerdict(v)}
                className="mt-0.5 h-4 w-4 flex-none accent-accent"
              />
              <span className="text-sm font-semibold text-fg">
                {DECISION_LABELS[v]}
                <span className="mt-0.5 block text-xs font-normal text-secondary">
                  {HINTS[v]}
                </span>
              </span>
            </label>
          );
        })}
      </fieldset>

      <div>
        <label htmlFor={notesId} className="mb-1.5 block text-ctl font-semibold text-fg">
          Notes for the record{' '}
          <span className={cx('font-normal', required ? 'text-warn-fg' : 'text-secondary')}>{required ? '(required for this verdict)' : '(optional)'}</span>
        </label>
        <textarea
          ref={notesRef}
          id={notesId}
          rows={4}
          maxLength={MAX_NOTES}
          value={notes}
          disabled={disabled}
          placeholder="What did you check?"
          aria-required={required}
          aria-invalid={notesError ? true : undefined}
          aria-describedby={notesError ? `${notesId}-error` : undefined}
          onChange={(e) => {
            setNotes(e.target.value);
            if (notesError && e.target.value.trim()) setNotesError(null);
          }}
          className="block w-full resize-y rounded-control border border-control bg-canvas px-3 py-2 text-ctl text-fg placeholder:text-muted focus:border-focus focus:outline-none focus:ring-1 focus:ring-focus disabled:cursor-not-allowed disabled:opacity-60"
        />
        {notesError && (
          <p id={`${notesId}-error`} className="mt-1 text-xs text-danger-fg">
            {notesError}
          </p>
        )}
      </div>

      {verdict === 'true_positive' && (
        <>
          <p className="text-ctl text-body">{preapprovedText(preapproved.size)} Choose them in the response plan, under the investigation.</p>
          {planSlot && createPortal(<ResponsePlan escalationId={escalation.id} selected={preapproved} onChange={setPreapproved} disabled={disabled} />, planSlot)}
        </>
      )}

      {(verdict === 'false_positive' || verdict === 'benign_positive') && (
        <Checkbox
          label="Suggest a suppression rule"
          hint="Creates a disabled rule from this alert for an admin to review under Suppressions."
          checked={suggestSuppression}
          disabled={disabled}
          onChange={(e) => setSuggestSuppression(e.target.checked)}
        />
      )}

      <details className="border-t border-subtle pt-3 text-ctl">
        <summary className="cursor-pointer text-body">Rate the automated triage (optional)</summary>
        <fieldset disabled={disabled} className="mt-3 grid gap-3 sm:grid-cols-2">
          <legend className="sr-only">Feedback on the automated triage</legend>
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
        </fieldset>
      </details>

      <div className="flex flex-col gap-2 border-t border-subtle pt-3.5">
        <span className="text-xs text-secondary">
          Recording for tenant <b className="text-fg">{tenant}</b>
        </span>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="primary" size="lg" className="flex-[1_1_200px]" disabled={disabled || !verdict || busy !== null} busy={busy === 'record'}>
            Record decision
          </Button>
          <Button size="lg" className="flex-[1_1_200px]" disabled={disabled || !verdict || busy !== null} busy={busy === 'next'} onClick={() => void record(true)}>
            Record and open next
          </Button>
        </div>
        <span className="text-xs text-secondary" aria-live="polite">
          {hint}
        </span>
      </div>
    </form>
  );
}
