/** The queue's bulk bar: claim, close or propose a suppression rule from up to 50 selected escalations. */

import { useState } from 'react';
import { Link } from 'react-router-dom';

import { ApiError } from '../../api/client';
import { bulkFailures, escalationTitle, toBulkItems } from '../../api/fields';
import { useBulkClaim, useBulkClose, useBulkProposeSuppression } from '../../api/hooks';
import { BULK_MAX_ITEMS, type BulkCloseDecision, type BulkOut, type EscalationOut, type SuppressionProposalOut } from '../../api/types';
import { Modal } from '../../components/Dialog';
import { Banner, Button, Checkbox, ErrorMessage, TextAreaField, TextField, cx } from '../../components/ui';
import { shortId } from '../../lib/format';
import { DECISION_LABELS } from './labels';

export type BulkResult =
  | { kind: 'claim' | 'close'; out: BulkOut; titles: Record<string, string> }
  | { kind: 'suppression'; out: SuppressionProposalOut };

function titlesOf(items: readonly EscalationOut[]): Record<string, string> {
  return Object.fromEntries(items.map((e) => [e.id, escalationTitle(e)]));
}

/** "Claimed 3 escalations: 2 succeeded, 1 failed" and the failures with the API's messages. */
export function BulkResultPanel({ result, onDismiss }: { result: BulkResult; onDismiss: () => void }) {
  const dismiss = (
    <Button size="sm" variant="quiet" onClick={onDismiss}>
      Dismiss
    </Button>
  );
  if (result.kind === 'suppression') {
    const rule = result.out.suppression;
    return (
      <Banner tone="info" role="status" actions={dismiss} title={result.out.created ? `Suppression rule “${rule.name}” proposed` : `A rule with the same match already exists: “${rule.name}”`}>
        {result.out.created ? 'It was created disabled for an admin to review and enable under ' : 'Nothing new was created. Review it under '}
        <Link to="/suppressions" className="text-link hover:text-link-hover hover:underline">
          Suppressions
        </Link>
        .
      </Banner>
    );
  }
  const { out, titles } = result;
  const failures = bulkFailures(out);
  const verb = result.kind === 'claim' ? 'Claim' : 'Close';
  const suppression = result.kind === 'close' && out.suppression ? out.suppression : null;
  return (
    <Banner
      tone={failures.length ? 'warning' : 'info'}
      role="status"
      actions={dismiss}
      title={`${verb}: ${out.succeeded} succeeded, ${out.failed} failed`}
    >
      {failures.length > 0 && (
        <ul aria-label="Failed escalations" className="mt-1 flex list-disc flex-col gap-0.5 pl-4">
          {failures.map((f) => (
            <li key={f.escalationId}>
              <span className="font-medium text-fg">{titles[f.escalationId] ?? shortId(f.escalationId)}</span>: {f.message}
            </li>
          ))}
        </ul>
      )}
      {suppression && (
        <p className="mt-1">
          {out.suppression_created ? 'Proposed a disabled suppression rule' : 'A rule with the same match already exists'}: “{suppression.name}”.{' '}
          <Link to="/suppressions" className="text-link hover:text-link-hover hover:underline">
            Review it under Suppressions
          </Link>
        </p>
      )}
    </Banner>
  );
}

function CloseDialog({ items, onClose, onDone }: { items: EscalationOut[]; onClose: () => void; onDone: (r: BulkResult) => void }) {
  const close = useBulkClose();
  const [decision, setDecision] = useState<BulkCloseDecision | null>(null);
  const [notes, setNotes] = useState('');
  const [propose, setPropose] = useState(false);
  const [tried, setTried] = useState(false);
  const notesError = tried && !notes.trim() ? 'A note is required: it is recorded on every escalation you close.' : null;
  const decisionError = tried && !decision ? 'Choose false positive or benign positive.' : null;

  const submit = () => {
    setTried(true);
    if (!decision || !notes.trim()) return;
    close.mutate(
      { items: toBulkItems(items), notes: notes.trim(), decision, propose_suppression: propose },
      { onSuccess: (out) => onDone({ kind: 'close', out, titles: titlesOf(items) }) },
    );
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={`Close ${items.length} escalation${items.length === 1 ? '' : 's'}`}
      description="Each one is decided as you choose, with the same note, and its alerts resume. Items that changed meanwhile are reported and left as they are."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={close.isPending} onClick={submit}>
            Close {items.length}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {close.isError && <ErrorMessage error={close.error} compact />}
        <fieldset aria-describedby={decisionError ? 'bulk-decision-error' : undefined}>
          <legend className="mb-2 text-ctl font-semibold text-fg">Close as</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {(['false_positive', 'benign_positive'] as const).map((d) => (
              <label
                key={d}
                className={cx(
                  'flex cursor-pointer items-center gap-2 rounded-control border px-3 py-2 text-ctl text-fg',
                  decision === d ? 'border-link bg-selected' : 'border-strong',
                )}
              >
                <input type="radio" name="bulk-decision" value={d} checked={decision === d} onChange={() => setDecision(d)} className="h-4 w-4 accent-accent" />
                {DECISION_LABELS[d]}
              </label>
            ))}
          </div>
          {decisionError && (
            <p id="bulk-decision-error" className="mt-1 text-xs text-danger-fg">
              {decisionError}
            </p>
          )}
        </fieldset>
        <TextAreaField
          label="Note (required)"
          rows={3}
          maxLength={4000}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          error={notesError}
          aria-required
          className="font-sans"
        />
        <Checkbox
          label="Propose a suppression rule from these escalations"
          hint="One disabled rule matching their alerts, for an admin to review under Suppressions."
          checked={propose}
          onChange={(e) => setPropose(e.target.checked)}
        />
      </div>
    </Modal>
  );
}

/** The ids `details` of a 422 `not_confirmed_benign` lists. */
function unconfirmedIds(err: unknown): string[] {
  if (!(err instanceof ApiError) || !Array.isArray(err.details)) return [];
  return err.details.flatMap((d) => (d && typeof d === 'object' && typeof (d as { escalation_id?: unknown }).escalation_id === 'string' ? [(d as { escalation_id: string }).escalation_id] : []));
}

function ProposeDialog({ items, onClose, onDone }: { items: EscalationOut[]; onClose: () => void; onDone: (r: BulkResult) => void }) {
  const propose = useBulkProposeSuppression();
  const [name, setName] = useState('');
  const titles = titlesOf(items);
  const err = propose.error;
  const unconfirmed = err instanceof ApiError && err.status === 422 && err.code === 'not_confirmed_benign' ? unconfirmedIds(err) : null;

  const submit = () =>
    propose.mutate(
      { escalation_ids: items.map((e) => e.id), name: name.trim() || null },
      { onSuccess: (out) => onDone({ kind: 'suppression', out }) },
    );

  return (
    <Modal
      open
      onClose={onClose}
      title="Propose a suppression rule"
      description={`From ${items.length} escalation${items.length === 1 ? '' : 's'}. Only escalations already decided false positive or benign positive qualify; the rule is created disabled for an admin to review.`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={propose.isPending} onClick={submit}>
            Propose rule
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {unconfirmed ? (
          <Banner tone="warning" role="alert" title="Not every escalation qualifies">
            <p>Nothing was created. These have no false-positive or benign-positive decision; deselect them, or decide them first:</p>
            <ul aria-label="Escalations that do not qualify" className="mt-1 list-disc pl-4">
              {(unconfirmed.length ? unconfirmed : items.map((e) => e.id)).map((id) => (
                <li key={id}>{titles[id] ?? shortId(id)}</li>
              ))}
            </ul>
          </Banner>
        ) : (
          propose.isError && <ErrorMessage error={err} compact />
        )}
        <TextField label="Rule name (optional)" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} hint="The API names it after the rule and source otherwise." />
      </div>
    </Modal>
  );
}

/**
 * The bulk bar over the queue. `selected` are the selected escalations at the
 * versions shown; results are per item and reported through `onResult`.
 */
export function BulkBar({
  selected,
  onClear,
  onResult,
  capped,
}: {
  selected: EscalationOut[];
  onClear: () => void;
  onResult: (r: BulkResult) => void;
  /** The selection reached BULK_MAX_ITEMS (more were asked for). */
  capped: boolean;
}) {
  const claim = useBulkClaim();
  const [dialog, setDialog] = useState<'close' | 'propose' | null>(null);
  const n = selected.length;
  const none = n === 0;

  const done = (r: BulkResult) => {
    setDialog(null);
    onClear();
    onResult(r);
  };

  return (
    <div role="region" aria-label="Bulk actions" className="flex flex-col gap-2">
      <div className="flex min-h-11 flex-wrap items-center gap-2 rounded-control border border-strong bg-raised-2 py-1.5 pl-3.5 pr-2 text-ctl">
        <span className="font-semibold tabular-nums text-fg" aria-live="polite">
          {n} selected
          {capped && <span className="font-normal text-warn-fg"> · at most {BULK_MAX_ITEMS} at a time</span>}
        </span>
        <span className="flex-1" />
        <Button
          size="sm"
          variant="primary"
          disabled={none}
          busy={claim.isPending}
          onClick={() =>
            claim.mutate(toBulkItems(selected), {
              onSuccess: (out) => done({ kind: 'claim', out, titles: titlesOf(selected) }),
            })
          }
        >
          {none ? 'Claim' : `Claim ${n}`}
        </Button>
        <Button size="sm" disabled={none} onClick={() => setDialog('close')}>
          {none ? 'Close…' : `Close ${n}…`}
        </Button>
        <Button size="sm" disabled={none} onClick={() => setDialog('propose')}>
          Propose suppression…
        </Button>
        <Button size="sm" variant="quiet" disabled={none} onClick={onClear}>
          Clear
        </Button>
      </div>
      {claim.isError && <ErrorMessage error={claim.error} compact />}
      {dialog === 'close' && <CloseDialog items={selected} onClose={() => setDialog(null)} onDone={done} />}
      {dialog === 'propose' && <ProposeDialog items={selected} onClose={() => setDialog(null)} onDone={done} />}
    </div>
  );
}
