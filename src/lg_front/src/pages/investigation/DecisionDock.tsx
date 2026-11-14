/**
 * The decision bar of the investigation view: one key chooses the verdict
 * (T, B, F), a note says what was checked, Ctrl+Enter records it and opens
 * the next escalation. Before anything is recorded the bar says what the
 * chosen verdict sets in motion. It stays at the bottom of the page.
 *
 * The request and its rules are those of the decision page
 * (useRecordDecision): the version the analyst looked at, a note for a true
 * positive, and on a conflict the verdict and the note are kept.
 */

import { useId, useRef, useState } from 'react';

import type { DecisionOut, EscalationOut, PreviewActionOut } from '../../api/types';
import { Keycap } from '../../components/investigation';
import { Banner, Button, ErrorMessage, cx } from '../../components/ui';
import type { Verdict } from '../escalations/labels';
import { MAX_NOTES, notesRequired, useRecordDecision } from '../escalations/useRecordDecision';
import { isSingleKey, useKeydown } from './keys';
import { preapprovedEntries } from './ResponseTable';

const VERDICTS: ReadonlyArray<{ value: Verdict; key: string; label: string }> = [
  { value: 'true_positive', key: 'T', label: 'True positive' },
  { value: 'benign_positive', key: 'B', label: 'Benign, expected here' },
  { value: 'false_positive', key: 'F', label: 'False positive' },
];

const NEEDS_MORE = 'Needs more information is not offered here yet: record a verdict, or leave the escalation open.';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** What recording `verdict` sets in motion, from the response plan and what is ticked in it. */
export function effectOf(verdict: Verdict | null, planned: readonly PreviewActionOut[], preapproved: ReadonlySet<string>): string {
  if (verdict === null) return 'Choose a verdict to see what it sets in motion.';
  if (verdict === 'benign_positive') return 'Closes it as real activity that is expected for this customer.';
  if (verdict === 'false_positive') return 'Closes it as not malicious and feeds the verdict back to triage.';
  const ticked = preapprovedEntries(planned, preapproved).length;
  const automatic = planned.filter((a) => a.without_preapproval === 'automatic').length;
  const waiting = planned.filter((a) => a.without_preapproval === 'awaiting_approval').length - ticked;
  if (planned.length === 0) return 'Marks it malicious and plans the response. A note is required.';
  const now = ticked + automatic;
  const parts = [now > 0 ? `runs ${plural(now, 'action', 'actions')} now (${ticked} ticked)` : 'runs no action now'];
  if (waiting > 0) parts.push(`sends ${plural(waiting, 'other', 'others')} to Approvals`);
  return `Marks it malicious, ${parts.join(' and ')}. A note is required.`;
}

const VERDICT_BUTTON =
  'inline-flex h-11 items-center gap-[7px] rounded-[3px] border px-[11px] text-[13.5px] font-medium min-[900px]:h-9 disabled:cursor-not-allowed disabled:opacity-55';

export function DecisionDock({
  escalation,
  blockedReason,
  claim,
  planned,
  preapproved,
  recordingAs,
  tenant,
  singleKeys,
  onSingleKeys,
  onDecided,
}: {
  escalation: EscalationOut;
  /** Why the caller cannot decide here at all (role, acting on another tenant, claimed by another analyst), or null. */
  blockedReason: string | null;
  /** The claim (or take-over) the decision needs first, or null when the escalation is the caller's. */
  claim: { label: string; busy: boolean; run: () => void } | null;
  /** The response plan a true positive would start. */
  planned: readonly PreviewActionOut[];
  /** The `approval_entry` of every action ticked in the plan. */
  preapproved: ReadonlySet<string>;
  recordingAs: string;
  tenant: string;
  singleKeys: boolean;
  onSingleKeys: (on: boolean) => void;
  /** After the decision is stored: the page opens the next escalation. */
  onDecided: (out: DecisionOut) => Promise<void> | void;
}) {
  const noteId = useId();
  const noteRef = useRef<HTMLInputElement>(null);
  const { record: send, error, conflict } = useRecordDecision(escalation);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [note, setNote] = useState('');
  const [noteError, setNoteError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const locked = blockedReason !== null;

  const choose = (v: Verdict) => {
    if (locked) return;
    setVerdict(v);
    setNotice(null);
  };

  const record = async () => {
    if (locked || busy) return;
    if (claim) {
      setNotice(`${claim.label} first: a decision is recorded under the name of the analyst who holds the escalation.`);
      return;
    }
    if (!verdict) {
      setNotice('Choose a verdict first: T, B or F.');
      return;
    }
    if (notesRequired(verdict) && !note.trim()) {
      setNoteError('A true positive needs a note: what did you check?');
      noteRef.current?.focus();
      return;
    }
    setNoteError(null);
    setNotice(null);
    setBusy(true);
    try {
      await send(
        {
          decision: verdict,
          notes: note.trim() || null,
          approved_actions: verdict === 'true_positive' ? preapprovedEntries(planned, preapproved) : [],
          feedback: null,
          suggest_suppression: verdict === 'true_positive' ? null : false,
        },
        onDecided,
      );
    } finally {
      setBusy(false);
    }
  };

  useKeydown((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      void record();
      return;
    }
    if (!singleKeys || !isSingleKey(e)) return;
    const key = e.key.toLowerCase();
    const hit = VERDICTS.find((v) => v.key.toLowerCase() === key);
    if (hit) choose(hit.value);
    else if (key === 'n' && !locked) setNotice(NEEDS_MORE);
  });

  const effect = locked ? blockedReason : (notice ?? effectOf(verdict, planned, preapproved));

  return (
    <div
      role="region"
      aria-label="Your decision"
      className={cx(
        '-mx-4 -mb-6 mt-[22px] grid grid-cols-1 items-center gap-x-3.5 gap-y-2 border-t-2 border-fg bg-raised px-4 pb-4 pt-3 md:-mx-6 md:px-6',
        'min-[900px]:sticky min-[900px]:bottom-0 min-[900px]:z-20 min-[900px]:grid-cols-[auto_minmax(180px,1fr)_auto] min-[900px]:pb-3 min-[900px]:pt-2.5',
      )}
    >
      {(conflict || error !== null || escalation.status === 'expired') && (
        <div className="col-span-full flex flex-col gap-2">
          {conflict && (
            <Banner tone="warning" role="alert" title="This escalation changed">
              {conflict}
            </Banner>
          )}
          {error !== null && <ErrorMessage error={error} compact />}
          {escalation.status === 'expired' && (
            <p className="text-xs text-warn-fg">The SLA of this escalation has expired. A decision is still accepted and audited as late.</p>
          )}
        </div>
      )}
      <div role="group" aria-label="Verdict" className="grid grid-cols-2 gap-1.5 min-[900px]:flex min-[900px]:flex-wrap">
        {VERDICTS.map((v) => {
          const on = verdict === v.value;
          return (
            <button
              key={v.value}
              type="button"
              aria-pressed={on}
              disabled={locked}
              onClick={() => choose(v.value)}
              className={cx(VERDICT_BUTTON, on ? 'border-fg bg-fg text-canvas' : 'border-control bg-canvas text-fg enabled:hover:bg-raised-2')}
            >
              <Keycap tone={on ? 'inverse' : 'plain'} className="hidden min-[900px]:inline-flex">
                {v.key}
              </Keycap>
              {v.label}
            </button>
          );
        })}
        <button
          type="button"
          aria-disabled="true"
          title={NEEDS_MORE}
          onClick={() => !locked && setNotice(NEEDS_MORE)}
          className={cx(VERDICT_BUTTON, 'cursor-not-allowed border-strong bg-canvas text-muted')}
        >
          <Keycap className="hidden min-[900px]:inline-flex">N</Keycap>
          Needs more
        </button>
      </div>
      <div className="min-w-0">
        <label htmlFor={noteId} className="sr-only">
          What did you check
        </label>
        <input
          id={noteId}
          ref={noteRef}
          value={note}
          maxLength={MAX_NOTES}
          disabled={locked}
          placeholder="What did you check? Required for a true positive."
          aria-required={notesRequired(verdict)}
          aria-invalid={noteError ? true : undefined}
          aria-describedby={noteError ? `${noteId}-error` : undefined}
          onChange={(e) => {
            setNote(e.target.value);
            if (noteError && e.target.value.trim()) setNoteError(null);
          }}
          className="h-11 w-full rounded-[3px] border border-control bg-raised px-2 text-ctl text-fg placeholder:text-muted focus:border-focus focus:outline-none focus:ring-1 focus:ring-focus disabled:cursor-not-allowed disabled:opacity-55 min-[900px]:h-9"
        />
        {noteError && (
          <p id={`${noteId}-error`} className="mt-1 text-xs text-danger-fg">
            {noteError}
          </p>
        )}
      </div>
      {claim && !locked ? (
        <Button variant="primary" size="lg" busy={claim.busy} onClick={claim.run}>
          {claim.label} to decide
        </Button>
      ) : (
        <Button variant="primary" size="lg" busy={busy} disabled={locked || busy} onClick={() => void record()}>
          Record and open next
          <span className="hidden items-center gap-1 min-[900px]:inline-flex">
            <Keycap tone="on-accent">Ctrl</Keycap>
            <Keycap tone="on-accent">Enter</Keycap>
          </span>
        </Button>
      )}
      <div className="col-span-full flex flex-wrap items-baseline gap-x-4 gap-y-1 text-xs text-muted">
        <span>
          Recording as <b className="font-semibold text-fg">{recordingAs}</b>, for <b className="font-semibold text-fg">{tenant}</b>
        </span>
        <span aria-live="polite" data-testid="decision-effect" className="min-w-0 break-words">
          {effect}
        </span>
        <button
          type="button"
          aria-pressed={singleKeys}
          onClick={() => onSingleKeys(!singleKeys)}
          className="ml-auto hidden rounded-[2px] text-xs text-link underline hover:text-link-hover min-[900px]:inline"
        >
          Single-key shortcuts: {singleKeys ? 'on' : 'off'}
        </button>
      </div>
    </div>
  );
}
