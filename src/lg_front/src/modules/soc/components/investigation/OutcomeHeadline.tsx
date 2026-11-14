/**
 * The outcome of an investigation: one of four categories tied to what
 * happens next (or who closed the alert, or that it is still running), and
 * the verdict as a sentence, the largest text of the page. The lines under
 * it say why the alert is with a person or why it was closed, and what
 * keeps the AI from closing it on its own. An analyst should be able to
 * stop reading there.
 *
 * With the verdict hidden (evidence-first review, blind audits) the
 * category, the sentence and the reasons are withheld and a note says so.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import type { InvestigationClosedByOut, InvestigationOutcomeOut, InvestigationSummaryOut } from '../../api/types';
import { cx } from '../../../../components/ui';
import { formatDateTime } from '../../../../lib/format';
import { alertHref } from '../../lib/links';
import { Glyph, type GlyphName } from './glyphs';
import { Keycap, VoiceTag } from './voices';

export type OutcomeKind =
  | 'needs_decision'
  | 'needs_review'
  | 'ai_closed_evidence'
  | 'ai_closed_audit'
  | 'closed_rule'
  | 'closed_cached'
  | 'closed_analyst'
  | 'closed'
  | 'waiting_approval'
  | 'investigating'
  | 'failed'
  | 'unknown';

const KINDS: Record<OutcomeKind, { label: string; glyph: GlyphName; colour: string }> = {
  needs_decision: { label: 'Needs your decision: likely malicious', glyph: 'threat', colour: 'text-state-bad' },
  needs_review: { label: 'Needs your decision: unsure', glyph: 'review', colour: 'text-state-waiting' },
  ai_closed_evidence: { label: 'Closed by AI, backed by evidence', glyph: 'backed', colour: 'text-state-ok' },
  ai_closed_audit: { label: 'Closed by AI, sampled for audit', glyph: 'audit', colour: 'text-state-ok' },
  closed_rule: { label: 'Closed by a suppression rule', glyph: 'rule', colour: 'text-secondary' },
  closed_cached: { label: 'Closed by an earlier analyst verdict', glyph: 'cached', colour: 'text-secondary' },
  closed_analyst: { label: 'Closed by an analyst', glyph: 'person', colour: 'text-secondary' },
  closed: { label: 'Closed', glyph: 'empty', colour: 'text-secondary' },
  waiting_approval: { label: 'Waiting for an approval', glyph: 'approval', colour: 'text-state-approval' },
  investigating: { label: 'Being investigated', glyph: 'run', colour: 'text-state-processing' },
  failed: { label: 'Investigation failed', glyph: 'cannot', colour: 'text-state-bad' },
  unknown: { label: 'Outcome not recorded', glyph: 'not', colour: 'text-secondary' },
};

const CLOSED_BY: Record<string, OutcomeKind> = { suppression_rule: 'closed_rule', cached_verdict: 'closed_cached', analyst: 'closed_analyst' };
const AI_CLOSED: ReadonlySet<string> = new Set(['ai_closed_evidence', 'ai_closed_audit']);
const WITH_PERSON: ReadonlySet<string> = new Set(['needs_decision', 'needs_review']);

/**
 * The one outcome shown for an alert. Who closed it comes first (an alert an
 * analyst closed keeps its AI category in the read model), then its
 * category; without an outcome, where its status says it is.
 */
export function outcomeKind(outcome: InvestigationOutcomeOut | null, status: string): OutcomeKind {
  if (!outcome) {
    if (status === 'failed') return 'failed';
    if (status === 'new' || status === 'queued' || status === 'processing') return 'investigating';
    if (status === 'waiting_approval') return 'waiting_approval';
    return status === 'closed' ? 'closed' : 'unknown';
  }
  const category = outcome.category ?? '';
  if (outcome.closed_by) {
    if (outcome.closed_by.kind === 'ai') return AI_CLOSED.has(category) ? (category as OutcomeKind) : 'closed';
    return CLOSED_BY[outcome.closed_by.kind] ?? 'closed';
  }
  if (WITH_PERSON.has(category) || AI_CLOSED.has(category)) return category as OutcomeKind;
  return status === 'closed' ? 'closed' : 'unknown';
}

export function outcomeLabel(kind: OutcomeKind): string {
  return KINDS[kind].label;
}

/** The outcome as a tag: its shape, its words; colour only repeats them. */
export function OutcomeTag({ kind, className }: { kind: OutcomeKind; className?: string }) {
  const k = KINDS[kind];
  return (
    <span data-outcome={kind} className={cx('inline-flex items-center gap-1.5 font-mono text-2xs font-semibold uppercase leading-tight tracking-eyebrow text-fg', className)}>
      <Glyph name={k.glyph} className={k.colour} />
      {k.label}
    </span>
  );
}

const SENTENCE_END = /(?<=[.!?])\s+/;
/** The headline stays a sentence or two; a longer summary continues under it at reading size. */
export const MAX_HEADLINE_CHARS = 260;

/** The first sentences of `text` that fit the headline, and what is left. */
export function splitHeadline(text: string): { headline: string; rest: string } {
  const flat = text.trim().replace(/\s+/g, ' ');
  if (flat.length <= MAX_HEADLINE_CHARS) return { headline: flat, rest: '' };
  const sentences = flat.split(SENTENCE_END);
  let headline = sentences[0];
  let used = 1;
  while (used < sentences.length && `${headline} ${sentences[used]}`.length <= MAX_HEADLINE_CHARS) {
    headline = `${headline} ${sentences[used]}`;
    used += 1;
  }
  return { headline, rest: sentences.slice(used).join(' ') };
}

const DECISION_WORDS: Record<string, string> = {
  true_positive: 'true positive',
  false_positive: 'false positive',
  benign_positive: 'benign, expected here',
  needs_more_info: 'needs more information',
};

/** A code written by code (`known_scanner`) in words. */
const codeWords = (code: string) => code.replace(/_/g, ' ');

/** What the read model records about a close besides its reason: the decision, the rule, the earlier alert, the time. */
function ClosedByDetails({ by }: { by: InvestigationClosedByOut }) {
  if (!by.decision && !by.rule_name && !by.source_alert_id && !by.at) return null;
  return (
    <p className="mt-1.5 flex max-w-[62em] flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted">
      {by.decision && <span>Decision: {DECISION_WORDS[by.decision] ?? codeWords(by.decision)}</span>}
      {by.rule_name && (
        <span>
          Rule: <span className="break-all text-body">{by.rule_name}</span>
        </span>
      )}
      {by.source_alert_id && (
        <Link to={alertHref(by.source_alert_id)} className="text-link underline hover:text-link-hover">
          The alert the analyst decided
        </Link>
      )}
      {by.at && <time dateTime={by.at}>{formatDateTime(by.at)}</time>}
    </p>
  );
}

function fallbackHeadline(kind: OutcomeKind, reason: string | null): string {
  if (kind === 'investigating') return 'The investigation is still running.';
  if (kind === 'failed') return 'The investigation failed before it reached a verdict.';
  return reason ?? 'No investigation ran: the model saw only the alert.';
}

export function OutcomeHeadline({
  outcome,
  summary,
  status,
  hidden = false,
  canReveal = true,
  checkLine,
  children,
}: {
  /** Null while the alert is still being processed. */
  outcome: InvestigationOutcomeOut | null;
  summary: InvestigationSummaryOut;
  /** The alert's status, for an alert without an outcome or that waits for an approval. */
  status: string;
  /** The verdict is hidden: evidence first. */
  hidden?: boolean;
  /** False when the verdict is withheld for everyone (a blind-audit sample). */
  canReveal?: boolean;
  /** How many claims are backed, said after the reason. */
  checkLine?: string;
  /** The subject of the alert (entity chips), always shown. */
  children?: ReactNode;
}) {
  const kind = outcomeKind(outcome, status);
  const by = outcome?.closed_by ?? null;
  const why = by?.reason.sentence ?? outcome?.reason?.sentence ?? null;
  const text = summary.text?.trim() || null;
  const { headline, rest } = splitHeadline(text ?? fallbackHeadline(kind, why));
  // Without a summary the headline already is the reason: say it once.
  const reason = text ? why : null;
  const whyLabel = by ? 'Why it was closed.' : 'Why it is with you.';
  const blockers = by ? [] : (outcome?.blockers ?? []);
  const evidence = outcome?.evidence ?? [];
  return (
    <div data-headline={hidden ? 'hidden' : kind}>
      {hidden ? (
        <div role="note" className="max-w-[46em] border border-dashed border-control px-4 py-3.5 text-sm text-secondary">
          <b className="font-semibold text-fg">The verdict and the claims are hidden.</b>{' '}
          {canReveal ? (
            <>
              Read what the tools returned, choose your own verdict in the bar below, then press <Keycap>V</Keycap> to compare. Blind audits always open
              this way.
            </>
          ) : (
            <>This alert is in a blind-audit sample: its verdict, scores and reasoning are withheld for everyone until an analyst labels it on the Blind audit page.</>
          )}
        </div>
      ) : (
        <>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <OutcomeTag kind={kind} />
            {text && summary.written_by === 'model' && <VoiceTag voice="claimed">Summary written by the model</VoiceTag>}
            {text && summary.written_by === 'rules' && <VoiceTag voice="decided">Summary written by the rules</VoiceTag>}
          </div>
          {kind === 'investigating' && !text && (
            <div aria-hidden="true" className="mb-3 flex max-w-[30em] flex-col gap-2">
              <span className="h-5 w-full animate-pulse rounded-tag bg-raised-2" />
              <span className="h-5 w-2/3 animate-pulse rounded-tag bg-raised-2" />
            </div>
          )}
          <p className="max-w-[30em] break-words text-xl font-semibold text-fg [text-wrap:balance] min-[900px]:text-headline">{headline}</p>
          {rest && <p className="mt-2.5 max-w-[62em] break-words text-sm text-body">{rest}</p>}
          {(reason || checkLine) && (
            <p className="mt-2.5 max-w-[62em] break-words text-sm text-body">
              {reason && (
                <>
                  <b className="font-semibold text-fg">{whyLabel}</b> {reason}{' '}
                </>
              )}
              {checkLine}
            </p>
          )}
          {by && <ClosedByDetails by={by} />}
          {blockers.length > 0 && (
            <div className="mt-2.5 max-w-[62em] text-ctl text-body">
              <VoiceTag voice="decided">Why the AI may not close it on its own</VoiceTag>
              <ul aria-label="Why the AI may not close it on its own" className="mt-1 list-disc pl-5">
                {blockers.map((b) => (
                  <li key={b.code}>{b.sentence}</li>
                ))}
              </ul>
            </div>
          )}
          {evidence.length > 0 && (
            <p className="mt-2.5 flex max-w-[62em] flex-wrap items-center gap-x-2 gap-y-1 text-ctl text-body">
              <VoiceTag voice="decided">Approved benign signals the rules found</VoiceTag>
              <span>{evidence.map(codeWords).join(', ')}</span>
            </p>
          )}
        </>
      )}
      {children}
    </div>
  );
}
