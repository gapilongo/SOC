/**
 * The outcome of an investigation: one of four categories tied to what
 * happens next (or who closed the alert, or that it is still running), and
 * the verdict as a sentence, the largest text of the page. The line under it
 * says why the alert is with a person or why it was closed. An analyst
 * should be able to stop reading there.
 *
 * With the verdict hidden (evidence-first review, blind audits) the
 * category, the sentence and the reason are withheld and a note says so.
 */

import type { ReactNode } from 'react';

import type { InvestigationOutcomeOut, InvestigationSummaryOut } from '../../api/investigation';
import { cx } from '../ui';
import { Glyph, type GlyphName } from './glyphs';
import { Keycap, VoiceTag } from './voices';

export type OutcomeKind =
  | 'needs_decision_malicious'
  | 'needs_decision_unsure'
  | 'ai_closed'
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
  needs_decision_malicious: { label: 'Needs your decision: likely malicious', glyph: 'threat', colour: 'text-state-bad' },
  needs_decision_unsure: { label: 'Needs your decision: unsure', glyph: 'review', colour: 'text-state-waiting' },
  ai_closed: { label: 'Closed by AI', glyph: 'backed', colour: 'text-state-ok' },
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

/** The one outcome shown for an alert: its category, else who closed it, else where its status says it is. */
export function outcomeKind(outcome: InvestigationOutcomeOut, status: string): OutcomeKind {
  if (outcome.category && outcome.category in KINDS) return outcome.category as OutcomeKind;
  if (status === 'closed') return CLOSED_BY[outcome.closed_by?.kind ?? ''] ?? 'closed';
  if (status === 'waiting_approval') return 'waiting_approval';
  if (status === 'failed') return 'failed';
  if (status === 'new' || status === 'queued' || status === 'processing') return 'investigating';
  return 'unknown';
}

export function outcomeLabel(kind: OutcomeKind): string {
  return KINDS[kind].label;
}

/** The outcome as a tag: its shape, its words; colour only repeats them. */
export function OutcomeTag({ kind, className }: { kind: OutcomeKind; className?: string }) {
  const k = KINDS[kind];
  return (
    <span data-outcome={kind} className={cx('inline-flex items-center gap-1.5 font-mono text-[11.5px] font-semibold uppercase leading-tight tracking-[0.06em] text-fg', className)}>
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

function fallbackHeadline(kind: OutcomeKind, outcome: InvestigationOutcomeOut): string {
  if (kind === 'investigating') return 'The investigation is still running.';
  if (kind === 'failed') return 'The investigation failed before it reached a verdict.';
  return outcome.closed_by?.reason ?? 'No investigation ran: the model saw only the alert.';
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
  outcome: InvestigationOutcomeOut;
  summary: InvestigationSummaryOut | null;
  /** The alert's status, for an alert in none of the four categories. */
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
  const needsDecision = kind === 'needs_decision_malicious' || kind === 'needs_decision_unsure';
  const { headline, rest } = splitHeadline(summary?.text ?? fallbackHeadline(kind, outcome));
  // Without a summary the headline already is the reason an alert was closed: say it once.
  const reason = !summary && outcome.closed_by?.reason === outcome.reason?.text ? null : outcome.reason?.text;
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
            {summary?.source === 'model' && <VoiceTag voice="claimed">Summary written by the model</VoiceTag>}
            {summary?.source === 'rules' && <VoiceTag voice="decided">Summary written by the rules</VoiceTag>}
          </div>
          {kind === 'investigating' && !summary && (
            <div aria-hidden="true" className="mb-3 flex max-w-[30em] flex-col gap-2">
              <span className="h-5 w-full animate-pulse rounded-[2px] bg-raised-2" />
              <span className="h-5 w-2/3 animate-pulse rounded-[2px] bg-raised-2" />
            </div>
          )}
          <p className="max-w-[30em] break-words text-xl font-semibold leading-[1.24] tracking-[-0.017em] text-fg [text-wrap:balance] min-[900px]:text-[25px]">{headline}</p>
          {rest && <p className="mt-2.5 max-w-[62em] break-words text-sm text-body">{rest}</p>}
          {(reason || checkLine) && (
            <p className="mt-2.5 max-w-[62em] break-words text-sm text-body">
              {reason && (
                <>
                  <b className="font-semibold text-fg">{needsDecision ? 'Why it is with you.' : kind === 'waiting_approval' ? 'Why it waits.' : 'Why it was closed.'}</b> {reason}{' '}
                </>
              )}
              {checkLine}
            </p>
          )}
        </>
      )}
      {children}
    </div>
  );
}
