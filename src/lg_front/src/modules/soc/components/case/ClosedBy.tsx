/**
 * Who or what closed an alert, and why, as the case read model gives it
 * (`CaseAlertOut`, api/types.ts): the AI on approved evidence, the AI on
 * the model's word, a suppression rule, an earlier analyst verdict, or an
 * analyst. An alert that is not closed shows where it stands instead.
 *
 * A mark and its words say who; the line under them says when, and names
 * the person, the rule or the earlier alert. The reason is the read
 * model's sentence, never one written here. Shape and words carry the
 * meaning; colour only repeats them.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import type { CaseAlertOut, CaseBlindAuditOut, CaseClosedByOut } from '../../api/types';
import { Glyph, type GlyphName } from '../../../../components/ui/glyphs';
import { cx } from '../../../../components/ui';
import { formatDateTime, shortId } from '../../../../lib/format';
import { alertHref, caseHref } from '../../lib/links';
import { SmallTag } from '../investigation';

export type CloserKind =
  | 'ai_evidence'
  | 'ai_audit'
  | 'ai'
  | 'suppression_rule'
  | 'cached_verdict'
  | 'analyst'
  | 'closed'
  | 'needs_decision'
  | 'needs_review'
  | 'waiting_approval'
  | 'investigating'
  | 'withheld';

const KINDS: Record<CloserKind, { label: string; glyph: GlyphName; colour: string }> = {
  ai_evidence: { label: 'AI, backed by evidence', glyph: 'backed', colour: 'text-state-ok' },
  ai_audit: { label: "AI, on the model's word", glyph: 'audit', colour: 'text-state-ok' },
  ai: { label: 'AI', glyph: 'backed', colour: 'text-state-ok' },
  suppression_rule: { label: 'Suppression rule', glyph: 'rule', colour: 'text-secondary' },
  cached_verdict: { label: 'Earlier analyst verdict', glyph: 'cached', colour: 'text-secondary' },
  analyst: { label: 'Analyst', glyph: 'person', colour: 'text-secondary' },
  closed: { label: 'Closed, by whom is not recorded', glyph: 'empty', colour: 'text-secondary' },
  needs_decision: { label: 'Needs a decision: likely malicious', glyph: 'threat', colour: 'text-state-bad' },
  needs_review: { label: 'Needs a decision: unsure', glyph: 'review', colour: 'text-state-waiting' },
  waiting_approval: { label: 'Waits for an approval', glyph: 'approval', colour: 'text-state-approval' },
  investigating: { label: 'Being investigated', glyph: 'run', colour: 'text-state-processing' },
  withheld: { label: 'Withheld for the blind audit', glyph: 'not', colour: 'text-secondary' },
};

const CLOSERS: ReadonlySet<string> = new Set(['suppression_rule', 'cached_verdict', 'analyst']);

/** Who closed a closed alert, from the read model's `closed_by` and the alert's category. */
export function closerOf(closedBy: CaseClosedByOut | null, category: string | null): CloserKind {
  if (!closedBy) return 'closed';
  if (closedBy.kind === 'ai') return category === 'ai_closed_evidence' ? 'ai_evidence' : category === 'ai_closed_audit' ? 'ai_audit' : 'ai';
  return CLOSERS.has(closedBy.kind) ? (closedBy.kind as CloserKind) : 'closed';
}

/** The one mark shown for an alert of a case: who closed it, or where it stands. */
export function closerKind(alert: Pick<CaseAlertOut, 'state' | 'status' | 'category' | 'closed_by' | 'hidden_for_blind_audit'>): CloserKind {
  if (alert.hidden_for_blind_audit) return 'withheld';
  if (alert.state === 'closed') return closerOf(alert.closed_by, alert.category);
  if (alert.state === 'open') {
    if (alert.status === 'waiting_approval') return 'waiting_approval';
    return alert.category === 'needs_decision' ? 'needs_decision' : 'needs_review';
  }
  return 'investigating';
}

export function closerLabel(kind: CloserKind): string {
  return KINDS[kind].label;
}

/** The mark and its words. */
export function CloserMark({ kind, className }: { kind: CloserKind; className?: string }) {
  const k = KINDS[kind];
  return (
    <span data-closer={kind} className={cx('inline-flex items-center gap-1.5 text-ctl text-fg', className)}>
      <Glyph name={k.glyph} className={cx('flex-none', k.colour)} />
      {k.label}
    </span>
  );
}

const DECISION_WORDS: Record<string, string> = {
  true_positive: 'true positive',
  false_positive: 'false positive',
  benign_positive: 'benign, expected here',
  needs_more_info: 'needs more information',
};

/** An analyst's decision in words (an unknown one as it is, without underscores). */
export function decisionWords(decision: string): string {
  return DECISION_WORDS[decision] ?? decision.replace(/_/g, ' ');
}

const TIER_WORDS: Record<string, string> = {
  off: 'the AI was not allowed to close on the model’s word',
  auto_full_audit: 'the AI may close on the model’s word, and every such close is audited',
};

/** The tenant's closure tier when the alert was decided, in words; null for one this release does not know. */
export function tierWords(tier: string | null): string | null {
  return tier ? (TIER_WORDS[tier] ?? null) : null;
}

/** What the blind audit says about an alert, or null when it was never sampled. */
export function auditWords(audit: Pick<CaseBlindAuditOut, 'state' | 'label' | 'agrees'>): string | null {
  if (audit.state === 'pending') return 'Blind audit: waits for its label';
  if (audit.state !== 'labelled' || !audit.label) return null;
  if (audit.agrees === null) return `Blind audit: labelled ${audit.label}`;
  return `Blind audit: labelled ${audit.label}, ${audit.agrees ? 'agrees with the AI' : 'disagrees with the AI'}`;
}

const SMALL = 'block text-xs text-muted';
const LINK = 'text-link underline hover:text-link-hover';

/** Who an analyst close names: "you", the e-mail, else a short id. */
function personName(person: { user_id: string; email: string | null } | null, userId: string | null | undefined): string | null {
  if (!person) return null;
  if (userId && person.user_id === userId) return 'you';
  return person.email ?? shortId(person.user_id);
}

/** The line under the mark of a closed alert: when, and the person, the rule or the earlier alert. */
function ClosedLine({ alert, userId }: { alert: CaseAlertOut; userId: string | null | undefined }) {
  const by = alert.closed_by;
  const at = by?.at ?? alert.closed_at;
  const parts: ReactNode[] = [];
  if (by?.kind === 'analyst') {
    const who = personName(by.analyst, userId);
    parts.push(who ? `by ${who}` : 'by an analyst');
  }
  if (by?.kind === 'suppression_rule' && by.rule_name) parts.push(<span className="break-words">rule “{by.rule_name}”</span>);
  if (by?.kind === 'cached_verdict' && by.source_alert_id) {
    parts.push(
      <>
        decided on{' '}
        <Link to={alertHref(by.source_alert_id)} className={cx('font-mono', LINK)} title={by.source_alert_id}>
          {shortId(by.source_alert_id)}
        </Link>
      </>,
    );
  }
  return (
    <small className={SMALL}>
      Closed{at && <> {formatDateTime(at)}</>}
      {parts.map((part, i) => (
        <span key={i}> · {part}</span>
      ))}
    </small>
  );
}

/**
 * The "state and closed by" of one alert: the mark, the line under it, and
 * the tags that say how the alert is in the case (linked and left closed,
 * reopened) and what its blind audit found.
 */
export function ClosedBy({ alert, userId }: { alert: CaseAlertOut; userId?: string | null }) {
  const kind = closerKind(alert);
  const audit = alert.hidden_for_blind_audit ? null : auditWords(alert.blind_audit);
  return (
    <span data-closed-by={kind} className="block">
      <CloserMark kind={kind} />
      {alert.state === 'closed' && !alert.hidden_for_blind_audit && <ClosedLine alert={alert} userId={userId} />}
      {alert.hidden_for_blind_audit && <small className={SMALL}>Closed{alert.closed_at && <> {formatDateTime(alert.closed_at)}</>}</small>}
      {(alert.role === 'linked' || alert.role === 'reopened' || audit) && (
        <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
          {alert.role === 'linked' && (
            <span title="Linked to this case by the safety net, and left closed">
              <SmallTag>Linked</SmallTag>
            </span>
          )}
          {alert.role === 'reopened' && <SmallTag tone="warn">Reopened</SmallTag>}
          {audit && <span className="text-xs text-muted">{audit}</span>}
        </span>
      )}
    </span>
  );
}

/**
 * Why: the read model's sentence for the close (the rule of the decision
 * policy for an AI close, with the closure tier), or why the alert is with
 * a person; what an analyst wrote is quoted as theirs. A decision recorded
 * on another case links to that case, which has the note.
 */
export function AlertWhy({ alert, caseId }: { alert: CaseAlertOut; caseId: string }) {
  if (alert.hidden_for_blind_audit) {
    return <span className="text-muted">This alert waits for its blind-audit label. Who or what closed it, and why, is shown once it is labelled.</span>;
  }
  const by = alert.closed_by;
  if (alert.state !== 'closed' || !by) {
    if (alert.reopened) return <span>{alert.reopened.reason.sentence}</span>;
    if (alert.why) return <span>{alert.why.sentence}</span>;
    return <span className="text-muted">{alert.state === 'closed' ? 'The reason of this close is not recorded.' : 'No decision yet: the investigation is still running.'}</span>;
  }
  const tier = by.kind === 'ai' ? tierWords(by.tier) : null;
  const elsewhere = by.kind === 'analyst' && by.decided_in_case_id !== null && by.decided_in_case_id !== caseId;
  return (
    <span data-why={by.reason.code}>
      {by.policy?.sentence ?? by.reason.sentence}
      {by.decision && (by.kind === 'analyst' || by.kind === 'cached_verdict') && <> Decision: {decisionWords(by.decision)}.</>}
      {by.notes && <q className="mt-0.5 block whitespace-pre-wrap break-words text-secondary">{by.notes}</q>}
      {elsewhere && by.decided_in_case_id && (
        <small className={SMALL}>
          Recorded on{' '}
          <Link to={caseHref(by.decided_in_case_id)} className={LINK}>
            another case
          </Link>
          , which has the note.
        </small>
      )}
      {tier && <small className={SMALL}>Closure tier when it was decided: {tier}.</small>}
    </span>
  );
}
