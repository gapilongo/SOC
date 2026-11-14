/**
 * The track record of an outcome: how often people confirmed it for this
 * tenant, as counts a reader can check. Never a percentage. Up to 60 alerts
 * are drawn as squares (one per alert); above that, the fraction and a bar.
 * Under the minimum sample the counts are shown and a rate is refused in
 * words.
 */

import type { OutcomeTrackRecordOut } from '../../api/types';

/** Above this many alerts the squares become a bar. */
export const MAX_SQUARES = 60;

/** Who confirmed what, per outcome category: the lead of the sentence and the alerts it counts. */
const WORDS: Record<string, { lead: string; alerts: string }> = {
  needs_decision: { lead: 'Analysts confirmed', alerts: 'alerts sent to a person as likely malicious' },
  needs_review: { lead: 'Analysts decided true positive on', alerts: 'alerts sent to a person as unsure' },
  ai_closed_evidence: { lead: 'Blind-audit labels agreed with the AI on', alerts: 'alerts the AI closed on approved evidence' },
  ai_closed_audit: { lead: 'Blind-audit labels agreed with the AI on', alerts: 'alerts the AI closed and sampled for audit' },
};
const OTHER = { lead: 'People confirmed', alerts: 'alerts with this outcome' };

function Squares({ confirmed, total }: { confirmed: number; total: number }) {
  return (
    <div role="img" aria-label={`${total} ${total === 1 ? 'alert' : 'alerts'}: ${confirmed} confirmed, ${total - confirmed} not`} className="my-2 flex max-w-[280px] flex-wrap gap-0.5 forced-color-adjust-none">
      {Array.from({ length: total }, (_, i) => (
        <i key={i} data-square={i < confirmed ? 'confirmed' : 'other'} className={i < confirmed ? 'h-[9px] w-[9px] bg-fg' : 'h-[9px] w-[9px] border-[1.5px] border-control'} />
      ))}
    </div>
  );
}

function Bar({ confirmed, total }: { confirmed: number; total: number }) {
  return (
    <div role="img" aria-label={`${confirmed} of ${total} alerts confirmed`} className="my-2 h-[9px] max-w-[280px] border border-control forced-color-adjust-none">
      <span className="bar-fill block h-full bg-fg" style={{ width: `${(100 * confirmed) / total}%` }} />
    </div>
  );
}

export function TrackRecord({
  record,
  scope,
  none = 'Not measured for this alert.',
}: {
  /** Null: the read model has no track record for this alert. */
  record: OutcomeTrackRecordOut | null;
  /** Whose alerts were counted: the tenant's name. */
  scope: string;
  /** Why there is no record, when there is none. */
  none?: string;
}) {
  if (!record) {
    return (
      <div data-track="none" className="text-ctl">
        <p className="text-body">{none}</p>
      </div>
    );
  }
  const words = WORDS[record.category] ?? OTHER;
  const total = Math.max(0, Math.round(record.total));
  const confirmed = Math.min(total, Math.max(0, Math.round(record.confirmed)));
  const basis = record.basis === 'blind_audit_labels' ? 'blind-audit labels' : 'analyst decisions';
  const window = `${scope}, last ${record.window_days} days, ${basis}`;
  if (total === 0) {
    return (
      <div data-track="empty" className="text-ctl">
        <p className="text-body">None of the {words.alerts} has been decided yet.</p>
        <small className="mt-1.5 block text-xs text-muted">{window}.</small>
      </div>
    );
  }
  // The API gives a rate only with enough samples; without one, the page refuses it in words.
  const few = record.rate === null || total < record.min_samples;
  return (
    <div data-track={few ? 'few' : 'counted'} className="text-ctl">
      <p className="text-body">
        <b className="font-semibold text-fg">
          {words.lead} {confirmed} of {total}
        </b>{' '}
        {words.alerts}.
      </p>
      {total <= MAX_SQUARES ? <Squares confirmed={confirmed} total={total} /> : <Bar confirmed={confirmed} total={total} />}
      <small className="mt-1.5 block text-xs text-muted">
        {window}.{' '}
        {few && (
          <span className="whitespace-nowrap rounded-[2px] bg-tint-warn px-1 py-0.5 font-mono text-2xs font-medium leading-none text-warn-fg">
            too few for a rate
          </span>
        )}
      </small>
    </div>
  );
}
