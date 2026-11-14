/**
 * The track record of an outcome: how often analysts confirmed it, as counts
 * a reader can check. Never a percentage. Up to 60 alerts are drawn as
 * squares (one per alert); above that, the fraction and a bar. Under the
 * minimum sample the counts are shown and a rate is refused in words.
 */

import type { TrackRecordOut } from '../../api/investigation';

/** Above this many alerts the squares become a bar. */
export const MAX_SQUARES = 60;

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
  outcome,
  scope,
}: {
  /** Null: not measured yet. */
  record: TrackRecordOut | null;
  /** The outcome in a sentence: "alerts sent to a person as likely malicious". */
  outcome: string;
  /** Whose alerts were counted: the tenant's name. */
  scope: string;
}) {
  if (!record) {
    return (
      <div data-track="none" className="text-ctl">
        <p className="text-body">Not measured yet.</p>
        <small className="mt-1.5 block text-xs text-muted">
          How often analysts confirmed the {outcome} is not counted yet, so no figure is shown.
        </small>
      </div>
    );
  }
  const total = Math.max(0, Math.round(record.total));
  const confirmed = Math.min(total, Math.max(0, Math.round(record.confirmed)));
  const window = `${scope}, last ${record.window_days} days`;
  if (total === 0) {
    return (
      <div data-track="empty" className="text-ctl">
        <p className="text-body">Of the {outcome}, analysts have decided none yet.</p>
        <small className="mt-1.5 block text-xs text-muted">{window}.</small>
      </div>
    );
  }
  const few = total < record.min_samples;
  return (
    <div data-track={few ? 'few' : 'counted'} className="text-ctl">
      {few ? (
        <p className="text-body">
          Of the {outcome}, analysts decided {total} so far and confirmed {confirmed}.
        </p>
      ) : (
        <p className="text-body">
          <b className="font-semibold text-fg">
            Analysts confirmed {confirmed} of {total}
          </b>{' '}
          {outcome}.
        </p>
      )}
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
