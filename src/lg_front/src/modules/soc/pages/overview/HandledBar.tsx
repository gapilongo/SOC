/**
 * "Closed without a person": of the window's finished alerts, how many no
 * person touched and how many reached one, as a sentence, a stacked bar and
 * the table the bar is drawn from (the bar never carries a figure alone).
 *
 * States: both kinds; one kind only (a single segment); nothing finished
 * yet; no alert in the window; a sample too small for a share. The closes
 * without a person are split by who or what closed them, as the API counts
 * them for the window (`closed_without_human_by`); on an API that does not
 * send the split it reads "not measured yet", never worked out here.
 */

import type { ReactNode } from 'react';

import type { DashboardOut } from '../../api/types';
import { CloserMark, type CloserKind } from '../../components/case';
import { cx } from '../../../../components/ui';
import { formatInt } from '../../../../lib/format';
import { formatPct } from '../../lib/reports';
import { MIN_SAMPLE, claimMean, closeMean, handledSplit, handledStatement, plural, sampleNote, type HandledSplit } from './figures';
import { Cell, NUM, SectionHead, TABLE, TBODY, TH, THEAD, TR, Withheld } from './parts';

// The data colours of console v2 (`--c-data-1` closed by the AI, `--c-data-4` a person); until the
// token file carries them, the accent and the neutral severity stand in.
const FILL = {
  handled: 'bg-[rgb(var(--c-data-1,var(--c-accent)))]',
  needed: 'bg-[rgb(var(--c-data-4,var(--c-sev-info)))]',
} as const;

const HOW = 'text-ctl text-body';

function Swatch({ kind }: { kind: keyof typeof FILL }) {
  return <span aria-hidden="true" className={cx('mr-1.5 inline-block h-2.5 w-2.5 rounded-sm', FILL[kind])} />;
}

function Share({ value }: { value: number | null }) {
  return value === null ? <Withheld>too few for a share</Withheld> : <>{formatPct(value, 0)}</>;
}

function Bar({ split }: { split: HandledSplit }) {
  const label = `${plural(split.finished, 'finished alert', 'finished alerts')}: ${formatInt(split.handled)} closed without a person, ${formatInt(split.needed)} reached a person`;
  return (
    <div role="img" aria-label={label} className="flex h-5 gap-0.5 forced-color-adjust-none">
      {(['handled', 'needed'] as const)
        .filter((kind) => split[kind] > 0)
        .map((kind) => (
          <span key={kind} data-segment={kind} className={cx('min-w-[3px] rounded-sm', FILL[kind])} style={{ flexGrow: split[kind] }} />
        ))}
    </div>
  );
}

function Row({ kind, name, count, share, children }: { kind: keyof typeof FILL; name: string; count: number; share: number | null; children: ReactNode }) {
  return (
    <tr className={TR} data-row={kind}>
      <Cell>
        <Swatch kind={kind} />
        <span className="text-fg">{name}</span>
      </Cell>
      <Cell label="Alerts" className={NUM}>
        {formatInt(count)}
      </Cell>
      <Cell label="Share" className={NUM}>
        <Share value={share} />
      </Cell>
      <Cell label="Checked by" className={HOW}>
        {children}
      </Cell>
    </tr>
  );
}

/** Who or what closed the alerts no person touched, and how each kind of close is checked. */
const CLOSED_BY: ReadonlyArray<{ key: string; kind: CloserKind; how: string }> = [
  { key: 'ai_evidence', kind: 'ai_evidence', how: 'Approved benign evidence backed the close, or an automatic response completed first.' },
  { key: 'ai_audit', kind: 'ai_audit', how: 'No independent evidence backs these closes. The blind audit samples them, and an analyst can reopen or flag one from its case.' },
  { key: 'suppression_rule', kind: 'suppression_rule', how: 'A suppression rule of this customer matched the alert, so no investigation ran.' },
  { key: 'cached_verdict', kind: 'cached_verdict', how: 'An analyst had already decided the same detection and behaviour is benign.' },
];

interface ClosedByRow {
  key: string;
  /** Null for a close reason this release does not know. */
  kind: CloserKind | null;
  count: number;
  how: string;
}

/** The split of the closes without a person, in the order above; null on an API that does not send it. */
export function closedBy(d: DashboardOut): ClosedByRow[] | null {
  const by = d.closed_without_human_by;
  if (!by) return null;
  const rows: ClosedByRow[] = CLOSED_BY.map((c) => ({ ...c, count: by[c.key] ?? 0 }));
  const other = by.other ?? 0;
  if (other > 0) rows.push({ key: 'other', kind: null, count: other, how: 'The alert records a close reason this release does not know.' });
  return rows;
}

export function HandledBar({ d, phrase, isAdmin }: { d: DashboardOut; phrase: string; isAdmin: boolean }) {
  const split = handledSplit(d);
  const claim = claimMean(d);
  const close = closeMean(d);
  const counted = split !== null && split.finished > 0;
  const closers = closedBy(d);
  return (
    <section aria-labelledby="ov-handled">
      <SectionHead
        id="ov-handled"
        title="Closed without a person"
        note={
          <>
            <span data-testid="overview-alerts-received">{formatInt(d.alerts_total)}</span> {d.alerts_total === 1 ? 'alert' : 'alerts'} received in {phrase}
          </>
        }
      />
      <p className="mb-3.5 mt-1.5 max-w-[36em] text-balance text-lg font-semibold text-fg md:text-2xl">
        {handledStatement(d, split, phrase)}
      </p>
      {d.alerts_total === 0 && (
        <p className="text-ctl text-secondary">{isAdmin ? 'Connect a source under Sources or send alerts to the ingest API.' : 'Figures appear as alerts arrive.'}</p>
      )}
      {counted && (
        <figure>
          <Bar split={split} />
          <table data-rows="free" className={cx(TABLE, 'mt-2')} aria-labelledby="ov-handled">
            <thead className={THEAD}>
              <tr>
                <th scope="col" className={cx(TH, 'lg:w-[30%]')}>
                  Who or what closed it
                </th>
                <th scope="col" className={cx(TH, 'lg:text-right')}>
                  Alerts
                </th>
                <th scope="col" className={cx(TH, 'lg:text-right')}>
                  Share
                </th>
                <th scope="col" className={TH}>
                  How it is checked
                </th>
              </tr>
            </thead>
            <tbody className={TBODY}>
              <Row kind="handled" name="Closed without a person" count={split.handled} share={split.handledShare}>
                No analyst decided it and no person approved or rejected a response action. The blind audit below is drawn from these closes.
              </Row>
              {closers ? (
                closers.map((c) => (
                  <tr key={c.key} className={TR} data-row={`closed-by-${c.key}`}>
                    <Cell className="lg:pl-7">{c.kind ? <CloserMark kind={c.kind} /> : <span className="text-secondary">Close reason not recognised</span>}</Cell>
                    <Cell label="Alerts" className={NUM}>
                      {formatInt(c.count)}
                    </Cell>
                    <Cell label="Share" className={NUM}>
                      <Share value={split.handledShare === null ? null : c.count / split.finished} />
                    </Cell>
                    <Cell label="Checked by" className={HOW}>
                      {c.how}
                    </Cell>
                  </tr>
                ))
              ) : (
                <tr className={TR} data-row="split">
                  <Cell className="text-secondary lg:pl-7">By AI on evidence, AI on the model&apos;s word, a suppression rule, an earlier analyst verdict</Cell>
                  <Cell colSpan={2} label="Alerts" className="lg:text-right">
                    <Withheld>not measured yet</Withheld>
                  </Cell>
                  <Cell label="Checked by" className={HOW}>
                    Who or what closed each alert is not counted for this window yet, so the closes above are not split further.
                  </Cell>
                </tr>
              )}
              <Row kind="needed" name="Reached a person" count={split.needed} share={split.neededShare}>
                An analyst decided it, a person approved or rejected an action, or it waits for one. {plural(d.open_escalations, 'item waits', 'items wait')}{' '}
                right now.{' '}
                {claim.value ? (
                  <>
                    Claimed in a mean of {claim.value}, over {formatInt(claim.n)} claimed in {phrase}.
                  </>
                ) : (
                  <>
                    Mean time to claim: <Withheld>too few for a mean</Withheld> ({sampleNote(claim.n, MIN_SAMPLE)}).
                  </>
                )}
              </Row>
            </tbody>
          </table>
          <figcaption className="mt-2 text-xs text-muted">
            Alerts still being processed and the built-in sample alerts are in neither row.
            {split.handledShare === null && <> Shares need at least {formatInt(MIN_SAMPLE)} finished alerts.</>}{' '}
            {close.value ? (
              <>
                Mean time from arrival to close: {close.value}, over {plural(close.n, 'alert', 'alerts')} closed in {phrase}.
              </>
            ) : (
              <>
                Mean time from arrival to close: <Withheld>too few for a mean</Withheld> ({sampleNote(close.n, MIN_SAMPLE)}).
              </>
            )}
          </figcaption>
        </figure>
      )}
    </section>
  );
}
