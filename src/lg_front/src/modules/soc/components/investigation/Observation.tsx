/**
 * Observed: what one tool call returned, unedited. Monospace on the recessed
 * surface with a double rule, its outcome (returned data, returned nothing,
 * failed) and its hash. The highlighter marks the few characters that
 * matter; it is the one loud colour of the page and is used nowhere else.
 */

import type { ReactNode } from 'react';

import type { ExcerptLineOut, ObservationOut } from '../../api/investigation';
import { formatDateTime } from '../../../../lib/format';
import { clockOf } from './clock';
import { cx } from '../../../../components/ui';
import { SmallTag } from './voices';

const OUTCOME_CLASS: Record<string, string> = {
  success: 'bg-tint-ok text-ok-fg',
  empty: 'bg-raised-2 text-secondary',
  failed: 'bg-tint-danger text-danger-fg',
};

/** "returned 3 rows", "returned data", "returned nothing", "failed". */
export function outcomeWords(o: Pick<ObservationOut, 'outcome' | 'rows'>): string {
  if (o.outcome === 'empty') return 'returned nothing';
  if (o.outcome === 'failed') return 'failed';
  if (typeof o.rows === 'number' && Number.isFinite(o.rows)) return `returned ${o.rows} ${o.rows === 1 ? 'row' : 'rows'}`;
  return 'returned data';
}

/** "9f2c…41e1" of a full digest. */
function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 4)}…${hash.slice(-4)}` : hash;
}

/** One excerpt line with its `[start, end)` ranges highlighted; ranges outside the line are dropped. */
function Marked({ line }: { line: ExcerptLineOut }) {
  const marks = (line.marks ?? [])
    .filter(([start, end]) => Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start && end <= line.text.length)
    .sort((a, b) => a[0] - b[0]);
  const parts: ReactNode[] = [];
  let at = 0;
  marks.forEach(([start, end], i) => {
    if (start < at) return; // overlapping ranges: the first one wins
    if (start > at) parts.push(line.text.slice(at, start));
    parts.push(
      <mark key={i} className="rounded-[1px] bg-mark px-0.5 text-mark-fg">
        {line.text.slice(start, end)}
      </mark>,
    );
    at = end;
  });
  parts.push(line.text.slice(at));
  return <>{parts}</>;
}

export function Observation({
  observation: o,
  repeated = false,
  children,
}: {
  observation: ObservationOut;
  /** Shown a second time on the page (under another claim): the meta line says so instead of repeating itself. */
  repeated?: boolean;
  /** Anything explained about the result, under a dashed rule. */
  children?: ReactNode;
}) {
  const time = clockOf(o.at)?.time ?? null;
  return (
    <div data-observation={o.id} data-outcome={o.outcome} className="border-l-[3px] border-double border-control bg-observed px-2.5 pb-2 pt-[7px]">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs text-secondary">
        <span className="font-mono text-2xs font-semibold leading-none text-fg">{o.id}</span>
        <span className="min-w-0 break-words font-medium text-fg">{o.title}</span>
        {!repeated && (
          <span className={cx('whitespace-nowrap rounded-[2px] px-1 py-0.5 font-mono text-2xs font-medium leading-none', OUTCOME_CLASS[o.outcome] ?? OUTCOME_CLASS.empty)}>
            {outcomeWords(o)}
          </span>
        )}
        {!repeated && o.simulated && <SmallTag tone="warn">Simulated</SmallTag>}
        {!repeated && o.cached && <SmallTag>Cached</SmallTag>}
        <span className="basis-full font-mono text-2xs leading-[1.3] text-muted">
          {repeated ? (
            'same observation as above'
          ) : (
            <>
              {o.tool}
              {' · '}
              {o.at && time ? (
                <time dateTime={o.at} title={formatDateTime(o.at)}>
                  {time}
                </time>
              ) : (
                'time not recorded'
              )}
              {' · '}
              {o.output_sha256 ? <span title={o.output_sha256}>sha256 {shortHash(o.output_sha256)}</span> : 'no hash yet'}
            </>
          )}
        </span>
      </div>
      <pre className="mt-[5px] whitespace-pre-line font-mono text-xs leading-[1.6] text-fg [overflow-wrap:anywhere] min-[900px]:whitespace-pre-wrap">
        {o.excerpt.map((line, i) => (
          <span key={i}>
            {i > 0 && '\n'}
            <Marked line={line} />
          </span>
        ))}
      </pre>
      {!repeated && o.detail && (
        <details className="mt-1.5 text-xs">
          <summary className="flex min-h-6 w-fit cursor-pointer items-center text-link">Query and full result</summary>
          <pre className="whitespace-pre-wrap pt-1.5 font-mono text-[11.5px] leading-normal text-body [overflow-wrap:anywhere]">
            {o.input_sha256 ? `input sha256   ${o.input_sha256}\n` : ''}
            {o.output_sha256 ? `output sha256  ${o.output_sha256}\n` : ''}
            {o.detail}
          </pre>
        </details>
      )}
      {children && <div className="mt-2 border-t border-dashed border-strong pt-[7px]">{children}</div>}
    </div>
  );
}
