/**
 * Observed: what one tool call returned, unedited. Monospace on the recessed
 * surface with a double rule, its outcome (returned data, returned nothing,
 * failed), the sources that answered and, where the trace store has the
 * call, its hash. The highlighter marks the few characters that matter; it
 * is the one loud colour of the page and is used nowhere else.
 */

import type { ReactNode } from 'react';

import type { InvestigationObservationOut, ObservationExcerptLineOut } from '../../api/types';
import { formatDateTime } from '../../../../lib/format';
import { clockOf } from './clock';
import { cx } from '../../../../components/ui';
import { SmallTag } from './voices';

const OUTCOME_CLASS: Record<string, string> = {
  success: 'bg-tint-ok text-ok-fg',
  empty: 'bg-raised-2 text-secondary',
  failed: 'bg-tint-danger text-danger-fg',
};

/** "returned data", "returned nothing", "failed". */
export function outcomeWords(o: Pick<InvestigationObservationOut, 'outcome'>): string {
  if (o.outcome === 'empty') return 'returned nothing';
  if (o.outcome === 'failed') return 'failed';
  return 'returned data';
}

const KIND_WORDS: Record<string, string> = { ip: 'IP address', url: 'URL', hash: 'file hash', email: 'e-mail address' };

/** "domain cdn-invoice-portal.example": what a lookup looked up, or null when the read model does not say. */
export function observationSubject(o: Pick<InvestigationObservationOut, 'kind' | 'target'>): string | null {
  if (!o.target) return null;
  return `${o.kind ? `${KIND_WORDS[o.kind] ?? o.kind.replace(/_/g, ' ')} ` : ''}${o.target}`;
}

/** "Threat-intelligence reputation: domain cdn-invoice-portal.example", the lookup and what it looked up. */
export function observationName(o: Pick<InvestigationObservationOut, 'title' | 'kind' | 'target'>): string {
  const subject = observationSubject(o);
  return subject ? `${o.title}: ${subject}` : o.title;
}

/** "9f2c…41e1" of a full digest. */
function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 4)}…${hash.slice(-4)}` : hash;
}

/** One excerpt line with its `[start, end)` ranges highlighted; ranges outside the line are dropped. */
function Marked({ line }: { line: ObservationExcerptLineOut }) {
  const marks = (line.marks ?? [])
    .filter(({ start, end }) => Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start && end <= line.text.length)
    .sort((a, b) => a.start - b.start);
  const parts: ReactNode[] = [];
  let at = 0;
  marks.forEach(({ start, end }, i) => {
    if (start < at) return; // overlapping ranges: the first one wins
    if (start > at) parts.push(line.text.slice(at, start));
    parts.push(
      <mark key={i} className="rounded-sm bg-mark px-0.5 text-mark-fg">
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
  observation: InvestigationObservationOut;
  /** Shown a second time on the page (under another claim): the meta line says so instead of repeating itself. */
  repeated?: boolean;
  /** Anything explained about the result, under a dashed rule. */
  children?: ReactNode;
}) {
  const time = clockOf(o.at)?.time ?? null;
  const threat = o.verdict === 'malicious' || o.verdict === 'suspicious';
  return (
    <div data-observation={o.id} data-outcome={o.outcome} className="border-l-3 border-double border-control bg-observed px-2.5 pb-2 pt-1.5">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs text-secondary">
        <span className="font-mono text-2xs font-semibold leading-none text-fg">{o.id}</span>
        <span className="min-w-0 break-words font-medium text-fg">{observationName(o)}</span>
        {!repeated && (
          <span className={cx('whitespace-nowrap rounded-tag px-1 py-0.5 font-mono text-2xs font-medium leading-none', OUTCOME_CLASS[o.outcome] ?? OUTCOME_CLASS.empty)}>
            {outcomeWords(o)}
          </span>
        )}
        {!repeated && o.verdict && o.outcome === 'success' && <SmallTag tone={threat ? 'warn' : 'neutral'}>Verdict {o.verdict}</SmallTag>}
        {!repeated && o.cached && <SmallTag>Cached</SmallTag>}
        <span className="basis-full font-mono text-2xs leading-tight text-muted">
          {repeated ? (
            'same observation as above'
          ) : (
            <>
              {o.sources.length > 0 ? o.sources.join(', ') : o.tool}
              {' · '}
              {o.at && time ? (
                <time dateTime={o.at} title={formatDateTime(o.at)}>
                  {time}
                </time>
              ) : (
                'time not recorded'
              )}
              {o.output_sha256 && (
                <>
                  {' · '}
                  <span title={o.output_sha256}>sha256 {shortHash(o.output_sha256)}</span>
                </>
              )}
            </>
          )}
        </span>
      </div>
      <pre className="mt-1 whitespace-pre-line font-mono text-xs leading-relaxed text-fg [overflow-wrap:anywhere] min-[900px]:whitespace-pre-wrap">
        {o.excerpt.map((line, i) => (
          <span key={i}>
            {i > 0 && '\n'}
            <Marked line={line} />
          </span>
        ))}
      </pre>
      {!repeated && o.excerpt_truncated && <p className="mt-1 text-2xs text-muted">The excerpt is cut: the tool returned more lines.</p>}
      {!repeated && (o.input_sha256 || o.output_sha256) && (
        <details className="mt-1.5 text-xs">
          <summary className="flex min-h-6 w-fit cursor-pointer items-center text-link">Hashes of this call</summary>
          <pre className="whitespace-pre-wrap pt-1.5 font-mono text-2xs leading-normal text-body [overflow-wrap:anywhere]">
            {o.input_sha256 ? `input sha256   ${o.input_sha256}\n` : ''}
            {o.output_sha256 ? `output sha256  ${o.output_sha256}` : ''}
          </pre>
        </details>
      )}
      {children && <div className="mt-2 border-t border-dashed border-strong pt-1.5">{children}</div>}
    </div>
  );
}
