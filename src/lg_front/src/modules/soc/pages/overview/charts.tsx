/**
 * The Overview's count panels. Each count is printed as a number next to its
 * label; bars are decoration (aria-hidden) and never carry meaning alone.
 */

import { Link } from 'react-router-dom';

import { readCounts, totalOf } from '../../api/fields';
import { SEVERITIES, SeverityTag, cx, type StateTone } from '../../../../components/ui';
import { formatInt } from '../../../../lib/format';
import { STATUS_STEPS } from './figures';

const STATE_DOT: Record<StateTone, string> = {
  waiting: 'bg-state-waiting',
  approval: 'bg-state-approval',
  processing: 'bg-state-processing',
  ok: 'bg-state-ok',
  bad: 'bg-state-bad',
  neutral: 'bg-muted',
};

const SEV_FILL: Record<(typeof SEVERITIES)[number], string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

function PanelHeader({ id, title, meta }: { id: string; title: string; meta: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
      <h2 id={id} className="text-sm font-semibold text-fg">
        {title}
      </h2>
      <span className="text-xs text-muted">{meta}</span>
    </div>
  );
}

/** Counts by severity: a proportional strip and the five counts (critical first). */
export function SeverityBar({
  id,
  title,
  meta,
  counts: raw,
  linkFor,
}: {
  id: string;
  title: string;
  meta: string;
  counts: Record<string, number>;
  linkFor?: (severity: string) => string;
}) {
  const counts = readCounts(raw);
  const total = totalOf(counts);
  return (
    <section aria-labelledby={id} className="flex flex-col gap-3.5 rounded-card border border-subtle bg-raised p-4 md:p-[18px]">
      <PanelHeader id={id} title={title} meta={meta} />
      <div aria-hidden="true" className="flex h-2.5 gap-0.5 overflow-hidden rounded-full bg-raised-2">
        {total > 0 &&
          SEVERITIES.filter((s) => counts[s]).map((s) => <span key={s} className={SEV_FILL[s]} style={{ flexGrow: counts[s] }} />)}
      </div>
      <ul className="grid grid-cols-[repeat(auto-fit,minmax(min(76px,100%),1fr))] gap-2">
        {SEVERITIES.map((s) => {
          const n = counts[s] ?? 0;
          return (
            <li key={s} className="flex flex-col gap-0.5">
              {linkFor && n > 0 ? (
                <Link to={linkFor(s)} className="inline-flex self-start hover:underline">
                  <SeverityTag value={s} />
                </Link>
              ) : (
                <SeverityTag value={s} />
              )}
              <span className={cx('text-xl font-semibold tabular-nums', n ? 'text-fg' : 'text-secondary')}>{formatInt(n)}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** Alerts by current status, in pipeline order (unknown statuses last). */
export function StatusPipeline({ title, counts: raw, linkFor }: { title: string; counts: Record<string, number>; linkFor: (status: string) => string }) {
  const counts = readCounts(raw);
  const known = new Set<string>(STATUS_STEPS.map((s) => s.status));
  const steps = [
    ...STATUS_STEPS,
    ...Object.keys(counts)
      .filter((k) => !known.has(k))
      .map((k) => ({ status: k, label: k.replace(/_/g, ' '), tone: 'neutral' as const })),
  ];
  return (
    <section aria-labelledby="ov-pipeline" className="flex flex-col gap-3.5 rounded-card border border-subtle bg-raised p-4 md:p-[18px]">
      <h2 id="ov-pipeline" className="text-sm font-semibold text-fg">
        {title}
      </h2>
      <ul className="grid grid-cols-[repeat(auto-fit,minmax(min(132px,100%),1fr))] gap-1.5">
        {steps.map((step) => {
          const n = counts[step.status] ?? 0;
          const body = (
            <>
              <span className="flex items-center gap-1.5 text-xs text-secondary">
                <span className={cx('h-1.5 w-1.5 flex-none rounded-full', STATE_DOT[step.tone])} aria-hidden="true" />
                {step.label}
              </span>
              <span className={cx('text-xl font-semibold tabular-nums', n ? 'text-fg' : 'text-secondary')}>{formatInt(n)}</span>
            </>
          );
          // Subgrids of the row, so the counts line up when a label wraps ("Waiting for an analyst").
          const cls = 'row-span-2 grid grid-rows-subgrid gap-1 rounded-control border border-subtle bg-sidebar p-2.5';
          return (
            <li key={step.status} className="row-span-2 grid grid-rows-subgrid">

              {n > 0 ? (
                <Link to={linkFor(step.status)} className={cx(cls, 'hover:border-control')}>
                  {body}
                </Link>
              ) : (
                <div className={cls}>{body}</div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** Single-series horizontal bars (count per category); the counts are printed, the bars are decoration. */
export function Breakdown({
  title,
  meta,
  counts: raw,
  order,
  linkFor,
  empty,
}: {
  title: string;
  meta: string;
  counts: Record<string, number>;
  order: readonly string[];
  linkFor?: (k: string) => string;
  empty: string;
}) {
  const counts = readCounts(raw);
  const keys = [...order.filter((k) => counts[k]), ...Object.keys(counts).filter((k) => !order.includes(k) && counts[k])];
  const max = Math.max(1, ...keys.map((k) => counts[k]));
  return (
    <section className="flex flex-col gap-3 rounded-card border border-subtle bg-raised p-4 md:p-[18px]">
      <div>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        <p className="mt-0.5 text-xs text-muted">{meta}</p>
      </div>
      {keys.length === 0 ? (
        <p className="text-ctl text-secondary">{empty}</p>
      ) : (
        <table className="w-full text-ctl">
          <caption className="sr-only">
            {title}: {meta}
          </caption>
          <thead className="sr-only">
            <tr>
              <th scope="col">Category</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => {
              const label = k.replace(/_/g, ' ');
              return (
                <tr key={k}>
                  <th scope="row" className="w-36 py-1 pr-3 text-left font-normal capitalize text-secondary">
                    {linkFor ? (
                      <Link to={linkFor(k)} className="hover:text-fg hover:underline">
                        {label}
                      </Link>
                    ) : (
                      label
                    )}
                  </th>
                  <td className="py-1">
                    <div className="flex items-center gap-2">
                      <div className="h-2 flex-1 rounded-sm bg-raised-2" aria-hidden="true">
                        <div className="bar-fill h-2 rounded-sm bg-state-processing" style={{ width: `${(counts[k] / max) * 100}%` }} />
                      </div>
                      <span className="w-14 text-right tabular-nums text-fg">{formatInt(counts[k])}</span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
