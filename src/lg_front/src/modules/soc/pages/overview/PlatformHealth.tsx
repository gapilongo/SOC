/**
 * Platform health, for admins: what waits to run, what the model cost, the
 * estimate of analyst time saved, and the window's alerts by where they
 * stand. Each count is printed next to its label; the bars are decoration
 * (aria-hidden) and never carry a figure alone.
 */

import { Link } from 'react-router-dom';

import { readCounts } from '../../api/fields';
import type { DashboardOut } from '../../api/types';
import { formatInt, formatUsd, humanize } from '../../../../lib/format';
import { alertsHref } from '../../lib/links';
import { formatHours } from '../../lib/reports';
import { Figure, FigureRow, LABEL, SectionHead } from './parts';

const LINK = 'text-link underline underline-offset-2 hover:text-link-hover';

/** Alert statuses in pipeline order, in the words the rest of the console uses. */
const STATUS_ORDER = ['new', 'queued', 'processing', 'waiting_human', 'waiting_approval', 'closed', 'failed'] as const;
const STATUS_LABEL: Record<string, string> = {
  new: 'New',
  queued: 'Queued',
  processing: 'Processing',
  waiting_human: 'Waiting for an analyst',
  waiting_approval: 'Waiting for approval',
  closed: 'Closed',
  failed: 'Failed',
};

/** Counts per category: label, a proportional bar, the count. */
function Breakdown({
  title,
  meta,
  counts: raw,
  order,
  label = humanize,
  linkFor,
  empty,
}: {
  title: string;
  meta: string;
  counts: Record<string, number>;
  order: readonly string[];
  label?: (key: string) => string;
  linkFor?: (key: string) => string;
  empty: string;
}) {
  const counts = readCounts(raw);
  const keys = [...order.filter((k) => counts[k]), ...Object.keys(counts).filter((k) => !order.includes(k) && counts[k])];
  const max = Math.max(1, ...keys.map((k) => counts[k]));
  return (
    <div className="min-w-0">
      <h3 className={LABEL}>{title}</h3>
      <p className="mt-0.5 text-xs text-muted">{meta}</p>
      {keys.length === 0 ? (
        <p className="mt-2 text-ctl text-secondary">{empty}</p>
      ) : (
        <table data-rows="free" className="mt-1.5 w-full text-ctl">
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
            {keys.map((k) => (
              <tr key={k} className="border-b border-subtle">
                <th scope="row" className="w-[45%] py-1 pr-3 text-left font-normal text-body">
                  {linkFor ? (
                    <Link to={linkFor(k)} className="hover:text-fg hover:underline">
                      {label(k)}
                    </Link>
                  ) : (
                    label(k)
                  )}
                </th>
                <td className="py-1">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 bg-raised-2" aria-hidden="true">
                      <div className="bar-fill h-1.5 bg-control" style={{ width: `${(counts[k] / max) * 100}%` }} />
                    </div>
                    <span className="w-14 text-right font-semibold tabular-nums text-fg">{formatInt(counts[k])}</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function PlatformHealth({ d, phrase }: { d: DashboardOut; phrase: string }) {
  const finished = (d.handled_without_human ?? 0) + (d.needed_human ?? 0);
  const model = d.llm_model ? ` Model: ${d.llm_model}.` : d.llm_model === null ? ' LLM use is off.' : '';
  return (
    <section aria-labelledby="ov-admin">
      <SectionHead id="ov-admin" title="Platform health" note="Shown to admins only." />
      <FigureRow>
        <Figure label="Queue depth, right now" big={formatInt(d.queue_depth)}>
          workflow runs wait to start.
        </Figure>
        <Figure
          label={`LLM cost, ${phrase.replace(/^the /, '')}`}
          big={formatUsd(d.llm_cost_usd)}
          small={
            <Link to="/usage" className={LINK}>
              LLM usage by day and model
            </Link>
          }
        >
          for {formatInt(d.llm_tokens)} tokens.{model}
        </Figure>
        <Figure
          label={`Analyst hours saved, ${phrase.replace(/^the /, '')}`}
          big={formatHours(d.analyst_hours_saved ?? 0)}
          small={
            <Link to="/reports" className={LINK}>
              How the estimate is made, in Reports
            </Link>
          }
        >
          An estimate over {formatInt(finished)} finished alerts: {formatInt(d.minutes_per_alert ?? 15)} minutes for each alert closed without a person.
        </Figure>
      </FigureRow>
      <div className="mt-4 grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-5 lg:grid-cols-3">
        <Breakdown
          title="Worker health"
          meta="Workflow runs not finished yet, by status, right now"
          counts={d.runs_by_status}
          order={['queued', 'running', 'waiting', 'retrying']}
          empty="No workflow run is waiting or running."
        />
        <Breakdown
          title="Alerts by status"
          meta={`Alerts received in ${phrase}, by where they stand now`}
          counts={d.by_status}
          order={STATUS_ORDER}
          label={(k) => STATUS_LABEL[k] ?? humanize(k)}
          linkFor={(status) => alertsHref({ status, from: d.since })}
          empty="No alert in this window."
        />
        <Breakdown
          title="Alerts by AI disposition"
          meta={`Alerts received in ${phrase}, by automated disposition`}
          counts={d.by_disposition}
          order={['malicious', 'benign', 'inconclusive']}
          linkFor={(k) => alertsHref({ disposition: k, from: d.since })}
          empty="No disposition recorded in this window."
        />
      </div>
    </section>
  );
}
