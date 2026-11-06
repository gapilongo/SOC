/** The Overview's escalation lists: the most overdue unassigned one, mine, and the next SLA deadlines. */

import { Link } from 'react-router-dom';

import type { EscalationFilters } from '../../api/endpoints';
import { escalationOwner, escalationSeverity, escalationTitle, formatEntities, type QueueFigures } from '../../api/fields';
import { useEscalationsTop } from '../../api/hooks';
import type { EscalationOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ErrorMessage, SeverityTag, Spinner, cx } from '../../components/ui';
import { formatDateTime, formatDuration, formatRelative } from '../../lib/format';
import { escalationHref, escalationQueueHref } from '../../lib/links';
import { slaLabel, slaStatus, type SlaStatus } from '../../lib/sla';

/** Active escalations: open or claimed (the API's queue figures count these). */
const ACTIVE = ['open', 'claimed'];
const UNASSIGNED_OVERDUE: EscalationFilters = { status: ACTIVE, assigned_to: 'none', overdue: true, order: 'sla_deadline' };
const MINE: EscalationFilters = { status: ACTIVE, assigned_to: 'me', order: 'sla_deadline' };
const BY_DEADLINE: EscalationFilters = { status: ACTIVE, order: 'sla_deadline' };

export const MY_LIST_SIZE = 3;
export const DEADLINES_SIZE = 5;

function slaClass(s: SlaStatus): string {
  if (s.state === 'breaching') return 'font-semibold text-warn';
  if (s.state === 'at_risk') return 'font-medium text-warn';
  return 'text-body';
}

function Sla({ e, now }: { e: EscalationOut; now: number }) {
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  return (
    <span className={cx('whitespace-nowrap tabular-nums', slaClass(s))} title={e.sla_deadline ? `SLA deadline ${formatDateTime(e.sla_deadline)}` : undefined}>
      {slaLabel(s)}
    </span>
  );
}

/** "Most overdue: <title>, 2h 14m past its deadline." (one request, only while something breaches). */
export function MostOverdue({ now, interval }: { now: number; interval: number | false }) {
  const q = useEscalationsTop(UNASSIGNED_OVERDUE, 1, { refetchInterval: interval });
  const e = q.items[0];
  if (!e) return null;
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  return (
    <p className="text-ctl text-body">
      Most overdue:{' '}
      <Link to={escalationHref(e)} className="font-medium text-fg hover:underline">
        {escalationTitle(e)}
      </Link>
      {s.seconds !== null && s.seconds < 0 && <>, {formatDuration(-s.seconds)} past its deadline</>}.
    </p>
  );
}

/** The caller's active escalations, soonest deadline first. */
export function MyClaimedList({ now, interval, total }: { now: number; interval: number | false; total: number }) {
  const q = useEscalationsTop(MINE, MY_LIST_SIZE, { refetchInterval: interval });
  if (q.isPending) return <Spinner label="Loading your escalations" />;
  if (q.isError) return <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />;
  const more = Math.max(0, total - q.items.length);
  return (
    <>
      <ol className="flex flex-col gap-1.5 text-ctl">
        {q.items.map((e) => (
          <li key={e.id} className="flex items-baseline justify-between gap-2">
            <Link to={escalationHref(e)} className="min-w-0 truncate font-medium text-fg hover:underline">
              {escalationTitle(e)}
            </Link>
            <Sla e={e} now={now} />
          </li>
        ))}
      </ol>
      {more > 0 && <p className="text-xs text-muted">and {more} more in your queue</p>}
    </>
  );
}

function OwnerCell({ e }: { e: EscalationOut }) {
  const { principal } = useAuth();
  const owner = escalationOwner(e, principal?.userId);
  return <span className={cx(owner.kind === 'you' ? 'font-medium text-fg' : 'text-secondary', 'break-all')}>{owner.label}</span>;
}

/** The next SLA deadlines of the whole queue (overdue first), with the next deadline still ahead. */
export function NextDeadlines({ queue, now, interval }: { queue: QueueFigures; now: number; interval: number | false }) {
  const q = useEscalationsTop(BY_DEADLINE, DEADLINES_SIZE, { refetchInterval: interval });
  const next = queue.nextSlaDeadline;
  return (
    <section aria-labelledby="ov-sla" className="overflow-hidden rounded-card border border-subtle bg-raised">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-subtle px-4 py-3 md:px-[18px]">
        <div className="min-w-0">
          <h2 id="ov-sla" className="text-sm font-semibold text-fg">
            Next SLA deadlines
          </h2>
          <p className="mt-0.5 text-xs text-muted">
            Open or claimed escalations, soonest deadline first, right now ·{' '}
            {next ? (
              <span title={formatDateTime(next)}>next deadline still ahead {formatRelative(next, now)}</span>
            ) : (
              'no deadline ahead'
            )}
            {queue.overdue > 0 && <> · {queue.overdue} past their deadline</>}
          </p>
        </div>
        <Link to={escalationQueueHref({ order: 'sla_deadline' })} className="text-ctl text-link hover:text-link-hover hover:underline">
          Open the escalation queue
        </Link>
      </div>
      {q.isPending && (
        <div className="px-4 py-6">
          <Spinner label="Loading deadlines" />
        </div>
      )}
      {q.isError && (
        <div className="p-4">
          <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />
        </div>
      )}
      {q.isSuccess && q.items.length === 0 && <p className="px-4 py-5 text-ctl text-secondary md:px-[18px]">No open escalation. The queue is clear.</p>}
      {q.items.length > 0 && (
        // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        <div role="region" aria-labelledby="ov-sla" tabIndex={0} className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-ctl">
            <thead>
              <tr className="text-left text-xs text-secondary">
                <th scope="col" className="px-4 py-2 font-medium md:pl-[18px]">
                  SLA
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Severity
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Escalation
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Level
                </th>
                <th scope="col" className="px-4 py-2 font-medium md:pr-[18px]">
                  Owner
                </th>
              </tr>
            </thead>
            <tbody>
              {q.items.map((e) => {
                const entities = formatEntities(e.entities_preview, 2);
                return (
                  <tr key={e.id} className="border-t border-subtle">
                    <td className="px-4 py-2.5 align-top md:pl-[18px]">
                      <Sla e={e} now={now} />
                    </td>
                    <td className="px-2 py-2.5 align-top">
                      <SeverityTag value={escalationSeverity(e)} />
                    </td>
                    <td className="px-2 py-2.5 align-top">
                      <Link to={escalationHref(e)} className="font-medium text-fg hover:underline">
                        {escalationTitle(e)}
                      </Link>
                      {entities && <span className="text-muted"> · {entities}</span>}
                    </td>
                    <td className="px-2 py-2.5 align-top text-secondary">{e.level}</td>
                    <td className="px-4 py-2.5 align-top md:pr-[18px]">
                      <OwnerCell e={e} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
