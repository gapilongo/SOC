/** The next deadlines of everything that needs a person (overdue first), whoever holds it. */

import { Link } from 'react-router-dom';

import type { EscalationFilters } from '../../api/endpoints';
import { escalationOwner, escalationSeverity, escalationTitle, formatEntities, type QueueFigures } from '../../api/fields';
import { useEscalationsTop } from '../../api/hooks';
import type { EscalationOut } from '../../api/types';
import { useAuth } from '../../../../auth/AuthContext';
import { ErrorMessage, SeverityTag, Spinner, cx } from '../../../../components/ui';
import { formatDateTime, formatRelative } from '../../../../lib/format';
import { alertHref } from '../../lib/links';
import { slaLabel, slaStatus, type SlaStatus } from '../../lib/sla';
import { plural } from './figures';
import { workQueueHref } from './links';
import { Cell, SectionHead, TABLE, TBODY, TH, THEAD, TR } from './parts';

/** Active items: open or claimed (the API's queue figures count these). */
const BY_DEADLINE: EscalationFilters = { status: ['open', 'claimed'], order: 'sla_deadline' };

export const DEADLINES_SIZE = 5;

function slaClass(s: SlaStatus): string {
  if (s.state === 'breaching') return 'font-semibold text-warn';
  if (s.state === 'at_risk') return 'font-medium text-warn';
  return 'text-body';
}

function Sla({ e, now }: { e: EscalationOut; now: number }) {
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  return (
    <span className={cx('whitespace-nowrap tabular-nums', slaClass(s))} title={e.sla_deadline ? `Deadline ${formatDateTime(e.sla_deadline)}` : undefined}>
      {slaLabel(s)}
    </span>
  );
}

function Owner({ e }: { e: EscalationOut }) {
  const { principal } = useAuth();
  const owner = escalationOwner(e, principal?.userId);
  // One line: a long e-mail is cut, the whole address is the tooltip.
  return (
    <span title={owner.label} className={cx(owner.kind === 'you' ? 'font-medium text-fg' : 'text-secondary', 'inline-block max-w-[13rem] truncate align-bottom')}>
      {owner.label}
    </span>
  );
}

export function Deadlines({ queue, now, interval }: { queue: QueueFigures; now: number; interval: number | false }) {
  const q = useEscalationsTop(BY_DEADLINE, DEADLINES_SIZE, { refetchInterval: interval });
  const next = queue.nextSlaDeadline;
  return (
    <section aria-labelledby="ov-deadlines">
      <SectionHead
        id="ov-deadlines"
        title="Next deadlines"
        note={
          <>
            Items that need a person, soonest deadline first, right now ·{' '}
            {next ? <span title={formatDateTime(next)}>the next deadline still ahead is {formatRelative(next, now)}</span> : 'no deadline ahead'}
            {queue.overdue > 0 && <> · {plural(queue.overdue, 'is past its deadline', 'are past their deadline')}</>}
          </>
        }
      >
        <Link to={workQueueHref('all')} className="text-link underline underline-offset-2 hover:text-link-hover">
          Open the whole queue
        </Link>
      </SectionHead>
      <div className="border-t border-strong">
        {q.isPending && (
          <div className="py-4">
            <Spinner label="Loading deadlines" />
          </div>
        )}
        {q.isError && (
          <div className="py-3">
            <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />
          </div>
        )}
        {q.isSuccess && q.items.length === 0 && <p className="border-b border-subtle py-3 text-ctl text-secondary">Nothing waits for a person. The queue is clear.</p>}
        {q.items.length > 0 && (
          <table className={TABLE} aria-labelledby="ov-deadlines">
            <thead className={THEAD}>
              <tr>
                {['Deadline', 'Severity', 'Item', 'Level', 'Owner'].map((h) => (
                  <th key={h} scope="col" className={TH}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className={TBODY}>
              {q.items.map((e) => {
                const entities = formatEntities(e.entities_preview, 2);
                return (
                  <tr key={e.id} className={TR}>
                    <Cell label="Deadline" className="lg:w-[1%] lg:whitespace-nowrap">
                      <Sla e={e} now={now} />
                    </Cell>
                    <Cell label="Severity" className="lg:w-[1%]">
                      <span className="inline-block align-middle">
                        <SeverityTag value={escalationSeverity(e)} />
                      </span>
                    </Cell>
                    <Cell label="Item">
                      <Link to={alertHref(e.alert_id)} className="font-medium text-fg hover:underline">
                        {escalationTitle(e)}
                      </Link>
                      {entities && <span className="text-muted"> · {entities}</span>}
                    </Cell>
                    <Cell label="Level" className="text-secondary lg:w-[1%]">
                      {e.level}
                    </Cell>
                    <Cell label="Owner" className="lg:w-[1%] lg:whitespace-nowrap">
                      <Owner e={e} />
                    </Cell>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
