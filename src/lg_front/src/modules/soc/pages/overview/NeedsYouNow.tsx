/**
 * "Needs you now": the signed-in person's own work, one line and one action
 * each. What they hold and its first deadline, the approvals their role may
 * give, what nobody holds, and the sampled AI closes waiting for a blind
 * label. Every count is "right now", never the window.
 */

import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { endpoints, type EscalationFilters } from '../../api/endpoints';
import { escalationTitle, type QueueFigures } from '../../api/fields';
import { useEscalationsTop } from '../../api/hooks';
import { qk } from '../../api/queryKeys';
import { useApi, useAuth } from '../../../../auth/AuthContext';
import { approvalRoleFor, can, roleAtLeast } from '../../../../auth/roles';
import { ErrorMessage, Spinner, buttonClass } from '../../../../components/ui';
import { formatDuration, formatInt, formatRelative } from '../../../../lib/format';
import { alertHref, APPROVALS_HREF } from '../../lib/links';
import { slaStatus } from '../../lib/sla';
import { RISK_ORDER, plural } from './figures';
import { BLIND_AUDIT_HREF, workQueueHref } from './links';

/** Active items: open or claimed (the API's queue figures count these). */
const ACTIVE = ['open', 'claimed'];
const MINE: EscalationFilters = { status: ACTIVE, assigned_to: 'me', order: 'sla_deadline' };
const UNASSIGNED_OVERDUE: EscalationFilters = { status: ACTIVE, assigned_to: 'none', overdue: true, order: 'sla_deadline' };

const TITLE_LINK = 'font-medium text-fg underline decoration-control underline-offset-2 hover:decoration-fg';

function Need({ n, title, action, children }: { n: ReactNode; title: string; action: ReactNode; children: ReactNode }) {
  return (
    <li className="grid grid-cols-[56px_minmax(0,1fr)] items-center gap-x-4 border-b border-subtle py-[11px] md:grid-cols-[76px_minmax(0,1fr)_auto]">
      <span className="text-2xl font-semibold leading-none tracking-[-0.02em] tabular-nums text-fg md:text-[30px]">{n}</span>
      <div className="min-w-0">
        <p className="text-[15px] font-medium text-fg">{title}</p>
        <div className="mt-px break-words text-[12.5px] text-secondary">{children}</div>
      </div>
      {action}
    </li>
  );
}

function Action({ to, primary, children }: { to: string; primary: boolean; children: ReactNode }) {
  return (
    <Link to={to} className={buttonClass(primary ? 'primary' : 'secondary', 'sm', 'col-start-2 mt-1.5 justify-self-start md:col-start-3 md:mt-0')}>
      {children}
    </Link>
  );
}

/** "The first deadline is in 4 minutes: <the item>." (one request, only while the caller holds something). */
function FirstDeadline({ now, interval }: { now: number; interval: number | false }) {
  const q = useEscalationsTop(MINE, 1, { refetchInterval: interval });
  if (q.isError) return <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />;
  const e = q.items[0];
  if (!e) return null;
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  const when = formatRelative(e.sla_deadline, now);
  const lead = s.seconds === null ? 'First in your queue' : s.seconds < 0 ? `The first deadline passed ${when}` : `The first deadline is ${when}`;
  return (
    <p>
      {lead}:{' '}
      <Link to={alertHref(e.alert_id)} className={TITLE_LINK}>
        {escalationTitle(e)}
      </Link>
      .
    </p>
  );
}

/** "Most overdue: <the item>, 2h 14m past its deadline." (one request, only while something is overdue). */
function MostOverdue({ now, interval }: { now: number; interval: number | false }) {
  const q = useEscalationsTop(UNASSIGNED_OVERDUE, 1, { refetchInterval: interval });
  if (q.isError) return <ErrorMessage error={q.error} compact onRetry={() => void q.refetch()} />;
  const e = q.items[0];
  if (!e) return null;
  const s = slaStatus(e.sla_deadline, now, e.created_at);
  return (
    <p className="inline">
      {' '}
      Most overdue:{' '}
      <Link to={alertHref(e.alert_id)} className={TITLE_LINK}>
        {escalationTitle(e)}
      </Link>
      {s.seconds !== null && s.seconds < 0 && <>, {formatDuration(-s.seconds)} past its deadline</>}.
    </p>
  );
}

/** "13 wait for approval; 4 of them need an admin. By risk: 2 high, 11 medium." */
function approvalsDetail(queue: QueueFigures, isAdmin: boolean): string {
  if (queue.pendingTotal === 0) return 'Nothing waits for approval.';
  const adminOnly = isAdmin ? 0 : Object.entries(queue.pendingByRisk).reduce((sum, [risk, n]) => sum + (approvalRoleFor(risk) === 'admin' ? n : 0), 0);
  const known = RISK_ORDER.filter((r) => queue.pendingByRisk[r]);
  const other = Object.keys(queue.pendingByRisk).filter((r) => !(RISK_ORDER as readonly string[]).includes(r) && queue.pendingByRisk[r]);
  const risks = [...known, ...other].map((r) => `${formatInt(queue.pendingByRisk[r])} ${r}`);
  return [
    `${plural(queue.pendingTotal, 'waits', 'wait')} for approval`,
    adminOnly > 0 ? `; ${plural(adminOnly, 'of them needs', 'of them need')} an admin` : '',
    '.',
    risks.length > 0 ? ` By risk: ${risks.join(', ')}.` : '',
  ].join('');
}

/** The sampled AI closes waiting for a label: the first page of the blind queue (the page the labeller opens). */
function useAuditBacklog(enabled: boolean, interval: number | false) {
  const api = useApi();
  const q = useQuery({
    queryKey: qk.blindAudit.queue('pending'),
    queryFn: ({ signal }) => endpoints.blindAuditItems(api, 'pending', undefined, signal),
    enabled,
    refetchInterval: interval,
    refetchIntervalInBackground: false,
  });
  const count = q.data ? q.data.items.length : null;
  // A full page with a cursor: at least this many wait.
  return { ...q, count, more: Boolean(q.data?.next_cursor) };
}

export function NeedsYouNow({ queue, now, interval }: { queue: QueueFigures; now: number; interval: number | false }) {
  const { principal } = useAuth();
  const claimer = can.claim(principal);
  const approver = roleAtLeast(principal?.role, 'analyst');
  const labeller = can.decide(principal);
  const audit = useAuditBacklog(labeller, interval);
  const breaching = queue.unassignedBreaching;

  // One primary action on the page: the first line that has something to do.
  const waiting: Array<[string, boolean]> = [
    ['mine', claimer && queue.myClaimed > 0],
    ['approvals', approver && queue.pendingMine > 0],
    ['unassigned', queue.unassigned > 0],
    ['audit', labeller && (audit.count ?? 0) > 0],
  ];
  const primary = waiting.find(([, has]) => has)?.[0];

  return (
    <section aria-labelledby="ov-now">
      <h2 id="ov-now" className="eyebrow mb-1.5">
        Needs you now
      </h2>
      <ul className="border-t border-strong">
        {claimer && (
          <Need
            n={formatInt(queue.myClaimed)}
            title={queue.myClaimed === 1 ? 'item you own is waiting' : 'items you own are waiting'}
            action={
              <Action to={workQueueHref('mine')} primary={primary === 'mine'}>
                Open my queue
              </Action>
            }
          >
            {queue.myClaimed > 0 ? <FirstDeadline now={now} interval={interval} /> : <p>You hold nothing. Claim an item from the queue to see it here.</p>}
          </Need>
        )}
        {approver && (
          <Need
            n={formatInt(queue.pendingMine)}
            title={queue.pendingMine === 1 ? 'response action you can approve' : 'response actions you can approve'}
            action={
              <Action to={APPROVALS_HREF} primary={primary === 'approvals'}>
                Open approvals
              </Action>
            }
          >
            <p>{approvalsDetail(queue, can.admin(principal))}</p>
          </Need>
        )}
        <Need
          n={formatInt(queue.unassigned)}
          title={queue.unassigned === 1 ? 'item nobody has claimed' : 'items nobody has claimed'}
          action={
            <Action to={workQueueHref('unassigned')} primary={primary === 'unassigned'}>
              Open the queue
            </Action>
          }
        >
          <p className="inline">
            {queue.unassigned === 0
              ? 'Every item that needs a person has an owner.'
              : breaching > 0
                ? `${plural(breaching, 'of them is', 'of them are')} past ${breaching === 1 ? 'its' : 'their'} deadline.`
                : 'None of them is past its deadline.'}
          </p>
          {breaching > 0 && <MostOverdue now={now} interval={interval} />}
        </Need>
        {labeller && (
          <Need
            n={audit.count === null ? '–' : `${formatInt(audit.count)}${audit.more ? '+' : ''}`}
            title={audit.count === 1 && !audit.more ? 'sampled AI close waits for a blind-audit label' : 'sampled AI closes wait for a blind-audit label'}
            action={
              <Action to={BLIND_AUDIT_HREF} primary={primary === 'audit'}>
                Label them
              </Action>
            }
          >
            {audit.isError ? (
              <ErrorMessage error={audit.error} compact onRetry={() => void audit.refetch()} />
            ) : audit.count === null ? (
              <Spinner label="Loading the blind-audit queue" />
            ) : audit.count === 0 ? (
              <p>No sample waits for a label.</p>
            ) : (
              <p>You label from the evidence; the AI&apos;s verdict stays hidden until you have chosen.</p>
            )}
          </Need>
        )}
      </ul>
    </section>
  );
}
