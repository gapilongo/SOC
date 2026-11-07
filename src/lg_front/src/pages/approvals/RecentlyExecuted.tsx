import type { ActionOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { StatusBadge } from '../../components/Badge';
import { ActionControls, ROLLBACK_REASONS } from '../actions/ActionDetails';
import { VERIFICATION_HELP, VerificationBadge } from '../actions/VerificationBadge';
import { Button, ErrorMessage, LoadingState } from '../../components/ui';
import { formatDateTime, formatRelative, humanize, shortId } from '../../lib/format';
import { approverLabel } from './approvals';
import type { ActionList } from './useActionList';

/** The statuses this section lists: the action ran (or was recorded as a dry run). */
export const EXECUTED_STATUSES = ['succeeded', 'failed', 'dry_run'];

/** How many executed actions the section shows; the rest are under All actions. */
export const RECENT_ROWS = 10;

function FollowUpNote({ action }: { action: ActionOut }) {
  if (action.status === 'dry_run') return <span className="text-xs text-muted">Recorded only (dry run); nothing was executed.</span>;
  if (action.status !== 'succeeded' || action.rollback?.available) return null;
  const reason = ROLLBACK_REASONS[action.rollback?.reason ?? ''] ?? (action.reversible === false ? 'This action cannot be undone.' : null);
  return reason ? <span className="text-xs text-muted">{reason}</span> : null;
}

/**
 * The latest executed actions with their verification, and the follow-ups the
 * caller's role allows: Roll back, Retry, Re-check (components/actions).
 */
export function RecentlyExecuted({
  list,
  now,
  onOpenAlert,
  onShowAll,
}: {
  list: ActionList;
  now: number;
  onOpenAlert: (alertId: string) => void;
  onShowAll: () => void;
}) {
  const { principal } = useAuth();
  const rows = list.items.slice(0, RECENT_ROWS);
  return (
    <section aria-labelledby="ap-done" className="overflow-hidden rounded-card border border-subtle bg-raised">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle px-4 py-3">
        <h2 id="ap-done" className="text-sm font-semibold text-fg">
          Recently executed
        </h2>
        {(list.items.length > RECENT_ROWS || list.hasNextPage) && (
          <Button size="sm" variant="quiet" onClick={onShowAll}>
            Show all executed actions
          </Button>
        )}
      </header>
      {list.isPending && <LoadingState label="Loading executed actions" />}
      {list.isError && (
        <div className="p-4">
          <ErrorMessage error={list.error} onRetry={() => void list.refetch()} />
        </div>
      )}
      {list.isSuccess && rows.length === 0 && <p className="px-4 py-3 text-ctl text-secondary">No action has been executed yet.</p>}
      {rows.length > 0 && (
        // A scrollable region must be reachable by keyboard (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        <div role="region" aria-labelledby="ap-done" tabIndex={0} className="relative overflow-x-auto">
          <table className="w-full min-w-[860px] text-left text-ctl">
            <caption className="sr-only">Recently executed actions</caption>
            <thead className="text-xs text-secondary">
              <tr>
                <th scope="col" className="px-4 py-2 font-medium">Action</th>
                <th scope="col" className="px-2 py-2 font-medium">Runs via</th>
                <th scope="col" className="px-2 py-2 font-medium">Executed</th>
                <th scope="col" className="px-2 py-2 font-medium">Status</th>
                <th scope="col" className="px-2 py-2 font-medium">Verification</th>
                <th scope="col" className="px-4 py-2 text-right font-medium">
                  <span className="sr-only">Follow-up</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => {
                const by = approverLabel(a.approved_by, principal?.userId);
                const when = a.executed_at ?? a.updated_at;
                return (
                  <tr key={a.id} className="border-t border-subtle align-top">
                    <td className="px-4 py-2.5">
                      <p className="font-medium text-fg">{humanize(a.action_type)}</p>
                      {/* One line; the full target is the tooltip (and the All actions view). */}
                      <code className="block max-w-[16rem] truncate font-mono text-xs text-body" title={a.target}>
                        {a.target}
                      </code>
                      <p className="text-xs text-secondary">
                        {by ?? 'Not approved by anyone'} · alert{' '}
                        <button
                          type="button"
                          className="rounded-tag font-mono text-link hover:text-link-hover hover:underline"
                          onClick={() => onOpenAlert(a.alert_id)}
                          aria-label={`Open alert ${a.alert_id}`}
                        >
                          {shortId(a.alert_id)}
                        </button>
                        {a.rollback_of && <> · rollback of {shortId(a.rollback_of)}</>}
                      </p>
                    </td>
                    <td className="px-2 py-2.5 text-body">{a.connector ?? '-'}</td>
                    <td className="whitespace-nowrap px-2 py-2.5 text-secondary">
                      <time dateTime={when} title={formatDateTime(when)}>
                        {formatRelative(when, now)}
                      </time>
                    </td>
                    <td className="px-2 py-2.5">
                      <StatusBadge value={a.status} />
                    </td>
                    <td className="px-2 py-2.5">
                      <VerificationBadge value={a.verification} detail={a.verification_detail} />
                      {a.verification && <p className="mt-0.5 max-w-[16rem] text-xs text-secondary">{VERIFICATION_HELP[a.verification]}</p>}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <div className="flex flex-col items-end gap-1">
                        <ActionControls action={a} />
                        <FollowUpNote action={a} />
                      </div>
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
