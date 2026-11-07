import { Check, Lock, X } from 'lucide-react';
import { useId, type ReactNode } from 'react';

import type { ActionOut } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { RiskBadge } from '../../components/Badge';
import type { PendingDecision } from '../actions/ApprovalDialog';
import { Button, Card, cx } from '../../components/ui';
import { formatDateTime, formatRelative, humanize, shortId } from '../../lib/format';
import {
  approvalAccess,
  guardrailSummary,
  readBlastRadius,
  requesterLabel,
  reversibleText,
  scopeText,
  usageLevel,
  usageText,
  type Usage,
} from './approvals';

function Item({ term, children, span }: { term: string; children: ReactNode; span?: 'two' | 'full' }) {
  return (
    <div className={cx('min-w-0', span === 'two' && 'sm:col-span-2', span === 'full' && 'col-span-full')}>
      <dt className="text-xs text-secondary">{term}</dt>
      <dd className="mt-0.5 text-ctl text-body">{children}</dd>
    </div>
  );
}

const LEVEL_DOT = { ok: 'bg-state-ok', near: 'bg-state-waiting', reached: 'bg-state-bad' } as const;

function UsageLine({ label, usage }: { label: string; usage: Usage }) {
  const level = usageLevel(usage);
  return (
    <li className="flex items-start gap-1.5">
      <span className={cx('mt-[7px] h-1.5 w-1.5 flex-none rounded-full', LEVEL_DOT[level])} aria-hidden="true" />
      <span>
        <span className="text-secondary">{label}: </span>
        <span className="tabular-nums">{usageText(usage)}</span>
        {level === 'reached' && <span className="font-medium text-danger-fg"> · limit reached, executing now would be blocked</span>}
        {level === 'near' && <span className="text-warn-fg"> · close to the limit</span>}
      </span>
    </li>
  );
}

function BlastRadiusFigure({ action }: { action: ActionOut }) {
  const b = readBlastRadius(action);
  if (!b) return null;
  const scope = scopeText(b);
  return (
    <Item term="Blast radius" span={b.type || b.tenant ? 'two' : undefined}>
      {scope && <p className="break-words">{scope}</p>}
      {(b.type || b.tenant) && (
        <ul className="mt-0.5 space-y-0.5 text-xs" aria-label="Hourly usage">
          {b.type && <UsageLine label={`${humanize(action.action_type)} per hour`} usage={b.type} />}
          {b.tenant && <UsageLine label="All actions of the tenant per hour" usage={b.tenant} />}
        </ul>
      )}
    </Item>
  );
}

/**
 * One action waiting for a human: what it does and to what, where it came
 * from, the guardrail re-check, the blast radius, and Approve / Reject as the
 * caller's role allows (locked with the reason otherwise).
 */
export function PendingCard({
  action,
  now,
  siblings,
  onDecide,
  onOpenAlert,
}: {
  action: ActionOut;
  now: number;
  /** Other pending actions of the same alert on the page. */
  siblings: number;
  onDecide: (d: PendingDecision) => void;
  onOpenAlert: (alertId: string) => void;
}) {
  const { principal } = useAuth();
  const access = approvalAccess(principal, action);
  const guardrail = guardrailSummary(action);
  const reversible = reversibleText(action);
  const lockId = useId();
  const blocked = guardrail?.verdict === 'blocked';
  return (
    <li>
      <Card variant="approval">
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
            <div className="min-w-0">
              <h3 className="text-base font-semibold text-fg">
                {humanize(action.action_type)}
                {action.rollback_of && <span className="font-normal text-secondary"> (rollback)</span>}
              </h3>
              <p className="flex flex-wrap items-center gap-x-1 text-xs text-secondary">
                <span>For alert</span>
                <button
                  type="button"
                  className="rounded-tag font-mono text-link hover:text-link-hover hover:underline"
                  onClick={() => onOpenAlert(action.alert_id)}
                  aria-label={`Open alert ${action.alert_id}`}
                >
                  {shortId(action.alert_id)}
                </button>
                <span>
                  · requested <time dateTime={action.created_at} title={formatDateTime(action.created_at)}>{formatRelative(action.created_at, now)}</time> by{' '}
                  {requesterLabel(action.requested_by, principal?.userId)}
                </span>
                {action.rollback_of && <span>· undoes action {shortId(action.rollback_of)}</span>}
              </p>
            </div>
            <RiskBadge value={action.risk_level} />
          </div>

          <dl className="grid grid-cols-1 gap-x-4 gap-y-2.5 sm:grid-cols-2 xl:grid-cols-4">
            <Item term="Target">
              <code className="break-all font-mono text-xs text-fg">{action.target}</code>
            </Item>
            <BlastRadiusFigure action={action} />
            {action.connector && <Item term="Runs via">{action.connector}</Item>}
            {reversible && (
              <Item term="Reversible">
                <span className={cx(!reversible.reversible && 'text-warn-fg')}>{reversible.text}</span>
              </Item>
            )}
            {guardrail && (
              <Item term="Guardrails" span="full">
                <span className="flex items-start gap-1.5">
                  <span className={cx('mt-[7px] h-1.5 w-1.5 flex-none rounded-full', blocked ? 'bg-state-bad' : 'bg-state-ok')} aria-hidden="true" />
                  <span>
                    <span className={cx('font-medium', blocked ? 'text-danger-fg' : 'text-fg')}>{guardrail.label}</span>
                    <span className="text-secondary"> · {guardrail.detail}</span>
                  </span>
                </span>
              </Item>
            )}
          </dl>

          <div className="flex flex-wrap items-center gap-2 border-t border-subtle pt-3">
            {(access.approve || access.reject) && (
              <Button
                size="sm"
                variant={blocked ? 'secondary' : 'primary'}
                disabled={!access.approve}
                aria-describedby={access.lock ? lockId : undefined}
                onClick={() => onDecide({ action, verb: 'approve' })}
                icon={access.approve ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Lock className="h-3.5 w-3.5" aria-hidden="true" />}
              >
                Approve
              </Button>
            )}
            {access.reject && (
              <Button size="sm" variant="destructive" onClick={() => onDecide({ action, verb: 'reject' })} icon={<X className="h-3.5 w-3.5" aria-hidden="true" />}>
                Reject
              </Button>
            )}
            {access.reject && siblings > 0 && (
              <Button size="sm" variant="quiet" onClick={() => onDecide({ action, verb: 'reject', rejectRemaining: true })}>
                Reject all pending for this alert
              </Button>
            )}
            {access.lock && (
              <span id={lockId} className="ml-auto flex items-center gap-1.5 text-xs text-body">
                <Lock className="h-3.5 w-3.5 flex-none text-secondary" aria-hidden="true" />
                {access.lock}
              </span>
            )}
          </div>
        </div>
      </Card>
    </li>
  );
}
