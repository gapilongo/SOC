/**
 * The result of a guided source setup: one row per check, in the order a
 * connection is made. A failed check shows what was found and what to
 * change; the checks after it are skipped until it is fixed. The state is
 * always given in words next to the icon, never by colour alone.
 */

import { CheckCircle2, MinusCircle, XCircle, type LucideIcon } from 'lucide-react';

import { isOneOf, SETUP_CHECK_STATUSES, type GuidedCheckOut, type SetupCheckOut, type SetupCheckStatus } from '../../api/types';
import { Banner, StatePill, cx, type StateTone } from '../../../../components/ui';

const STATUS: Record<SetupCheckStatus, { label: string; tone: StateTone; Icon: LucideIcon; icon: string }> = {
  passed: { label: 'Passed', tone: 'ok', Icon: CheckCircle2, icon: 'text-ok-fg' },
  failed: { label: 'Failed', tone: 'bad', Icon: XCircle, icon: 'text-danger-fg' },
  skipped: { label: 'Not checked', tone: 'neutral', Icon: MinusCircle, icon: 'text-muted' },
};

/** A status this app does not know (a newer API) reads as not checked. */
function statusOf(check: SetupCheckOut): SetupCheckStatus {
  return isOneOf(SETUP_CHECK_STATUSES, check.status) ? check.status : 'skipped';
}

/** "All 7 checks passed." / "3 of 7 checks passed, 1 failed." */
export function checksSummary(result: GuidedCheckOut): string {
  const total = result.checks.length;
  const passed = result.checks.filter((c) => statusOf(c) === 'passed').length;
  const failed = result.checks.filter((c) => statusOf(c) === 'failed').length;
  if (failed === 0 && passed === total) return `All ${total} checks passed.`;
  if (failed === 0) return `${passed} of ${total} checks passed; the others did not apply.`;
  return `${passed} of ${total} checks passed, ${failed} failed. Fix what failed, then run the checks again.`;
}

function CheckRow({ check }: { check: SetupCheckOut }) {
  const status = statusOf(check);
  const { label, tone, Icon, icon } = STATUS[status];
  return (
    <li data-status={status} className="flex items-start gap-3 rounded-control border border-subtle bg-canvas/50 p-3">
      <Icon className={cx('mt-0.5 h-5 w-5 flex-none', icon)} strokeWidth={1.75} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium text-fg">
          {check.title}
          <StatePill tone={tone}>{label}</StatePill>
        </p>
        <p className={cx('mt-1 break-words text-sm', status === 'skipped' ? 'text-muted' : 'text-body')}>{check.message}</p>
        {status === 'failed' && check.fix && (
          <Banner tone="warning" title="What to change" className="mt-2">
            <span className="break-words">{check.fix}</span>
          </Banner>
        )}
      </div>
    </li>
  );
}

export function SetupChecks({ result, label }: { result: GuidedCheckOut; label: string }) {
  return (
    <div className="space-y-3">
      <p role="status" className={cx('text-sm font-medium', result.ok ? 'text-fg' : 'text-body')}>
        {checksSummary(result)}
      </p>
      <ol aria-label={label} className="space-y-2">
        {result.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </ol>
    </div>
  );
}
