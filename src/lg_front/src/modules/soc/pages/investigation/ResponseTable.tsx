/**
 * The response of an alert, as the investigation read model gives it: every
 * action with its exact target, whether it can be undone and the guardrail
 * result.
 *
 * A `preview` is what a true positive would propose now: nothing has run, a
 * ticked action runs the moment the decision is recorded, and the rest waits
 * on the Approvals page. What may be ticked is the decision page's rule
 * (escalations/preapproval.ts). A `plan` is on the ledger: each action shows
 * its status instead. Targets are shown as everywhere a human approves an
 * action (ActionTarget).
 */

import { useId, type ReactNode } from 'react';

import { text } from '../../api/fields';
import type { ProposedActionOut } from '../../api/types';
import { ActionTarget } from '../../../../components/ActionTarget';
import { Glyph, SeverityBars } from '../../components/investigation';
import { cx } from '../../../../components/ui';
import { humanize } from '../../../../lib/format';
import { canPreapprove } from '../escalations/preapproval';

/** Whether the caller may tick this action to run on a true positive; when not, what happens to it instead. */
export function preapproval(a: ProposedActionOut): { allowed: boolean; instead: string | null } {
  if (canPreapprove(a) && text(a.approval_entry)) return { allowed: true, instead: null };
  if (a.role_lock === 'disabled' || a.without_preapproval === 'blocked') return { allowed: false, instead: 'Not available' };
  if (a.role_lock === 'admin') return { allowed: false, instead: 'Needs an admin' };
  if (!text(a.target)) return { allowed: false, instead: 'No target sent: approve it on the Approvals page' };
  return { allowed: false, instead: a.without_preapproval === 'automatic' ? 'Runs automatically' : 'Waits on the Approvals page' };
}

/** The `approved_actions` entries of the ticked actions that may still be pre-approved. */
export function preapprovedEntries(actions: readonly ProposedActionOut[], selected: ReadonlySet<string>): string[] {
  return actions.flatMap((a) => (a.approval_entry && selected.has(a.approval_entry) && preapproval(a).allowed ? [a.approval_entry] : []));
}

const STATUS_WORDS: Record<string, string> = {
  proposed: 'Proposed',
  awaiting_approval: 'Waits for an approval',
  approved: 'Approved, not run yet',
  rejected: 'Rejected',
  executing: 'Running',
  succeeded: 'Ran',
  failed: 'Failed',
  dry_run: 'Dry run: recorded, nothing changed',
  blocked: 'Blocked',
};

const TH = 'whitespace-nowrap border-b border-strong px-2.5 py-1.5 text-left font-mono text-2xs font-medium uppercase tracking-label text-muted first:pl-0';
const TD = 'block px-0 py-0.5 align-top text-ctl min-[900px]:table-cell min-[900px]:border-b min-[900px]:border-subtle min-[900px]:px-2.5 min-[900px]:py-1.5 min-[900px]:first:pl-0';
const SMALL = 'block text-xs text-muted';

/** The column name before a value, for the stacked records of a narrow screen. */
function Label({ children }: { children: string }) {
  return <span className="mr-2 inline-block min-w-[92px] font-mono text-2xs font-medium uppercase tracking-label text-muted min-[900px]:hidden">{children}</span>;
}

function Row({
  a,
  planned,
  checked,
  disabled,
  onToggle,
  decide,
}: {
  a: ProposedActionOut;
  planned: boolean;
  checked: boolean;
  disabled: boolean;
  onToggle: (on: boolean) => void;
  decide?: ReactNode;
}) {
  const id = useId();
  const target = text(a.target);
  const blocked = a.guardrail?.verdict === 'blocked' || a.role_lock === 'disabled' || a.without_preapproval === 'blocked' || a.status === 'blocked' || a.status === 'rejected';
  const { allowed, instead } = preapproval(a);
  const name = humanize(a.action_type);
  return (
    <tr data-action={a.action_id ?? a.approval_entry ?? a.action_type} className={cx('block border-b border-strong py-2.5 min-[900px]:table-row min-[900px]:border-0 min-[900px]:py-0', blocked && 'text-muted')}>
      <td className={TD}>
        <span className={cx('font-semibold min-[900px]:whitespace-nowrap', blocked ? 'text-secondary' : 'text-fg')}>{name}</span>
        {a.description && a.description !== name && <small className={SMALL}>{a.description}</small>}
      </td>
      <td className={TD}>
        <Label>Target</Label>
        {target ? (
          // As wide as the target up to 20rem, so a short one never breaks inside a word in a tight column.
          <span className="inline-block max-w-full align-top min-[900px]:w-max min-[900px]:max-w-[20rem]">
            <ActionTarget target={target} />
          </span>
        ) : (
          <span className="text-warn-fg">not sent</span>
        )}
      </td>
      <td className={cx(TD, !blocked && a.reversible === false && 'text-warn-fg')}>
        <Label>Undo</Label>
        {a.reversible === null ? <span className="text-muted">Not recorded</span> : a.reversible ? 'Yes' : 'No'}
        {a.reversible && a.inverse_action && <small className={SMALL}>{humanize(a.inverse_action)}</small>}
        {a.reversible === false && a.irreversible_note && <small className={SMALL}>{a.irreversible_note}</small>}
      </td>
      <td className={TD}>
        <Label>Guardrail</Label>
        {!a.guardrail ? (
          <span className="text-muted">Not checked again</span>
        ) : a.guardrail.verdict === 'passed' ? (
          <span className="inline-flex items-center gap-1 whitespace-nowrap text-ctl text-body">
            <Glyph name="tick" className="h-3 w-3 text-state-ok" />
            Passed
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 whitespace-nowrap text-ctl text-danger-fg">
            <Glyph name="cannot" className="h-3 w-3" />
            Blocked
          </span>
        )}
        {a.guardrail?.reason && <small className={SMALL}>{a.guardrail.reason}</small>}
      </td>
      <td className={TD}>
        <Label>{planned ? 'Status' : 'Approval'}</Label>
        {planned ? (
          <span data-status={a.status ?? undefined} className={blocked ? undefined : 'text-body'}>
            {a.status ? (STATUS_WORDS[a.status] ?? humanize(a.status)) : 'Not recorded'}
            {decide}
          </span>
        ) : allowed ? (
          <label htmlFor={id} className={cx('inline-flex items-center gap-1.5 text-body min-[900px]:whitespace-nowrap', disabled ? 'cursor-not-allowed' : 'cursor-pointer')}>
            <input
              id={id}
              type="checkbox"
              className="h-4 w-4 flex-none accent-accent disabled:cursor-not-allowed"
              checked={checked}
              disabled={disabled}
              onChange={(e) => onToggle(e.target.checked)}
            />
            <span>
              Run on true positive
              <span className="sr-only">
                : {name} on {target}
              </span>
            </span>
          </label>
        ) : (
          <span className={blocked ? undefined : 'text-body'}>{instead}</span>
        )}
        <small className="block pt-0.5">
          <SeverityBars value={a.risk} suffix="risk" />
        </small>
      </td>
    </tr>
  );
}

export function ResponseTable({
  actions,
  planned = false,
  selected,
  onChange,
  disabled,
  decide,
}: {
  actions: ProposedActionOut[];
  /** The actions are on the ledger (`response.source` is `plan`): each shows its status, none can be ticked. */
  planned?: boolean;
  /** The `approval_entry` of every ticked action. */
  selected: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
  /** The caller cannot record the decision now: the plan is read-only. */
  disabled: boolean;
  /** planned: what the caller may do about an action now (approve or reject one that waits), under its status. */
  decide?: (action: ProposedActionOut) => ReactNode;
}) {
  return (
    <table data-rows="free" className="block w-full border-collapse min-[900px]:table">
      <thead className="sr-only min-[900px]:not-sr-only min-[900px]:table-header-group">
        <tr>
          <th scope="col" className={TH}>
            Action
          </th>
          <th scope="col" className={TH}>
            Exact target
          </th>
          <th scope="col" className={TH}>
            Can it be undone
          </th>
          <th scope="col" className={TH}>
            Guardrail
          </th>
          <th scope="col" className={TH}>
            {planned ? 'Status' : 'Approval'}
          </th>
        </tr>
      </thead>
      <tbody className="block min-[900px]:table-row-group">
        {actions.map((a, i) => (
          <Row
            key={a.action_id ?? a.approval_entry ?? `${a.action_type}:${a.target}:${i}`}
            a={a}
            planned={planned}
            checked={Boolean(a.approval_entry && selected.has(a.approval_entry))}
            disabled={disabled}
            decide={planned ? decide?.(a) : undefined}
            onToggle={(on) => {
              if (!a.approval_entry) return;
              const next = new Set(selected);
              if (on) next.add(a.approval_entry);
              else next.delete(a.approval_entry);
              onChange(next);
            }}
          />
        ))}
      </tbody>
    </table>
  );
}
