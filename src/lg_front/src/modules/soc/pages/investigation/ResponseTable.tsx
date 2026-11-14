/**
 * The proposed response of an escalation that still waits for its decision:
 * every planned action with its exact target, whether it can be undone, the
 * guardrail result and what approval it needs. Nothing has run. A ticked
 * action runs the moment a true positive is recorded; the rest waits on the
 * Approvals page. What may be ticked is the decision page's rule
 * (escalations/preapproval.ts), and a target is shown as everywhere a human
 * approves an action (ActionTarget).
 */

import { useId } from 'react';

import { text } from '../../api/fields';
import type { PreviewActionOut } from '../../api/types';
import { ActionTarget } from '../../../../components/ActionTarget';
import { Glyph, SeverityBars } from '../../components/investigation';
import { cx } from '../../../../components/ui';
import { humanize } from '../../../../lib/format';
import { canPreapprove } from '../escalations/preapproval';

/** Whether the caller may tick this action to run on a true positive; when not, what happens to it instead. */
export function preapproval(a: PreviewActionOut): { allowed: boolean; instead: string | null } {
  if (canPreapprove(a)) return { allowed: true, instead: null };
  if (a.role_lock === 'disabled' || a.without_preapproval === 'blocked') return { allowed: false, instead: 'Not available' };
  if (a.role_lock === 'admin') return { allowed: false, instead: 'Needs an admin' };
  if (!text(a.target)) return { allowed: false, instead: 'No target sent: approve it on the Approvals page' };
  return { allowed: false, instead: a.without_preapproval === 'automatic' ? 'Runs automatically' : 'Waits on the Approvals page' };
}

/** The `approved_actions` entries of the ticked actions that may still be pre-approved. */
export function preapprovedEntries(actions: readonly PreviewActionOut[], selected: ReadonlySet<string>): string[] {
  return actions.filter((a) => selected.has(a.approval_entry) && preapproval(a).allowed).map((a) => a.approval_entry);
}

const TH = 'whitespace-nowrap border-b border-strong px-2.5 py-[7px] text-left font-mono text-2xs font-medium uppercase tracking-[0.05em] text-muted first:pl-0';
const TD = 'block px-0 py-0.5 align-top text-ctl min-[900px]:table-cell min-[900px]:border-b min-[900px]:border-subtle min-[900px]:px-2.5 min-[900px]:py-[7px] min-[900px]:first:pl-0';
const SMALL = 'block text-xs text-muted';

/** The column name before a value, for the stacked records of a narrow screen. */
function Label({ children }: { children: string }) {
  return <span className="mr-2 inline-block min-w-[92px] font-mono text-[10.5px] font-medium uppercase tracking-[0.05em] text-muted min-[900px]:hidden">{children}</span>;
}

function Row({ a, checked, disabled, onToggle }: { a: PreviewActionOut; checked: boolean; disabled: boolean; onToggle: (on: boolean) => void }) {
  const id = useId();
  const target = text(a.target);
  const blocked = a.guardrail.verdict !== 'passed' || a.role_lock === 'disabled' || a.without_preapproval === 'blocked';
  const { allowed, instead } = preapproval(a);
  const name = humanize(a.action_type);
  return (
    <tr data-entry={a.approval_entry} className={cx('block border-b border-strong py-2.5 min-[900px]:table-row min-[900px]:border-0 min-[900px]:py-0', blocked && 'text-muted')}>
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
        <small className={SMALL}>
          {a.connector.name}
          {a.connector.ready ? '' : ' (not ready)'}
          {a.connector.live === false ? ', dry run' : ''}
        </small>
      </td>
      <td className={cx(TD, 'text-muted min-[900px]:whitespace-nowrap')}>
        <Label>Reach</Label>
        Not available yet
      </td>
      <td className={cx(TD, !blocked && (a.reversible ? 'text-body' : 'text-warn-fg'))}>
        <Label>Undo</Label>
        {a.reversible ? 'Yes' : 'No'}
        {a.reversible && a.inverse_action && <small className={SMALL}>{humanize(a.inverse_action)}</small>}
        {!a.reversible && a.irreversible_note && <small className={SMALL}>{a.irreversible_note}</small>}
      </td>
      <td className={TD}>
        <Label>Guardrail</Label>
        {a.guardrail.verdict === 'passed' ? (
          <span className="inline-flex items-center gap-[5px] whitespace-nowrap text-[12.5px] text-body">
            <Glyph name="tick" className="h-[11px] w-[11px] text-state-ok" />
            Passed
          </span>
        ) : (
          <span className="inline-flex items-center gap-[5px] whitespace-nowrap text-[12.5px] text-danger-fg">
            <Glyph name="cannot" className="h-[11px] w-[11px]" />
            Blocked
          </span>
        )}
        {a.guardrail.reason && <small className={SMALL}>{a.guardrail.reason}</small>}
      </td>
      <td className={TD}>
        <Label>Approval</Label>
        {allowed ? (
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
  selected,
  onChange,
  disabled,
}: {
  actions: PreviewActionOut[];
  /** The `approval_entry` of every ticked action. */
  selected: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
  /** The caller cannot record the decision now: the plan is read-only. */
  disabled: boolean;
}) {
  return (
    <table className="block w-full border-collapse min-[900px]:table">
      <thead className="sr-only min-[900px]:not-sr-only min-[900px]:table-header-group">
        <tr>
          <th scope="col" className={TH}>
            Action
          </th>
          <th scope="col" className={TH}>
            Exact target
          </th>
          <th scope="col" className={TH}>
            Reach
          </th>
          <th scope="col" className={TH}>
            Can it be undone
          </th>
          <th scope="col" className={TH}>
            Guardrail
          </th>
          <th scope="col" className={TH}>
            Approval
          </th>
        </tr>
      </thead>
      <tbody className="block min-[900px]:table-row-group">
        {actions.map((a, i) => (
          <Row
            key={a.approval_entry || `${a.action_type}:${a.target}:${i}`}
            a={a}
            checked={selected.has(a.approval_entry)}
            disabled={disabled}
            onToggle={(on) => {
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
