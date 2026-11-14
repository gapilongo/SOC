/**
 * Which planned actions an analyst may pre-approve with a true-positive
 * decision: one rule for the decision page's plan and the investigation
 * view's response table.
 */

import { text } from '../../api/fields';
import type { PreviewActionOut, ProposedActionOut } from '../../api/types';

/** What the rule reads of an action: the same fields on a response preview and on the investigation read model. */
export type Preapprovable = Pick<PreviewActionOut, 'can_preapprove' | 'role_lock' | 'target'> | Pick<ProposedActionOut, 'can_preapprove' | 'role_lock' | 'target'>;

/**
 * The caller may tick this action to run when the decision is recorded: the
 * preview allows it for their role (`can_preapprove`, no `role_lock`) and
 * the action names what it acts on. An action without a target is never
 * pre-approved; it waits on the Approvals page.
 */
export function canPreapprove(a: Preapprovable): boolean {
  const locked = a.role_lock === 'admin' || a.role_lock === 'disabled';
  return a.can_preapprove === true && !locked && Boolean(text(a.target));
}
