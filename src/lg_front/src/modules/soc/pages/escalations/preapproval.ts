/**
 * Which planned actions an analyst may pre-approve with a true-positive
 * decision: one rule for the decision page's plan and the investigation
 * view's response table.
 */

import { text } from '../../api/fields';
import type { PreviewActionOut } from '../../api/types';

/**
 * The caller may tick this action to run when the decision is recorded: the
 * preview allows it for their role (`can_preapprove`, no `role_lock`) and
 * the action names what it acts on. An action without a target is never
 * pre-approved; it waits on the Approvals page.
 */
export function canPreapprove(a: PreviewActionOut): boolean {
  const locked = a.role_lock === 'admin' || a.role_lock === 'disabled';
  return a.can_preapprove && !locked && Boolean(text(a.target));
}
