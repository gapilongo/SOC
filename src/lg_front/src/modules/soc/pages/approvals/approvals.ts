/**
 * What the Approvals page says about a response action, as pure functions:
 * who may approve it (mirroring the API's rules), why a human must approve,
 * its blast radius and hourly usage, and the queue figures of the header.
 *
 * Newer APIs add `guardrail`, `blast_radius`, `reversible` and
 * `irreversible_note`; older APIs omit them and a malformed value must not
 * crash the page, so every reader returns null for anything it cannot use and
 * the page omits that figure rather than show a wrong one.
 */

import { finite, readCounts, readGuardrail, text, totalOf, type QueueFigures } from '../../../../api/fields';
import type { ActionOut } from '../../../../api/types';
import { approvalRoleFor, can, decisionBlockedReason } from '../../../../auth/roles';
import type { Principal } from '../../../../auth/store';
import { humanize, shortId } from '../../../../lib/format';
import { describeBlockedReason } from '../../lib/guardrails';

/** `requested_by` of the actions the workflow proposes (lg_sotf.models.vocabulary). */
export const WORKFLOW_REQUESTER = 'agent:workflow';
/** `approved_by` of an action the autonomy policy approved (no human). */
export const POLICY_APPROVER = 'policy:auto';

// Who may approve --------------------------------------------------------------

export interface ApprovalAccess {
  /** The caller may press Approve. */
  approve: boolean;
  /** The caller may press Reject. */
  reject: boolean;
  /**
   * Why Approve is locked (shown next to it), or null when it is not. A
   * caller who may neither approve nor reject gets no buttons, only this.
   */
  lock: string | null;
}

/**
 * The API's approval rules (lg_sotf.services.response.approval_allowed and
 * the REVIEWER dependency): analysts approve low and medium risk, admins any
 * risk; nothing whose risk the tenant's autonomy policy disables (the
 * guardrail re-check reports it as `autonomy_disabled`); a decision needs a
 * user account of the tenant. Rejecting is open to analysts and admins at any
 * risk.
 */
export function approvalAccess(p: Principal | null, action: Pick<ActionOut, 'risk_level' | 'guardrail'>): ApprovalAccess {
  const general = decisionBlockedReason(p);
  if (general) return { approve: false, reject: false, lock: general };
  const reject = can.reject(p);
  const guardrail = readGuardrail(action);
  if (guardrail?.verdict === 'blocked' && guardrail.code === 'autonomy_disabled') {
    return { approve: false, reject, lock: "The tenant's autonomy policy disables actions of this risk, so nobody can approve it." };
  }
  if (can.approve(p, action.risk_level)) return { approve: true, reject, lock: null };
  const needed = approvalRoleFor(action.risk_level);
  const lock =
    needed === 'admin'
      ? `${humanize(action.risk_level)} risk needs an admin to approve.`
      : `Unknown risk level ${action.risk_level}: it cannot be approved here.`;
  return { approve: false, reject, lock };
}

// Why a human must approve ----------------------------------------------------

/** The planner's `approval_reason` codes (lg_sotf.services.response, rollback). */
export const APPROVAL_REASONS: Record<string, string> = {
  admin_approval_required: 'An analyst pre-approved it, but its risk needs an admin.',
  llm_only_evidence: 'Containment on evidence from the model alone is never automatic.',
  target_not_corroborated: 'The rule evidence does not concern this target, so containing it is not automatic.',
  hourly_cap_reached: "The tenant's hourly action cap was reached, so it did not run automatically.",
  blast_radius_exceeded: 'The hourly limit for this action type was reached, so it did not run automatically.',
  rollback_review: 'A rollback requested for review.',
};

/** Why this action waits for a human, in words. */
export function approvalReasonText(code: string | null | undefined): string {
  if (!code) return "The tenant's autonomy policy asks for a human approval at this risk.";
  return APPROVAL_REASONS[code] ?? humanize(code);
}

export interface GuardrailSummary {
  verdict: 'passed' | 'blocked';
  /** "Passed" or "Blocked", with "checked now" when it was re-evaluated against the current policy. */
  label: string;
  /** Why it is blocked, or why a human must approve it. */
  detail: string;
}

/** The guardrail result of an action, or null when the API sent none (older API, or not pending). */
export function guardrailSummary(action: Pick<ActionOut, 'guardrail'>): GuardrailSummary | null {
  const g = readGuardrail(action);
  if (!g) return null;
  const when = g.evaluated === 'now' ? ' (checked now)' : '';
  if (g.verdict === 'blocked') {
    const detail = g.code ? describeBlockedReason(g.code) : g.reason ?? 'A guardrail blocks it.';
    const extra = g.code && g.reason && !detail.includes(g.reason) ? ` (${g.reason})` : '';
    return { verdict: 'blocked', label: `Blocked${when}`, detail: `${detail}${extra}` };
  }
  return { verdict: 'passed', label: `Passed${when}`, detail: approvalReasonText(g.approval_reason) };
}

// Blast radius -----------------------------------------------------------------

export interface Usage {
  /** Started executing in the last hour. */
  used: number;
  /** The hourly limit, or null when there is none. */
  limit: number | null;
}

export interface BlastRadius {
  targetKind: string | null;
  scopeHosts: string[];
  /** This action type's hourly usage against its limit (null when not sent). */
  type: Usage | null;
  /** The tenant's hourly usage against its cap (null when not sent). */
  tenant: Usage | null;
}

function usage(used: unknown, limit: unknown): Usage | null {
  const n = finite(used);
  if (n === null || n < 0) return null;
  const l = finite(limit);
  return { used: n, limit: l !== null && l >= 0 ? l : null };
}

/** An action's blast radius, or null when absent or malformed (older APIs). */
export function readBlastRadius(action: Pick<ActionOut, 'blast_radius'>): BlastRadius | null {
  const b: unknown = action.blast_radius;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return null;
  const r = b as Record<string, unknown>;
  const hosts = Array.isArray(r.scope_hosts) ? r.scope_hosts.filter((h): h is string => Boolean(text(h))) : [];
  const out: BlastRadius = {
    targetKind: text(r.target_kind),
    scopeHosts: hosts,
    type: usage(r.executed_last_hour, r.hourly_limit),
    tenant: usage(r.tenant_executed_last_hour, r.tenant_hourly_cap),
  };
  if (!out.targetKind && !hosts.length && !out.type && !out.tenant) return null;
  return out;
}

/** "3 of 10 in the last hour", "3 in the last hour (no limit)". */
export function usageText(u: Usage): string {
  return u.limit === null ? `${u.used} in the last hour (no limit)` : `${u.used} of ${u.limit} in the last hour`;
}

/** Where usage stands against its limit: room left, close (80 % or more), or reached. */
export function usageLevel(u: Usage): 'ok' | 'near' | 'reached' {
  if (u.limit === null) return 'ok';
  if (u.used >= u.limit) return 'reached';
  return u.used >= u.limit * 0.8 ? 'near' : 'ok';
}

/** "1 host", "3 hosts: ws-1, ws-2, ws-3", "User". */
export function scopeText(b: BlastRadius, max = 3): string | null {
  if (b.scopeHosts.length) {
    const shown = b.scopeHosts.slice(0, max).join(', ');
    const more = b.scopeHosts.length > max ? `, +${b.scopeHosts.length - max} more` : '';
    return `${b.scopeHosts.length} ${b.scopeHosts.length === 1 ? 'host' : 'hosts'}: ${shown}${more}`;
  }
  return b.targetKind ? `One ${humanize(b.targetKind).toLowerCase()}` : null;
}

// Reversibility ------------------------------------------------------------------

/** "Yes" / "No: <note>", or null when the API does not say (older API, unknown type). */
export function reversibleText(action: Pick<ActionOut, 'reversible' | 'irreversible_note'>): { reversible: boolean; text: string } | null {
  if (action.reversible === true) return { reversible: true, text: 'Yes, it can be rolled back once executed.' };
  if (action.reversible === false) {
    const note = text(action.irreversible_note);
    return { reversible: false, text: note ? `No. ${note}` : 'No, it cannot be undone.' };
  }
  return null;
}

// People ------------------------------------------------------------------------

/** Who requested an action: the workflow, you, or a short user id. */
export function requesterLabel(requestedBy: string | null | undefined, userId: string | null | undefined): string {
  if (!requestedBy || requestedBy === WORKFLOW_REQUESTER) return 'the alert workflow';
  if (userId && requestedBy === userId) return 'you';
  return shortId(requestedBy);
}

/** Who approved an executed action: the autonomy policy, you, or a short user id (null when nobody). */
export function approverLabel(approvedBy: string | null | undefined, userId: string | null | undefined): string | null {
  if (!approvedBy) return null;
  if (approvedBy === POLICY_APPROVER) return 'Automatic (autonomy policy)';
  if (userId && approvedBy === userId) return 'Approved by you';
  return `Approved by ${shortId(approvedBy)}`;
}

// Header figures ------------------------------------------------------------------

export interface ApprovalFigures {
  /** Pending actions the caller may approve. */
  mine: number;
  total: number;
  byRisk: Record<string, number>;
  /** False when counted from the loaded page only (an API without the dashboard figures). */
  exact: boolean;
}

/**
 * The header counts: the dashboard's queue figures when the API sends them,
 * else counted from the pending actions loaded on the page.
 */
export function approvalFigures(
  queue: QueueFigures | null,
  pending: ReadonlyArray<Pick<ActionOut, 'risk_level' | 'guardrail'>>,
  p: Principal | null,
  complete: boolean,
): ApprovalFigures {
  if (queue) return { mine: queue.pendingMine, total: queue.pendingTotal, byRisk: queue.pendingByRisk, exact: true };
  const byRisk: Record<string, number> = {};
  for (const a of pending) byRisk[a.risk_level] = (byRisk[a.risk_level] ?? 0) + 1;
  const mine = pending.filter((a) => approvalAccess(p, a).approve).length;
  return { mine, total: totalOf(readCounts(byRisk)), byRisk, exact: complete };
}
