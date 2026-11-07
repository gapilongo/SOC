/**
 * Role checks mirroring the API's RBAC (docs/api.md "Roles"). The server is
 * the authority; the UI only hides or disables what the API would refuse.
 */

import type { Role } from '../api/types';
import type { Principal } from './store';

/** Roles from least to most privileged. */
export const ROLE_ORDER = ['viewer', 'analyst', 'admin'] as const satisfies readonly Role[];

export function roleRank(role: string | null | undefined): number {
  return role ? ROLE_ORDER.indexOf(role as Role) : -1;
}

export function roleAtLeast(role: string | null | undefined, minimum: Role): boolean {
  const rank = roleRank(role);
  return rank >= 0 && rank >= ROLE_ORDER.indexOf(minimum);
}

/** A platform admin acting on another tenant through X-Tenant-ID. */
export function isTenantOverride(p: Principal | null): boolean {
  return Boolean(p && p.isPlatformAdmin && p.tenantId !== p.homeTenantId);
}

/**
 * Claiming, deciding and approving are attributed to a person: they need a
 * provisioned user account in the tenant, and are refused under a
 * platform-admin tenant override.
 */
function personalDecision(p: Principal | null): boolean {
  return Boolean(p && p.userId && !isTenantOverride(p));
}

export function approvalRoleFor(risk: string): Role | null {
  if (risk === 'low' || risk === 'medium') return 'analyst';
  if (risk === 'high' || risk === 'critical') return 'admin';
  return null;
}

/** The escalation fields the claim/decide rules look at. */
export interface EscalationRef {
  status: string;
  assigned_to?: string | null;
}

const ACTIVE_ESCALATION = new Set(['open', 'claimed', 'expired']);

/** Claimed by someone other than `p` (the API lets only an admin act on it then). */
function claimedByOther(p: Principal | null, e: EscalationRef): boolean {
  return e.status === 'claimed' && Boolean(e.assigned_to) && e.assigned_to !== p?.userId;
}

export const can = {
  view: (p: Principal | null) => roleAtLeast(p?.role, 'viewer'),
  addNote: (p: Principal | null) => roleAtLeast(p?.role, 'analyst'),
  createSuppression: (p: Principal | null) => roleAtLeast(p?.role, 'analyst'),
  manageSuppressions: (p: Principal | null) => roleAtLeast(p?.role, 'admin'),
  claim: (p: Principal | null) => roleAtLeast(p?.role, 'analyst') && personalDecision(p),
  decide: (p: Principal | null) => roleAtLeast(p?.role, 'analyst') && personalDecision(p),
  /**
   * Claim (or, for an admin, take over) this escalation: any active one that
   * is not already yours; one claimed by another analyst needs an admin.
   */
  claimEscalation: (p: Principal | null, e: EscalationRef) =>
    can.claim(p) &&
    ACTIVE_ESCALATION.has(e.status) &&
    !(e.status === 'claimed' && e.assigned_to === p?.userId) &&
    (!claimedByOther(p, e) || roleAtLeast(p?.role, 'admin')),
  /** Decide this escalation: not while another analyst holds the claim (admins may). */
  decideEscalation: (p: Principal | null, e: EscalationRef) =>
    can.decide(p) && ACTIVE_ESCALATION.has(e.status) && (!claimedByOther(p, e) || roleAtLeast(p?.role, 'admin')),
  /** Rejecting a pending action is open to analysts and admins at any risk level. */
  reject: (p: Principal | null) => roleAtLeast(p?.role, 'analyst') && personalDecision(p),
  approve: (p: Principal | null, risk: string) => {
    const needed = approvalRoleFor(risk);
    return needed !== null && roleAtLeast(p?.role, needed) && personalDecision(p);
  },
  reprocess: (p: Principal | null) => roleAtLeast(p?.role, 'admin'),
  admin: (p: Principal | null) => roleAtLeast(p?.role, 'admin'),
  grantPlatformAdmin: (p: Principal | null) => Boolean(p?.isPlatformAdmin),
  platform: (p: Principal | null) => Boolean(p?.isPlatformAdmin) && !isTenantOverride(p),
  /** Account security (password, MFA) is about the signed-in person: not while acting on another tenant. */
  account: (p: Principal | null) => can.view(p) && !isTenantOverride(p),
};

/** Why deciding this escalation is unavailable, for disabled-button hints. */
export function escalationDecisionBlockedReason(p: Principal | null, e: EscalationRef): string | null {
  const general = decisionBlockedReason(p);
  if (general) return general;
  if (claimedByOther(p, e) && !roleAtLeast(p?.role, 'admin')) return 'Claimed by another analyst; only they or an admin can decide it.';
  return null;
}

/** Why a personal decision is unavailable, for disabled-button hints. */
export function decisionBlockedReason(p: Principal | null): string | null {
  if (!p) return 'Sign in first.';
  if (!roleAtLeast(p.role, 'analyst')) return 'Requires the analyst role.';
  if (isTenantOverride(p)) return 'Decisions belong to members of the tenant; not available while acting on another tenant.';
  if (!p.userId) return 'Your single sign-on identity is not linked to a user account in this tenant.';
  return null;
}
