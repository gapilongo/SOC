/**
 * The sidebar's navigation model: groups (Operate / Report / Configure /
 * Platform) of items filtered by role. The groups themselves come from the
 * route table (app/routes.tsx), so every item is gated exactly like its route.
 */

import type { LucideIcon } from 'lucide-react';

import { can } from '../../auth/roles';
import type { Principal } from '../../auth/store';

/** Dashboard summary fields that feed a nav count (absent on older APIs). */
export type NavCountField = 'unassigned_breaching' | 'pending_approvals';

/** A count chip on a nav item, and its meaning for screen readers. */
export interface NavCount {
  field: NavCountField;
  tone: 'warn' | 'approval';
  meaning: (n: number) => string;
}

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  allowed: (p: Principal | null) => boolean;
  count?: NavCount;
}

export interface NavGroup {
  id: string;
  title: string;
  items: NavItem[];
}

/** The groups and items `p` may use; empty groups are dropped. */
export function navFor(groups: readonly NavGroup[], p: Principal | null): NavGroup[] {
  return groups.map((g) => ({ ...g, items: g.items.filter((i) => i.allowed(p)) })).filter((g) => g.items.length > 0);
}

/**
 * Nav counts from the dashboard summary, read defensively: a field shows only
 * when the API sends it as a positive whole number, so older APIs (without
 * the field) show no count rather than a made-up one.
 */
export function navCounts(summary: unknown): Partial<Record<NavCountField, number>> {
  const out: Partial<Record<NavCountField, number>> = {};
  if (!summary || typeof summary !== 'object') return out;
  for (const field of ['unassigned_breaching', 'pending_approvals'] as const) {
    const value = (summary as Record<string, unknown>)[field];
    if (typeof value === 'number' && Number.isInteger(value) && value > 0) out[field] = value;
  }
  return out;
}

/** "Signed in as ..." under the nav, saying why pages may be missing. */
export function roleNote(p: Principal | null): string {
  if (!p) return '';
  if (can.platform(p)) return 'Signed in as a platform admin.';
  if (can.admin(p)) return p.isPlatformAdmin ? 'Signed in as a platform admin acting on a tenant.' : 'Signed in as a tenant admin.';
  if (p.role === 'analyst') return 'Signed in as an analyst. Admin pages are hidden.';
  return 'Signed in as a viewer. Admin pages are hidden.';
}
