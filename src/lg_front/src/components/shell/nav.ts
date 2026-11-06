/**
 * The sidebar's navigation model: groups (Operate / Report / Configure /
 * Platform) of items filtered by role with the helpers of auth/roles.ts. Each
 * item maps to an existing route; the Approvals item opens the actions page
 * until a dedicated approvals page exists.
 */

import {
  type LucideIcon,
  BarChart3,
  Bell,
  Building2,
  FileClock,
  FileText,
  Filter,
  KeyRound,
  LayoutDashboard,
  Plug,
  Rocket,
  Send,
  Settings,
  ShieldAlert,
  UserCheck,
} from 'lucide-react';

import { can } from '../../auth/roles';
import type { Principal } from '../../auth/store';

/** Dashboard summary fields that feed a nav count (absent on older APIs). */
export type NavCountField = 'unassigned_breaching' | 'pending_approvals';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  allowed: (p: Principal | null) => boolean;
  count?: { field: NavCountField; tone: 'warn' | 'approval'; meaning: (n: number) => string };
}

export interface NavGroup {
  id: string;
  title: string;
  items: NavItem[];
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'operate',
    title: 'Operate',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, allowed: can.view },
      {
        to: '/escalations',
        label: 'Escalations',
        icon: ShieldAlert,
        allowed: can.view,
        count: {
          field: 'unassigned_breaching',
          tone: 'warn',
          meaning: (n) => plural(n, 'unassigned escalation breaching SLA', 'unassigned escalations breaching SLA'),
        },
      },
      {
        to: '/actions',
        label: 'Approvals',
        icon: UserCheck,
        allowed: can.view,
        count: { field: 'pending_approvals', tone: 'approval', meaning: (n) => plural(n, 'action you can approve', 'actions you can approve') },
      },
      { to: '/alerts', label: 'Alerts', icon: Bell, allowed: can.view },
      { to: '/suppressions', label: 'Suppressions', icon: Filter, allowed: can.view },
    ],
  },
  {
    id: 'report',
    title: 'Report',
    items: [
      { to: '/reports', label: 'Reports', icon: FileText, allowed: can.view },
      { to: '/usage', label: 'LLM usage', icon: BarChart3, allowed: can.admin },
      { to: '/audit', label: 'Audit log', icon: FileClock, allowed: can.admin },
    ],
  },
  {
    id: 'configure',
    title: 'Configure',
    items: [
      { to: '/getting-started', label: 'Getting started', icon: Rocket, allowed: can.admin },
      { to: '/sources', label: 'Sources', icon: Plug, allowed: can.admin },
      { to: '/integrations', label: 'Integrations', icon: Send, allowed: can.admin },
      { to: '/users', label: 'Users and API keys', icon: KeyRound, allowed: can.admin },
      { to: '/settings', label: 'Tenant settings', icon: Settings, allowed: can.admin },
    ],
  },
  {
    id: 'platform',
    title: 'Platform',
    items: [{ to: '/platform', label: 'MSSP console', icon: Building2, allowed: can.platform }],
  },
];

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

/** The groups and items `p` may use; empty groups are dropped. */
export function navFor(p: Principal | null): NavGroup[] {
  return NAV_GROUPS.map((g) => ({ ...g, items: g.items.filter((i) => i.allowed(p)) })).filter((g) => g.items.length > 0);
}

/** Page names for the header breadcrumb and the phone top bar, by path. */
export function pageLabel(pathname: string): string | null {
  if (pathname === '/account') return 'Account security';
  const item = NAV_ITEMS.find((i) => (i.to === '/' ? pathname === '/' : pathname === i.to || pathname.startsWith(`${i.to}/`)));
  return item?.label ?? null;
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
