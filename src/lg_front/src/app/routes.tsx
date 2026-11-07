/**
 * The route table: one entry per signed-in page, with its role gate and,
 * for pages in the sidebar, its nav entry. App.tsx renders the routes from
 * it, the sidebar and the breadcrumb derive from it, so a page's gate and
 * its nav visibility cannot diverge.
 *
 * Public routes (sign-in, the OIDC callback and the printable monthly
 * report, which sits outside the app shell) stay inline in App.tsx.
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
import { lazy, type ComponentType } from 'react';

import { can } from '../auth/roles';
import type { Principal } from '../auth/store';
import { LegacyActionsRedirect } from '../pages/approvals/redirect';
import type { NavCount, NavGroup, NavItem } from './shell/nav';

// One chunk per route.
const OverviewPage = lazy(() => import('../pages/overview/OverviewPage'));
const AlertsPage = lazy(() => import('../pages/alerts/AlertsPage'));
const EscalationsPage = lazy(() => import('../pages/escalations/EscalationsPage'));
const DecisionPage = lazy(() => import('../pages/escalations/DecisionPage'));
const ApprovalsPage = lazy(() => import('../pages/approvals/ApprovalsPage'));
const SuppressionsPage = lazy(() => import('../pages/SuppressionsPage'));
const SourcesPage = lazy(() => import('../pages/SourcesPage'));
const IntegrationsPage = lazy(() => import('../pages/integrations/IntegrationsPage'));
const UsersPage = lazy(() => import('../pages/UsersPage'));
const TenantSettingsPage = lazy(() => import('../pages/settings/TenantSettingsPage'));
const UsagePage = lazy(() => import('../pages/UsagePage'));
const AuditPage = lazy(() => import('../pages/AuditPage'));
const ReportsPage = lazy(() => import('../pages/ReportsPage'));
const PlatformPage = lazy(() => import('../pages/platform/PlatformPage'));
const GettingStartedPage = lazy(() => import('../pages/GettingStartedPage'));
const AccountSecurityPage = lazy(() => import('../pages/AccountSecurityPage'));
const SetupWizardPage = lazy(() => import('../pages/setup/SetupWizardPage'));
const PovPage = lazy(() => import('../pages/PovPage'));

export type NavGroupId = 'operate' | 'report' | 'configure' | 'platform';

/** Sidebar group titles, in display order. */
const NAV_GROUP_TITLES: Record<NavGroupId, string> = {
  operate: 'Operate',
  report: 'Report',
  configure: 'Configure',
  platform: 'Platform',
};

export interface AppRoute {
  /** URL path (`/` is the index route); may hold route parameters. */
  path: string;
  Page: ComponentType;
  /** Role gate (RequireRole); the nav entry, if any, shows exactly when this allows. */
  allowed: (p: Principal | null) => boolean;
  /** Page name for the breadcrumb, when the page has no nav entry. */
  label?: string;
  nav?: { group: NavGroupId; label: string; icon: LucideIcon; count?: NavCount };
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** Signed-in pages, inside the app shell. Within each nav group, the sidebar follows this order. */
export const APP_ROUTES: readonly AppRoute[] = [
  // Operate
  { path: '/', Page: OverviewPage, allowed: can.view, nav: { group: 'operate', label: 'Overview', icon: LayoutDashboard } },
  {
    path: '/escalations',
    Page: EscalationsPage,
    allowed: can.view,
    nav: {
      group: 'operate',
      label: 'Escalations',
      icon: ShieldAlert,
      count: {
        field: 'unassigned_breaching',
        tone: 'warn',
        meaning: (n) => plural(n, 'unassigned escalation breaching SLA', 'unassigned escalations breaching SLA'),
      },
    },
  },
  { path: '/escalations/:id', Page: DecisionPage, allowed: can.view },
  {
    path: '/approvals',
    Page: ApprovalsPage,
    allowed: can.view,
    nav: {
      group: 'operate',
      label: 'Approvals',
      icon: UserCheck,
      count: { field: 'pending_approvals', tone: 'approval', meaning: (n) => plural(n, 'action you can approve', 'actions you can approve') },
    },
  },
  // The page's name before it became Approvals: old links and bookmarks redirect.
  { path: '/actions', Page: LegacyActionsRedirect, allowed: can.view },
  { path: '/alerts', Page: AlertsPage, allowed: can.view, nav: { group: 'operate', label: 'Alerts', icon: Bell } },
  { path: '/suppressions', Page: SuppressionsPage, allowed: can.view, nav: { group: 'operate', label: 'Suppressions', icon: Filter } },
  // Report
  { path: '/reports', Page: ReportsPage, allowed: can.view, nav: { group: 'report', label: 'Reports', icon: FileText } },
  { path: '/usage', Page: UsagePage, allowed: can.admin, nav: { group: 'report', label: 'LLM usage', icon: BarChart3 } },
  { path: '/audit', Page: AuditPage, allowed: can.admin, nav: { group: 'report', label: 'Audit log', icon: FileClock } },
  // Configure
  { path: '/getting-started', Page: GettingStartedPage, allowed: can.admin, nav: { group: 'configure', label: 'Getting started', icon: Rocket } },
  // First-run setup (reached from the Overview and Getting started) and where it ends.
  { path: '/setup', Page: SetupWizardPage, allowed: can.setup, label: 'Setup' },
  { path: '/pov', Page: PovPage, allowed: can.admin, label: 'Proof of value' },
  { path: '/sources', Page: SourcesPage, allowed: can.admin, nav: { group: 'configure', label: 'Sources', icon: Plug } },
  { path: '/integrations', Page: IntegrationsPage, allowed: can.admin, nav: { group: 'configure', label: 'Integrations', icon: Send } },
  { path: '/users', Page: UsersPage, allowed: can.admin, nav: { group: 'configure', label: 'Users and API keys', icon: KeyRound } },
  { path: '/settings', Page: TenantSettingsPage, allowed: can.admin, nav: { group: 'configure', label: 'Tenant settings', icon: Settings } },
  // Platform
  { path: '/platform', Page: PlatformPage, allowed: can.platform, nav: { group: 'platform', label: 'MSSP console', icon: Building2 } },
  // Reached from the account menu, which shows it under the same gate.
  { path: '/account', Page: AccountSecurityPage, allowed: can.account, label: 'Account security' },
];

/** The sidebar: every route with a nav entry, grouped, each item gated like its route. */
export const NAV_GROUPS: readonly NavGroup[] = (Object.keys(NAV_GROUP_TITLES) as NavGroupId[]).map((id) => ({
  id,
  title: NAV_GROUP_TITLES[id],
  items: APP_ROUTES.flatMap((r): NavItem[] =>
    r.nav?.group === id ? [{ to: r.path, label: r.nav.label, icon: r.nav.icon, allowed: r.allowed, count: r.nav.count }] : [],
  ),
}));

/** Page name for the header breadcrumb and the phone top bar: the route at `pathname` or its closest parent. */
export function pageLabel(pathname: string): string | null {
  for (const r of APP_ROUTES) {
    const label = r.nav?.label ?? r.label;
    if (!label || r.path.includes(':')) continue;
    if (r.path === '/' ? pathname === '/' : pathname === r.path || pathname.startsWith(`${r.path}/`)) return label;
  }
  return null;
}
