/**
 * The SOC module's manifest: everything the shell knows about the security
 * operations service (ADR 0015). Pages are reached only through `lazy()`, one
 * chunk per route.
 *
 * The SOC is the first module and still carries the pages every service will
 * share (tenant configuration, users, the MSSP console, account security).
 * They move to a module of their own when a second service needs them.
 */

import {
  BarChart3,
  Bell,
  Building2,
  ClipboardCheck,
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
import { lazy } from 'react';

import { qk } from './api/queryKeys';
import { can } from '../../auth/roles';
import { defineModule, type Allowed } from '../../core/module';
import { useNavCount } from './navCounts';

// One chunk per route.
const OverviewPage = lazy(() => import('./pages/overview/OverviewPage'));
const AlertsPage = lazy(() => import('./pages/alerts/AlertsPage'));
const EscalationsPage = lazy(() => import('./pages/escalations/EscalationsPage'));
const DecisionPage = lazy(() => import('./pages/escalations/DecisionPage'));
const ApprovalsPage = lazy(() => import('./pages/approvals/ApprovalsPage'));
const LegacyActionsRedirect = lazy(() => import('./pages/approvals/redirect').then((m) => ({ default: m.LegacyActionsRedirect })));
const SuppressionsPage = lazy(() => import('./pages/SuppressionsPage'));
const SourcesPage = lazy(() => import('./pages/SourcesPage'));
const IntegrationsPage = lazy(() => import('./pages/integrations/IntegrationsPage'));
const UsersPage = lazy(() => import('./pages/UsersPage'));
const TenantSettingsPage = lazy(() => import('./pages/settings/TenantSettingsPage'));
const UsagePage = lazy(() => import('./pages/UsagePage'));
const AuditPage = lazy(() => import('./pages/AuditPage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const MonthlyReportPage = lazy(() => import('./pages/MonthlyReportPage'));
const PlatformPage = lazy(() => import('./pages/platform/PlatformPage'));
const GettingStartedPage = lazy(() => import('./pages/GettingStartedPage'));
const AccountSecurityPage = lazy(() => import('./pages/AccountSecurityPage'));
const SetupWizardPage = lazy(() => import('./pages/setup/SetupWizardPage'));
const PovPage = lazy(() => import('./pages/PovPage'));
const BlindAuditPage = lazy(() => import('./pages/blindAudit/BlindAuditPage'));

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** Any signed-in user; the API enforces the role. */
const signedIn: Allowed = () => true;

export const soc = defineModule({
  id: 'soc',
  title: 'Security operations',
  entitlement: 'soc',
  permissions: { ...can, signedIn },
  // The four groups are capability groups: a later service adds its pages to them, or declares its own.
  navGroups: [
    { id: 'operate', title: 'Operate', order: 10 },
    { id: 'report', title: 'Report', order: 20 },
    { id: 'configure', title: 'Configure', order: 30 },
    { id: 'platform', title: 'Platform', order: 40 },
  ],
  routes: [
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
          useCount: () => useNavCount('unassigned_breaching'),
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
        count: {
          useCount: () => useNavCount('pending_approvals'),
          tone: 'approval',
          meaning: (n) => plural(n, 'action you can approve', 'actions you can approve'),
        },
      },
    },
    // The page's name before it became Approvals: old links and bookmarks redirect.
    { path: '/actions', Page: LegacyActionsRedirect, allowed: can.view },
    { path: '/alerts', Page: AlertsPage, allowed: can.view, nav: { group: 'operate', label: 'Alerts', icon: Bell } },
    { path: '/suppressions', Page: SuppressionsPage, allowed: can.view, nav: { group: 'operate', label: 'Suppressions', icon: Filter } },
    // Labelling is a person's decision, like deciding an escalation.
    { path: '/blind-audit', Page: BlindAuditPage, allowed: can.decide, nav: { group: 'operate', label: 'Blind audit', icon: ClipboardCheck } },
    // Report
    { path: '/reports', Page: ReportsPage, allowed: can.view, nav: { group: 'report', label: 'Reports', icon: FileText } },
    // Printable report: outside the app shell so only the report prints.
    { path: '/reports/monthly/:month', Page: MonthlyReportPage, allowed: signedIn, shell: false },
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
  ],
  liveEvents: {
    'alert.created': [qk.alerts.all, qk.alert.all, qk.dashboard.all],
    'alert.updated': [qk.alerts.all, qk.alert.all, qk.dashboard.all],
    'escalation.created': [qk.escalations.all, qk.escalation.all, qk.dashboard.all],
    'escalation.updated': [qk.escalations.all, qk.escalation.all, qk.dashboard.all],
    'action.updated': [qk.actions.all, qk.dashboard.all],
  },
});
